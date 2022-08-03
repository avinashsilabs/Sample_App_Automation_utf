/***************************************************************************//**
   Copyright 2021
   Silicon Labs, Inc.
   All rights reserved.

   @file     aws_iot_sdk_commands.c

*******************************************************************************/


/*******************************************************************************
* INCLUDE FILES:
*******************************************************************************/
#include "aws_iot_mqtt_client_interface.h"
#include "aws_iot_shadow_interface.h"
#include "sl_cli.h"
#include "sl_cli_arguments.h"
#include "rsi_common_apis.h"
#include "rsi_os.h"
#include <string.h>
#include "utilities.h"

/*******************************************************************************
* CONSTANTS:
*******************************************************************************/
#define RSI_MQTT_YIELD_TASK_STACK_SIZE (324)
#define RSI_MQTT_YIELD_TASK_PRIORITY (5)

/*******************************************************************************
* TYPES:
*******************************************************************************/


/*******************************************************************************
* GLOBAL VARIABLES:
*******************************************************************************/
extern char* strdup(const char* str1);

/*******************************************************************************
* MACROS:
*******************************************************************************/
/* This Macro section should contain Macro functions used only in this module */
/******************************************************************************/

/*******************************************************************************
* LOCAL VARIABLES:
*******************************************************************************/
/* All following variables declared here must be declared 'static' */
static IoT_Client_Connect_Params s_connect_params = IoT_Client_Connect_Params_initializer;
static ShadowInitParameters_t s_shadow_init_params = { 0 };
static ShadowConnectParameters_t s_shadow_connect_params = { 0 };
static rsi_task_handle_t s_yield_task_handle = NULL;
static volatile bool s_run_yield_task = false;
static volatile bool s_run_shadow_yield_task = false;
static rsi_mutex_handle_t s_yield_mutex = 0;
static jsonStruct_t s_window_actuator;
static jsonStruct_t s_temperature_handler;
static int32_t s_temperature = 0;
static bool s_window_open = false;
static char s_json_document_buffer[400];
static volatile IoT_Error_t s_connection_status = NETWORK_DISCONNECTED_ERROR;
static AWS_IoT_Client s_iot_client = { 0 };
static IoT_Client_Init_Params s_init_params = {
    .enableAutoReconnect = true,
    .pHostURL = NULL,
    .port = 8883,
    .mqttPacketTimeout_ms = 200,
    .mqttCommandTimeout_ms = 20000,
    .tlsHandshakeTimeout_ms = 5000,
    .isSSLHostnameVerify = false,
    .disconnectHandler = NULL,
    .disconnectHandlerData = "",
    .pRootCALocation = "",
    .pDeviceCertLocation = "",
    .pDevicePrivateKeyLocation = "",
};

/*******************************************************************************
* FUNCTION PROTOTYPES (for local functions):
*******************************************************************************/
/* All following functions declared here must be declared 'static' */
static void rsi_mqtt_yield_task(void);
static void aws_iot_disconnect_handler(AWS_IoT_Client* client, void* clientData);
static void iot_subscribe_callback_handler(AWS_IoT_Client* pClient,
    char* topicName,
    uint16_t topicNameLen,
    IoT_Publish_Message_Params* params,
    void* pData);
static void window_actuate_callback(const char* pJsonString, uint32_t JsonStringDataLen, jsonStruct_t* pContext);
static void shadow_update_status_callback(const char* pThingName,
    ShadowActions_t action,
    Shadow_Ack_Status_t status,
    const char* pReceivedJsonDocument,
    void* pContextData);
static IoT_Error_t create_yield_task(void);




/*******************************************************************************
*
*                       IMPLEMENTATION: Public functions
*
*******************************************************************************/
void aws_client_init(sl_cli_command_arg_t* arguments) {
    char* server_name = sl_cli_get_argument_string(arguments, 0);
    uint16_t server_port = sl_cli_get_argument_uint16(arguments, 1);
    char* client_id = sl_cli_get_argument_string(arguments, 2);
    uint8_t clean_session = sl_cli_get_argument_uint8(arguments, 3);

    if (s_yield_mutex == 0) {
        rsi_mutex_create(&s_yield_mutex);
    }

    if (s_init_params.pHostURL != NULL)
    {
        free(s_init_params.pHostURL);
    }
    s_init_params.pHostURL = strdup(server_name);
    s_init_params.port = server_port;
    s_init_params.disconnectHandler = aws_iot_disconnect_handler;
    IoT_Error_t status = aws_iot_mqtt_init(&s_iot_client, &s_init_params);
    if (status != SUCCESS) {
        print_status(status);
        return;
    }
    if (s_connect_params.pClientID != NULL)
    {
        free(s_connect_params.pClientID);
    }
    s_connect_params.pClientID = strdup(client_id);
    s_connect_params.clientIDLen = strlen(client_id);
    s_connect_params.isCleanSession =  (bool) clean_session;
    status = aws_iot_mqtt_connect(&s_iot_client, &s_connect_params);
    if (status == SUCCESS) {
        s_run_yield_task = true;
        status = create_yield_task();
    }
    print_status(status);
}

void aws_client_disconnect(sl_cli_command_arg_t* arguments) {
    (void)arguments;
    s_run_yield_task = false;
    rsi_mutex_lock(&s_yield_mutex);
    IoT_Error_t status = aws_iot_mqtt_disconnect(&s_iot_client);
    status = aws_iot_mqtt_free(&s_iot_client);
    rsi_mutex_unlock(&s_yield_mutex);
    print_status(status);
}

void aws_client_subscribe(sl_cli_command_arg_t* arguments) {
    char* topic = sl_cli_get_argument_string(arguments, 0);
    uint16_t qos = sl_cli_get_argument_uint16(arguments, 1);
    rsi_mutex_lock(&s_yield_mutex);
    char* topicCopy = strdup(topic); // todo: need to free this when unsubscribing
    IoT_Error_t status = aws_iot_mqtt_subscribe(&s_iot_client, topicCopy, strlen(topic), qos, iot_subscribe_callback_handler, "");
    rsi_mutex_unlock(&s_yield_mutex);
    print_status(status);
}

void aws_client_unsubscribe(sl_cli_command_arg_t* arguments) {
    char* topic = sl_cli_get_argument_string(arguments, 0);
    rsi_mutex_lock(&s_yield_mutex);
    IoT_Error_t status = aws_iot_mqtt_unsubscribe(&s_iot_client, topic, strlen(topic));
    rsi_mutex_unlock(&s_yield_mutex);
    print_status(status);
}

void aws_client_publish(sl_cli_command_arg_t* arguments) {
    char* topic = sl_cli_get_argument_string(arguments, 0);
    char* payload = sl_cli_get_argument_string(arguments, 1);
    uint8_t is_base64 = sl_cli_get_argument_uint8(arguments, 2);
    uint16_t qos = sl_cli_get_argument_uint16(arguments, 3);

    size_t payloadLen = strlen(payload);
    uint8_t* base64decodedPayload = NULL;
    if (is_base64) {
        base64decodedPayload = base64_decode(payload, payloadLen, (uint32_t*)&payloadLen);
    }
    IoT_Publish_Message_Params pubParams = {
        .qos = qos,
        .payload = is_base64 ? (void*)base64decodedPayload : (void*)payload,
        .payloadLen = payloadLen,
        .isDup = 0,
        .isRetained = 0
    };

    rsi_mutex_lock(&s_yield_mutex);
    IoT_Error_t status = aws_iot_mqtt_publish(&s_iot_client, topic, strlen(topic), &pubParams);
    rsi_mutex_unlock(&s_yield_mutex);
    print_status(status);
    if (is_base64) {
        free(base64decodedPayload);
    }
}

void aws_shadow_init_command(sl_cli_command_arg_t* arguments)
{
    char* server_name = sl_cli_get_argument_string(arguments, 0);
    uint16_t server_port = sl_cli_get_argument_uint16(arguments, 1);
    char* client_id = sl_cli_get_argument_string(arguments, 2);
    char* thing_name = sl_cli_get_argument_string(arguments, 3);

    if (s_yield_mutex == 0) {
        rsi_mutex_create(&s_yield_mutex);
    }
    s_shadow_init_params.disconnectHandler = aws_iot_disconnect_handler;
    s_shadow_init_params.enableAutoReconnect = true;
    s_shadow_init_params.pRootCA = "";
    s_shadow_init_params.pClientCRT = "";
    s_shadow_init_params.pClientKey = "";
    if (s_shadow_init_params.pHost != NULL)
    {
        free(s_shadow_init_params.pHost);
    }
    s_shadow_init_params.pHost = strdup(server_name);
    s_shadow_init_params.port = server_port;
    IoT_Error_t status = aws_iot_shadow_init(&s_iot_client, &s_shadow_init_params);
    if (status != SUCCESS) {
        print_status(status);
        return;
    }

    if (s_shadow_connect_params.pMqttClientId != NULL)
    {
        free(s_shadow_connect_params.pMqttClientId);
    }
    if (s_shadow_connect_params.pMyThingName != NULL)
    {
        free(s_shadow_connect_params.pMyThingName);
    }
    s_shadow_connect_params.pMqttClientId = strdup(client_id);
    s_shadow_connect_params.mqttClientIdLen = strlen(client_id);
    s_shadow_connect_params.pMyThingName = strdup(thing_name);
    s_shadow_connect_params.deleteActionHandler = NULL;
    status = aws_iot_shadow_connect(&s_iot_client, &s_shadow_connect_params);
    s_connection_status = NETWORK_DISCONNECTED_ERROR;
    if (status == SUCCESS) {
        s_run_shadow_yield_task = true;
        status = create_yield_task();
    }
    if (status != SUCCESS) {
        print_status(status);
        return;
    }
    bool connected = false;
    for (int i = 0; i < 10; ++i) {
        rsi_mutex_lock(&s_yield_mutex);
        connected = aws_iot_mqtt_is_client_connected(&s_iot_client);
        rsi_mutex_unlock(&s_yield_mutex);
        if (connected) {
            break;
        }
        rsi_os_task_delay(1000);
    }
    if (!connected)
    {
        print_status(NETWORK_DISCONNECTED_ERROR);
        return;
    }
    s_window_actuator.cb = window_actuate_callback;
    s_window_actuator.pData = &s_window_open;
    s_window_actuator.dataLength = sizeof(bool);
    s_window_actuator.pKey = "windowOpen";
    s_window_actuator.type = SHADOW_JSON_BOOL;
    s_temperature_handler.cb = NULL;
    s_temperature_handler.pKey = "temperature";
    s_temperature_handler.pData = &s_temperature;
    s_temperature_handler.dataLength = sizeof(s_temperature);
    s_temperature_handler.type = SHADOW_JSON_INT32;
    rsi_mutex_lock(&s_yield_mutex);
    status = aws_iot_shadow_register_delta(&s_iot_client, &s_window_actuator);
    rsi_mutex_unlock(&s_yield_mutex);
    print_status(status);
}

void aws_shadow_update(sl_cli_command_arg_t* arguments)
{
    s_temperature = sl_cli_get_argument_int16(arguments, 0);
    rsi_mutex_lock(&s_yield_mutex);
    IoT_Error_t status = aws_iot_shadow_init_json_document(s_json_document_buffer, sizeof(s_json_document_buffer));
    if (status != SUCCESS) {
        rsi_mutex_unlock(&s_yield_mutex);
        print_status(status);
        return;
    }
    status = aws_iot_shadow_add_reported(s_json_document_buffer,
        sizeof(s_json_document_buffer),
        2,
        &s_temperature_handler,
        &s_window_actuator);
    if (status != SUCCESS) {
        rsi_mutex_unlock(&s_yield_mutex);
        print_status(status);
        return;
    }
    status = aws_iot_finalize_json_document(s_json_document_buffer, sizeof(s_json_document_buffer));
    if (status != SUCCESS) {
        rsi_mutex_unlock(&s_yield_mutex);
        print_status(status);
        return;
    }
    status = aws_iot_shadow_update(&s_iot_client,
        s_shadow_connect_params.pMyThingName,
        s_json_document_buffer,
        shadow_update_status_callback,
        NULL,
        5,
        true);
    rsi_mutex_unlock(&s_yield_mutex);
    print_status(status);
}

/*******************************************************************************
*
*                       IMPLEMENTATION: Private functions
*
*******************************************************************************/

static IoT_Error_t create_yield_task(void) {
    IoT_Error_t status = SUCCESS;
    if (s_yield_task_handle == NULL) {
        status = rsi_task_create((rsi_task_function_t)rsi_mqtt_yield_task,
            (uint8_t*)"mqtt_yield_task",
            RSI_MQTT_YIELD_TASK_STACK_SIZE,
            NULL,
            RSI_MQTT_YIELD_TASK_PRIORITY,
            &s_yield_task_handle);
    }
    return status;
}


static void rsi_mqtt_yield_task(void)
{
    while (true) {
        if (s_run_yield_task) {
            rsi_mutex_lock(&s_yield_mutex);
            s_connection_status = aws_iot_mqtt_yield(&s_iot_client, 500);
            rsi_mutex_unlock(&s_yield_mutex);
            rsi_os_task_delay(10);
        }
        else if (s_run_shadow_yield_task) {
            rsi_mutex_lock(&s_yield_mutex);
            s_connection_status = aws_iot_shadow_yield(&s_iot_client, 500);
            rsi_mutex_unlock(&s_yield_mutex);
            rsi_os_task_delay(10);
        }
        else {
            rsi_os_task_delay(100);
        }
    }
}

static void iot_subscribe_callback_handler(AWS_IoT_Client* pClient,
    char* topicName,
    uint16_t topicNameLen,
    IoT_Publish_Message_Params* params,
    void* pData)
{
    (void)pClient;
    (void)pData;
    char* b64data = base64_encode(params->payload, params->payloadLen);
    if (b64data != NULL)
    {
        char* topicCopy = malloc(topicNameLen + 1);
        strncpy(topicCopy, topicName, topicNameLen);
        topicCopy[topicNameLen] = 0;
        printf("\r\nSAPI+RSI_AWS_IOT_MQTT_READ_DATA %s %d %d %d %s\r\n", topicCopy, params->qos, params->isRetained, params->isDup, b64data);
        free(topicCopy);
        free(b64data);
    }
}

static void aws_iot_disconnect_handler(AWS_IoT_Client* client, void* clientData)
{
    (void)client;
    (void)clientData;
}

static void window_actuate_callback(const char* pJsonString, uint32_t JsonStringDataLen, jsonStruct_t* pContext)
{
    IOT_UNUSED(pJsonString);
    IOT_UNUSED(JsonStringDataLen);

    if (pContext != NULL) {
        printf("\nDelta - Window state changed to %d\n", *(bool*)(pContext->pData));
    }
}

static void shadow_update_status_callback(
    const char* pThingName,
    ShadowActions_t action,
    Shadow_Ack_Status_t status,
    const char* pReceivedJsonDocument,
    void* pContextData)
{
    IOT_UNUSED(pThingName);
    IOT_UNUSED(action);
    IOT_UNUSED(pReceivedJsonDocument);
    IOT_UNUSED(pContextData);

    if (SHADOW_ACK_TIMEOUT == status) {
        printf("\r\nSAPI+RSI_AWS_IOT_SHADOW_UPDATE_TIMEOUT %s\r\n", pThingName);
    }
    else if (SHADOW_ACK_REJECTED == status) {
        printf("\r\nSAPI+RSI_AWS_IOT_SHADOW_UPDATE_REJECTED %s\r\n", pThingName);
    }
    else if (SHADOW_ACK_ACCEPTED == status) {
        printf("\r\nSAPI+RSI_AWS_IOT_SHADOW_UPDATE_ACCEPTED %s\r\n", pThingName);
    }
}
