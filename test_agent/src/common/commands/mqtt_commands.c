#include "utilities.h"
#include "rsi_wlan_apis.h"
#include "rsi_error.h"
#include "rsi_wlan.h"
#include "sl_cli.h"
#include "sl_cli_arguments.h"
#include "rsi_nwk.h"
#include "rsi_emb_mqtt_client.h"
#include <string.h>



static void mqtt_publish_handler(uint16_t status, const uint8_t *buffer, const uint32_t length)
{
    (void)status;
    (void)buffer;
    (void)length;

    // format of data in "buffer"
    // flags   chunk len   topic len  topic  message
    // xx xx   xx xx       xx xx      .....  ....... 

    if (status == RSI_ERROR_NONE && length >= 6)
    {
        uint16_t chunk_len = *((uint16_t*)(buffer+2));
        uint16_t topic_len = *((uint16_t*)(buffer+4));
        
        // sanity check header data
        if (length == (uint32_t)(6 + chunk_len + topic_len))
        {
            char* b64data = base64_encode(buffer, length);
            if (b64data != NULL)
            {
                printf("\r\nSAPI+RSI_MQTT_READ_DATA %s\r\n", b64data);
                free(b64data);
            }
        }
    }
    
}

static void mqtt_remote_socket_terminate_handler(uint16_t status, const uint8_t *buffer, const uint32_t length)
{
    (void)status;
    (void)buffer;
    (void)length;
}

static void mqtt_ka_timeout_handler(uint16_t status, const uint8_t *buffer, const uint32_t length)
{
    (void)status;
    (void)buffer;
    (void)length;
}



void mqtt_client_init(sl_cli_command_arg_t* arguments)
{
    char* server_ip = sl_cli_get_argument_string(arguments, 0);
    uint32_t server_port = sl_cli_get_argument_uint32(arguments, 1);
    uint32_t client_port = sl_cli_get_argument_uint32(arguments, 2);
    uint16_t flags = sl_cli_get_argument_uint16(arguments, 3);
    uint16_t keepalive_interval = sl_cli_get_argument_uint16(arguments, 4);
    char* clientid = sl_cli_get_argument_string(arguments, 5);
    char* username = sl_cli_get_argument_string(arguments, 6);
    char* password = sl_cli_get_argument_string(arguments, 7);

    int32_t status = rsi_emb_mqtt_register_call_back(RSI_WLAN_NWK_EMB_MQTT_PUB_MSG_CB, mqtt_publish_handler);
    if (status != RSI_ERROR_NONE) {
        print_status(status);
        return;
    }
    status = rsi_emb_mqtt_register_call_back(RSI_WLAN_NWK_EMB_MQTT_REMOTE_TERMINATE_CB, mqtt_remote_socket_terminate_handler);
    if (status != RSI_ERROR_NONE) {
        print_status(status);
        return;
    }
    status = rsi_emb_mqtt_register_call_back(RSI_WLAN_NWK_EMB_MQTT_KEEPALIVE_TIMEOUT_CB, mqtt_ka_timeout_handler);
    if (status != RSI_ERROR_NONE) {
        print_status(status);
        return;
    }
    uint32_t ip_address = str_to_ipv4(server_ip);
    status = rsi_emb_mqtt_client_init ((int8_t*)&ip_address, server_port, client_port, flags, keepalive_interval, (int8_t*)clientid, (int8_t*)username, (int8_t*)password);
    print_status(status);

}

void mqtt_client_connect(sl_cli_command_arg_t* arguments)
{
    uint8_t enable_username = sl_cli_get_argument_uint8(arguments, 0);
    uint8_t enable_password = sl_cli_get_argument_uint8(arguments, 1);
    char* will_topic = sl_cli_get_argument_string(arguments, 2);
    (void) will_topic;
    char* will_message = sl_cli_get_argument_string(arguments, 3);
    (void) will_message;

    uint8_t flags = ((enable_username & 1) << 6) | ((enable_password & 1) << 7);
    int32_t status = rsi_emb_mqtt_connect (flags, NULL, 0, NULL);
    print_status(status);
}

void mqtt_client_publish(sl_cli_command_arg_t* arguments)
{
    char* topic = sl_cli_get_argument_string(arguments, 0);
    uint8_t qos = sl_cli_get_argument_uint8(arguments, 1);
    uint8_t retained = sl_cli_get_argument_uint8(arguments, 2);
    uint8_t dup = sl_cli_get_argument_uint8(arguments, 3);
    char* payload = sl_cli_get_argument_string(arguments, 4);
    
    rsi_mqtt_pubmsg_t message = {
        .qos = qos,
        .dup = dup,
        .retained = retained,
        .payload = (int8_t*)payload,
        .payloadlen = strlen(payload)
    };
    int32_t status = rsi_emb_mqtt_publish((int8_t*)topic, &message);
    print_status(status);
}

void mqtt_client_subscribe(sl_cli_command_arg_t* arguments)
{
    char* topic = sl_cli_get_argument_string(arguments, 0);
    uint8_t qos = sl_cli_get_argument_uint8(arguments, 1);

    int32_t status = rsi_emb_mqtt_subscribe(qos, (int8_t *)topic);
    print_status(status);
}

void mqtt_client_unsubscribe(sl_cli_command_arg_t* arguments)
{
    char* topic = sl_cli_get_argument_string(arguments, 0);

    int32_t status = rsi_emb_mqtt_unsubscribe((int8_t *)topic);
    print_status(status);
}

void mqtt_client_disconnect(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    int32_t status = rsi_emb_mqtt_disconnect();
    print_status(status);
}

void mqtt_client_destroy(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    int32_t status = rsi_emb_mqtt_destroy();
    print_status(status);
}