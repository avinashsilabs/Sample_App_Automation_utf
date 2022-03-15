/***************************************************************************//**
   Copyright 2021
   Silicon Labs, Inc.
   All rights reserved.

   @file     rs911x_commands.c

*******************************************************************************/


/*******************************************************************************
* INCLUDE FILES:
*******************************************************************************/
#include "sl_cli.h"
#include "sl_cli_arguments.h"
#include "rsi_wlan_apis.h"
#include "rsi_common_apis.h"
#include "rsi_bootup_config.h"
#include "rsi_wlan.h"
#include "rsi_ble_config.h"
#include "rsi_hal.h"
#include "utilities.h"
#include <string.h>
#include "rsi_driver.h"

/*******************************************************************************
* CONSTANTS:
*******************************************************************************/
//! Wireless driver task priority
#define RSI_DRIVER_TASK_PRIORITY   4
#define GLOBAL_BUFF_LEN         12000
#define RSI_DRIVER_TASK_STACK_SIZE  (2048/4)
#define CERT_VERIFY_TASK_STACK_SIZE (96)

/*******************************************************************************
* TYPES:
*******************************************************************************/
typedef void (*callback_handler_ptr)(uint16_t status, uint8_t* buffer, const uint32_t length);


/*******************************************************************************
* GLOBAL VARIABLES:
*******************************************************************************/
// globals for feature settings, referenced by #defines in rsi_wlan_config.h
uint32_t g_rsi_feature_bit_map = (FEAT_SECURITY_OPEN);
uint32_t g_rsi_tcp_ip_feature_bit_map = (TCP_IP_FEAT_DHCPV4_CLIENT | TCP_IP_FEAT_SSL | TCP_IP_FEAT_DNS_CLIENT);
uint32_t g_rsi_custom_feature_bit_map = (FEAT_CUSTOM_FEAT_EXTENTION_VALID);
uint32_t g_rsi_ext_custom_feature_bit_map = (EXT_FEAT_384K_MODE | EXT_FEAT_RSA_KEY_WITH_4096_SUPPORT | EXT_FEAT_SSL_CERT_WITH_4096_KEY_SUPPORT | EXT_FEAT_UART_SEL_FOR_DEBUG_PRINTS);
uint32_t g_rsi_bt_feature_bit_map = (BT_RF_TYPE | ENABLE_BLE_PROTOCOL);
uint32_t g_rsi_ext_tcp_ip_feature_bit_map = 0;
uint32_t g_rsi_ble_feature_bit_map = 0;
uint32_t g_rsi_ble_custom_ext_feature_bit_map = 0;
uint32_t g_rsi_config_feature_bit_map = 0;
uint8_t g_rsi_band = RSI_BAND_2P4GHZ;

//global which indicates how many times DUT is connected during run
uint32_t g_wifi_connections = 0;
//global which indicates how many times DUT is disconnected during run
uint32_t g_wifi_disconnections = 0;

//globals for socket limit settings, referenced by #defines in rsi_wlan_config.h
uint8_t g_rsi_ltcp_sockets = 0;
uint8_t g_rsi_client_sockets = 2;

//globals for socket WMM settings, referenced by #defines in rsi_wlan_config.h
uint8_t g_rsi_tos = 0;

//globals for power save parameters, referenced by #defines in rsi_wlan_config.h
uint8_t g_dtim_aligned_type = 0;
uint16_t g_monitor_interval = 50;
uint8_t g_num_of_dtim_skip = 0;

//globals for rsi_set_tx_wait_time settings, referenced by #defines in rsi_wlan_config.h
uint32_t g_tx_wait_time = 0;

extern rsi_rsp_ipv4_parmas_t current_ip;

/*******************************************************************************
* MACROS:
*******************************************************************************/
/* This Macro section should contain Macro functions used only in this module */
/******************************************************************************/

/*******************************************************************************
* LOCAL VARIABLES:
*******************************************************************************/
/* All following variables declared here must be declared 'static' */
static uint8_t s_global_buf[GLOBAL_BUFF_LEN];
static rsi_task_handle_t s_driver_task_handle = NULL;
static rsi_task_handle_t s_cert_task_handle = NULL;
static bool s_driver_initialized = false;
static bool s_device_initialized = false;
static uint8_t* s_certificate_buffer = NULL;
static uint32_t s_certificate_length = 0;
static rsi_semaphore_handle_t s_cert_verify_sem;
static uint16_t s_ssl_verify_sock_id;

/*******************************************************************************
* FUNCTION PROTOTYPES (for local functions):
*******************************************************************************/
/* All following functions declared here must be declared 'static' */
static void join_fail_handler(uint16_t status, const uint8_t* buffer, const uint32_t length);
static void ip_renewal_fail_handler(uint16_t status, const uint8_t* buffer, const uint32_t length);
static void ip_change_handler(uint16_t status, const uint8_t* buffer, const uint32_t length);
static void certificate_response_handler(uint16_t status, const uint8_t* buffer, const uint32_t length);
static void rsi_wlan_async_module_state(uint16_t status, uint8_t* payload, const uint32_t payload_length);
static void rsi_app_task_verify_certificate(void);
static void remote_terminate_handler(uint16_t status, const uint8_t* buffer, const uint32_t length);

/*******************************************************************************
*
*                       IMPLEMENTATION: Public functions
*
*******************************************************************************/
void rsi_set_features(sl_cli_command_arg_t* arguments)
{
    uint8_t arg_idx = 0;
    g_rsi_feature_bit_map = sl_cli_get_argument_uint32(arguments, arg_idx++);
    g_rsi_tcp_ip_feature_bit_map = sl_cli_get_argument_uint32(arguments, arg_idx++);
    g_rsi_custom_feature_bit_map = sl_cli_get_argument_uint32(arguments, arg_idx++);
    g_rsi_ext_custom_feature_bit_map = sl_cli_get_argument_uint32(arguments, arg_idx++);
    g_rsi_bt_feature_bit_map = sl_cli_get_argument_uint32(arguments, arg_idx++);
    g_rsi_ext_tcp_ip_feature_bit_map = sl_cli_get_argument_uint32(arguments, arg_idx++);
    // Note: BLE feature bitmap and BLE custom ext feature bitmap are not currently configurable by SAPI driver
    g_rsi_ble_feature_bit_map = sl_cli_get_argument_uint32(arguments, arg_idx++);
    g_rsi_ble_custom_ext_feature_bit_map = sl_cli_get_argument_uint32(arguments, arg_idx++);
    g_rsi_config_feature_bit_map = sl_cli_get_argument_uint32(arguments, arg_idx++);
    g_rsi_band = sl_cli_get_argument_uint8(arguments, arg_idx++);

    g_wifi_connections = 0;
    g_wifi_disconnections = 0;
    print_status(RSI_ERROR_NONE);
}


void rsi_set_socket_limit(sl_cli_command_arg_t* arguments)
{
	g_rsi_ltcp_sockets = sl_cli_get_argument_uint8(arguments, 0);
	g_rsi_client_sockets = sl_cli_get_argument_uint8(arguments, 1);

	print_status(RSI_ERROR_NONE);
}

void rsi_set_tos_field(sl_cli_command_arg_t* arguments)
{
	g_rsi_tos = sl_cli_get_argument_uint8(arguments, 0);
}

void rsi_device_init_command(sl_cli_command_arg_t* arguments)
{
    int32_t status;
    uint8_t arg_idx = 0;
    uint16_t opermode = sl_cli_get_argument_uint16(arguments, arg_idx++);
    uint16_t coex_mode = sl_cli_get_argument_uint16(arguments, arg_idx++);

    //! Driver initialization
    if (!s_driver_initialized) {
        // rsi_driver_init must only be called once
        status = rsi_driver_init(s_global_buf, GLOBAL_BUFF_LEN);
        if ((status < 0) || (status > GLOBAL_BUFF_LEN)) {
            print_status(status);
            return;
        }
        s_driver_initialized = true;
        rsi_semaphore_create(&s_cert_verify_sem, 0);
    }

    //! RS device intialisation
    if (s_device_initialized) {
        // if rsi_device_init was previously called, we must call rsi_device_deinit before calling it again
        rsi_device_deinit();
        s_device_initialized = false;
    }
    status = rsi_device_init(LOAD_NWP_FW);
    if (status != RSI_SUCCESS) {
        printf("\r\nDevice Initialization Failed, Error Code : 0x%X\r\n", (uint16_t)status);
        return;
    }
    else {
        printf("\r\nDevice Initialization Success\r\n");
    }
    s_device_initialized = true;

    //! Task created for Driver task
    if (s_driver_task_handle == NULL) {
        // Only one instance of the driver task should be created
        rsi_task_create((rsi_task_function_t)rsi_wireless_driver_task,
            (uint8_t*)"wireless_task",
            RSI_DRIVER_TASK_STACK_SIZE,
            NULL,
            RSI_DRIVER_TASK_PRIORITY,
            &s_driver_task_handle);
    }
    if (s_cert_task_handle == NULL && (g_rsi_ext_tcp_ip_feature_bit_map & EXT_TCP_IP_CERT_BYPASS)) {
        rsi_task_create((void*)rsi_app_task_verify_certificate,
            (uint8_t*)"cert_verify_task",
            CERT_VERIFY_TASK_STACK_SIZE,
            NULL,
            RSI_DRIVER_TASK_PRIORITY,
            &s_cert_task_handle);
    }

    //! WiSeConnect initialization
    //0x5A5A represents auto join is successful
    status = rsi_wireless_init(opermode, coex_mode);
    if ((status != RSI_SUCCESS) && (status != 0x5A5A)) {
        printf("\r\nWireless Initialization Failed, Error Code : 0x%X\r\n", (uint16_t)status);
        return;
    }
    else {
        printf("\r\nWireless Initialization Success\r\n");
    }

    // Register callbacks
    rsi_wlan_register_callbacks(RSI_JOIN_FAIL_CB, (callback_handler_ptr)join_fail_handler);
    rsi_wlan_register_callbacks(RSI_IP_FAIL_CB, (callback_handler_ptr)ip_renewal_fail_handler);
    rsi_wlan_register_callbacks(RSI_IP_CHANGE_NOTIFY_CB, (callback_handler_ptr)ip_change_handler);
    rsi_wlan_register_callbacks(RSI_WLAN_ASYNC_STATS, (callback_handler_ptr)rsi_wlan_async_module_state);
    rsi_wlan_register_callbacks(RSI_REMOTE_SOCKET_TERMINATE_CB, (callback_handler_ptr)remote_terminate_handler);
    if (g_rsi_ext_tcp_ip_feature_bit_map & EXT_TCP_IP_CERT_BYPASS)
        rsi_wlan_register_callbacks(RSI_WLAN_SERVER_CERT_RECEIVE_NOTIFY_CB, (callback_handler_ptr)certificate_response_handler);
}

void rsi_device_reset_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    print_status(rsi_bl_module_power_cycle());
}

void rsi_efr_reset_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    printf("Resetting MCU...\r\n");
    NVIC_SystemReset();
}

void ram_dump_command(sl_cli_command_arg_t* arguments)
{
    uint32_t start_address = sl_cli_get_argument_uint32(arguments, 0);
    uint32_t end_address = sl_cli_get_argument_uint32(arguments, 1);
    if (end_address < start_address) {
        print_status(RSI_ERROR_INVALID_ADDRESS);
        return;
    }
    uint32_t offset = start_address;
    uint32_t content_length = end_address - start_address + 1;
    uint32_t bytes_left = content_length;
    const uint32_t max_chunk_size = 1024;
    uint8_t *ram_buffer = malloc(max_chunk_size);
    uint32_t chunk_len;
    int32_t status;
    uint32_t iteration = 0;

    while (bytes_left) {
        uint32_t chunk_len = (bytes_left >= max_chunk_size) ? max_chunk_size : bytes_left;
        int32_t status = rsi_get_ram_dump(offset, chunk_len, ram_buffer);
        if (status != RSI_SUCCESS) {
            break;
        }
        // print buffer in base64
        char* b64data = base64_encode(ram_buffer, chunk_len);
        if (iteration == 0)
            printf("\r\nSAPI+RSI_RAM_DATA %s ", b64data);
        else
            printf("%s ", b64data);
        free(b64data);
        // adjust counters
        bytes_left -= chunk_len;
        offset += chunk_len;
        iteration += 1;
    }
    free(ram_buffer);
    print_status(status);
}

void rsi_device_version_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    uint8_t fw_version[20];
    int32_t status = rsi_get_fw_version(fw_version, sizeof(fw_version));

    if (status == RSI_ERROR_NONE)
    {
        printf("%s\r\n", fw_version);
    }
    else
    {
        print_status(status);
    }
}

void rsi_device_set_sleep(sl_cli_command_arg_t* arguments)
{
    uint8_t value = sl_cli_get_argument_uint8(arguments, 0);
    if (value == 0)
    {
        rsi_hal_clear_gpio(RSI_HAL_SLEEP_CONFIRM_PIN);
    }
    else
    {
        rsi_hal_set_gpio(RSI_HAL_SLEEP_CONFIRM_PIN);
    }
    print_status(RSI_SUCCESS);
}

void rsi_device_read_wake(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    uint8_t value = rsi_hal_get_gpio(RSI_HAL_WAKEUP_INDICATION_PIN);
    printf("\r\n%d\r\n", value);
    print_status(RSI_SUCCESS);
}

void rsi_device_power_save(sl_cli_command_arg_t* arguments)
{
    uint8_t psp_mode = sl_cli_get_argument_uint8(arguments, 0);
    uint8_t psp_type = sl_cli_get_argument_uint8(arguments, 1);
    int32_t status = rsi_wlan_power_save_profile(psp_mode, psp_type);
    print_status(status);
}



void begin_set_ssl_certificate(sl_cli_command_arg_t* arguments)
{
    uint16_t length = sl_cli_get_argument_uint16(arguments, 0);
    if (s_certificate_buffer != NULL)
    {
        free(s_certificate_buffer);
    }
    s_certificate_length = length;
    s_certificate_buffer = malloc(length + 1);
    if (s_certificate_buffer == NULL)
    {
        print_status(RSI_ERROR_INSUFFICIENT_BUFFER);
    }
    else
    {
        print_status(RSI_SUCCESS);
    }
}

void set_ssl_certificate_part(sl_cli_command_arg_t* arguments)
{
    uint16_t offset = sl_cli_get_argument_uint16(arguments, 0);
    char* cert_data = sl_cli_get_argument_string(arguments, 1);
    uint32_t data_len = strlen(cert_data);
    cert_data[data_len - 1] = '\n';

    if (s_certificate_buffer == NULL)
    {
        print_status(RSI_ERROR_INSUFFICIENT_BUFFER);
    }
    else
    {
        memcpy(&s_certificate_buffer[offset], cert_data, strlen(cert_data) + 1);
    }
    print_status(RSI_SUCCESS);
}

void end_set_ssl_certificate(sl_cli_command_arg_t* arguments)
{
    uint8_t cert_type = sl_cli_get_argument_uint8(arguments, 0);
    uint8_t cert_index = sl_cli_get_argument_uint8(arguments, 1);
    if (s_certificate_buffer == NULL)
    {
        print_status(RSI_ERROR_INSUFFICIENT_BUFFER);
    }
    else
    {
        int32_t status = rsi_wlan_set_certificate_index(cert_type, cert_index, NULL, 0);
        if (status == RSI_SUCCESS) {
            status = rsi_wlan_set_certificate_index(cert_type, cert_index, s_certificate_buffer, s_certificate_length);
        }
        print_status(status);
        free(s_certificate_buffer);
        s_certificate_buffer = NULL;
        s_certificate_length = 0;
    }

}

void rsi_clear_cert(sl_cli_command_arg_t* arguments)
{
	uint8_t cert_type = sl_cli_get_argument_uint8(arguments, 0);
	uint8_t cert_index = sl_cli_get_argument_uint8(arguments, 1);

	int32_t status = rsi_wlan_set_certificate_index(cert_type, cert_index, NULL, 0);
	print_status(status);

}

void rsi_set_band_command(sl_cli_command_arg_t* arguments)
{
    g_rsi_band = sl_cli_get_argument_uint8(arguments, 0);
    print_status(RSI_ERROR_NONE);
}

/*******************************************************************************
*
*                       IMPLEMENTATION: Private functions
*
*******************************************************************************/

static void join_fail_handler(uint16_t status, const uint8_t* buffer, const uint32_t length)
{
    (void)buffer;
    (void)length;
    printf("\r\nSAPI+REJOIN_ERROR %d\r\n", status);
}

void remote_terminate_handler(uint16_t status, const uint8_t* buffer, const uint32_t length)
{
	uint32_t bytes_sent = rsi_bytes4R_to_uint32(&buffer[2]);
	uint16_t socket_id = rsi_bytes2R_to_uint16(&buffer[0]);
	printf("\r\nSAPI+REMOTE_TERMINATE status:%d,socket_id:%d,bytes_sent:%d\r\n", status, socket_id, bytes_sent);
}


void rsi_wlan_async_module_state(uint16_t status, uint8_t* payload, const uint32_t payload_length)
{
    UNUSED_PARAMETER(status);

    if (payload_length != sizeof(rsi_state_notification_t))
        return;

    rsi_state_notification_t* state = (rsi_state_notification_t*)payload;

    if ((state->StateCode & 0xF0) == 0x80)
    {
        g_wifi_connections++;
        printf("\r\nWi-Fi connections %ld\r\n", g_wifi_connections);
    }

    if ((state->StateCode & 0xF0) == 0x90)
    {
        g_wifi_disconnections++;
        printf("\r\nWi-Fi disconnections %ld\r\n", g_wifi_disconnections);
    }
}

static void ip_renewal_fail_handler(uint16_t status, const uint8_t* buffer, const uint32_t length)
{
    UNUSED_PARAMETER(status);
    UNUSED_CONST_PARAMETER(buffer);
    UNUSED_CONST_PARAMETER(length);
    printf("\r\nSAPI+RSI_IPCONF_FAILURE %d\r\n", status);
}

static void ip_change_handler(uint16_t status, const uint8_t* buffer, const uint32_t length)
{
    UNUSED_PARAMETER(status);
    if (length == sizeof(rsi_rsp_ipv4_parmas_t)) {
        current_ip = *((rsi_rsp_ipv4_parmas_t*)(buffer));
    }
    printf("\r\nSAPI+RSI_IPCONF %d.%d.%d.%d %d.%d.%d.%d %d.%d.%d.%d\r\n",
        current_ip.ipaddr[0], current_ip.ipaddr[1], current_ip.ipaddr[2], current_ip.ipaddr[3],
        current_ip.netmask[0], current_ip.netmask[1], current_ip.netmask[2], current_ip.netmask[3],
        current_ip.gateway[0], current_ip.gateway[1], current_ip.gateway[2], current_ip.gateway[3]);
}

static void certificate_response_handler(uint16_t status, const uint8_t* buffer, const uint32_t length)
{
    UNUSED_PARAMETER(status);
    UNUSED_CONST_PARAMETER(length);
    rsi_cert_recv_t* cert_recev = (rsi_cert_recv_t*)buffer;
    s_ssl_verify_sock_id = rsi_bytes2R_to_uint16(cert_recev->sock_desc);
    if (cert_recev->more_chunks == 0) {
        rsi_semaphore_post(&s_cert_verify_sem);
    }
}

static void rsi_app_task_verify_certificate()
{
    while (1) {
        rsi_semaphore_wait(&s_cert_verify_sem, 0);
        rsi_certificate_valid(1, s_ssl_verify_sock_id);
        s_ssl_verify_sock_id = 0;
    }
}

void rsi_set_default_connection_stats()
{
    g_wifi_connections = 0;
    g_wifi_disconnections = 0;
}

void wlan_radio_init_command()
{

    print_status(rsi_wlan_radio_init());
}

void rsi_set_power_save_params(sl_cli_command_arg_t* arguments)
{
	uint8_t g_dtim_aligned_type = sl_cli_get_argument_uint8(arguments, 0);
	uint16_t g_monitor_interval = sl_cli_get_argument_uint16(arguments, 1);
	uint8_t g_num_of_dtim_skip = sl_cli_get_argument_uint8(arguments, 2);
	print_status(RSI_ERROR_NONE);
}

void rsi_set_tx_wait_time(sl_cli_command_arg_t* arguments)
{
	g_tx_wait_time = sl_cli_get_argument_uint32(arguments, 0);
}

void rsi_device_power_save_listen_interval(sl_cli_command_arg_t* arguments)
{
	uint8_t psp_mode = sl_cli_get_argument_uint8(arguments, 0);
	uint8_t psp_type = sl_cli_get_argument_uint8(arguments, 1);
	uint16_t listen_interval = sl_cli_get_argument_uint8(arguments, 2);
	int32_t status = rsi_wlan_power_save_with_listen_interval(psp_mode, psp_type, listen_interval);
	print_status(status);
}

void wlan_request_radio_command(sl_cli_command_arg_t* arguments)
{
	uint8_t radio_enable = sl_cli_get_argument_uint8(arguments, 0);
	int32_t status = rsi_wlan_req_radio(radio_enable);
	print_status(status);
}
