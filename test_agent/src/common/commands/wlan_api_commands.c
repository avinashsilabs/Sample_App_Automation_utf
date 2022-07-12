/***************************************************************************//**
   Copyright 2021
   Silicon Labs, Inc.
   All rights reserved.

   @file     wlan_api_commands.c

*******************************************************************************/


/*******************************************************************************
* INCLUDE FILES:
*******************************************************************************/
#include "rsi_wlan_apis.h"
#include "rsi_error.h"
#include "rsi_wlan.h"
#include "sl_cli.h"
#include "sl_cli_arguments.h"
//#include "wifi_variables.h"
#include "utilities.h"
#include <string.h>
#include "rsi_driver.h"

/*******************************************************************************
* CONSTANTS:
*******************************************************************************/
#define SCAN_RESULT_COUNT (11)
#define SCAN_RESULT_SIZE  (sizeof(rsi_rsp_scan_t) * SCAN_RESULT_COUNT)
#define RSI_HTTP_OTAF_UPGRADE_SUCCESS 1
#define RSI_HTTP_OTAF_UPGRADE_FAILED 2

/*******************************************************************************
* TYPES:
*******************************************************************************/


/*******************************************************************************
* GLOBAL VARIABLES:
*******************************************************************************/
//globals for scan feature settings, referenced by #defines in rsi_wlan_config.h
uint16_t g_rsi_scan_channel_bitmap_2_4 = 0;
uint32_t  g_rsi_scan_channel_bitmap_5_0 = 0;
uint8_t  g_rsi_scan_add_feature = 0;

//globals for rejoin, referenced by #defines in rsi_wlan_config.h
uint32_t g_rsi_rejoin_max_retry = 20;
uint32_t g_rsi_rejoin_scan_interval = 6;
uint32_t g_rsi_rejoin_beacon_missed_count = 40;
uint32_t g_rsi_rejoin_first_time_retry = 0;

//globals for eap settings, referenced by #defines in rsi_wlan_config.h
uint8_t g_rsi_eap_method[EAP_METHOD_LEN];
uint8_t g_rsi_eap_inner_method[EAP_INNER_METHOD_LEN];
uint8_t g_rsi_private_key_password[EAP_PASSWORD_LEN];

uint8_t  g_rsi_set_region = 1;  //by default region configurations taken from user
uint8_t  g_rsi_region_code = 1; //by default region selected is US
uint16_t  g_rsi_module_type = 1; //by default antenna selected is board antenna

//globals for join,referenced by #defines in rsi_wlan_config.h
uint8_t g_rsi_power_level;
uint8_t g_rsi_join_feat_bit_map;
uint32_t g_rsi_listen_interval;
uint8_t g_rsi_data_rate;

//globals for selecting ssl ciphers, referenced by #defines in rsi_wlan_common_config.h file
uint32_t g_rsi_ssl_ciphers = (SSL_DEFAULT_CIPHERS | BIT_TLS_RSA_WITH_AES_256_CBC_SHA256 | BIT_TLS_RSA_WITH_AES_128_CBC_SHA256 \
    | BIT_TLS_RSA_WITH_AES_256_CBC_SHA | BIT_TLS_RSA_WITH_AES_128_CBC_SHA | BIT_TLS_RSA_WITH_AES_128_CCM_8 \
    | BIT_TLS_RSA_WITH_AES_256_CCM_8);


//globals for bg scan, referenced by #defines in rsi_wlan_config.h
uint16_t g_rsi_bg_scan_enable = 0;
//instant BG scan
uint16_t g_rsi_instant_bg = 0;
//BG scan threshold value
uint16_t g_rsi_bg_scan_threshold = 63;
//RSSI tolerance Threshold
uint16_t g_rsi_rssi_tolerance_threshold = 4;
//BG scan periodicity
uint16_t g_rsi_bg_scan_periodicity = 2;
// Active scan duration
uint16_t g_rsi_active_scan_duration = 50;
//Passive scan duration
uint16_t g_rsi_passive_scan_duration = 50;
// Multi probe
uint8_t g_rsi_multiprobe = 0;

//globals for roaming, referenced by #defines in rsi_wlan_config.h
uint32_t g_rsi_roaming_threshold = 67;
uint32_t g_rsi_roaming_hysterisis = 4;

//globals for timeout, referenced by #defines in rsi_wlan_config.h
uint32_t g_rsi_timeout_bit_map = 4;
uint16_t g_rsi_timeout_value = 10;

//globals for AP region parameters, referenced by #defines in rsi_wlan_config.h
uint8_t g_region_config = 0;
uint8_t g_region_code[4] = "US ";

//globals for AP mode ht caps parameters, referenced by #defines in rsi_wlan_config.h
uint16_t g_rsi_ht_caps_bitmap = 0;

extern int sli_cli_io_getchar();
extern int32_t rsi_wlan_pmk_generate(int8_t type, int8_t* psk, int8_t* ssid, uint8_t* pmk, uint16_t length);


/*******************************************************************************
* MACROS:
*******************************************************************************/
/* This Macro section should contain Macro functions used only in this module */
/******************************************************************************/

/*******************************************************************************
* LOCAL VARIABLES:
*******************************************************************************/
/* All following variables declared here must be declared 'static' */
static volatile int32_t http_recv_status;
static uint32_t otaf_status = 0xAAAA;


/*******************************************************************************
* FUNCTION PROTOTYPES (for local functions):
*******************************************************************************/
/* All following functions declared here must be declared 'static' */
static void scan_response_handler(uint16_t status, const uint8_t* buffer, const uint16_t length);
static void join_response_handler(uint16_t status, const uint8_t* buffer, const uint16_t length);
static void wlan_wfd_discovery_notify_handler(uint16_t status, uint8_t* buffer, const uint32_t length);
static void wlan_wfd_connection_request_notify_handler(uint16_t status, uint8_t* buffer, const uint32_t length);
static void wlan_ping_response_handler(uint16_t status, const uint8_t* buffer, const uint16_t length);
static void http_otaf_response_handler(uint16_t status, const uint8_t* buffer);


/*******************************************************************************
*
*                       IMPLEMENTATION: Public functions
*
*******************************************************************************/
void rsa_wlan_set_mac_address(sl_cli_command_arg_t* arguments)
{
    uint8_t mac_address[6];
    char* mac_addr_str = sl_cli_get_argument_string(arguments, 0);
    for (int i=0; i<6; i++) {
        int val;
        sscanf(mac_addr_str + 3 * i, "%02X", &val);
        mac_address[i] = (uint8_t)val;
    }
    int32_t status = rsi_wlan_set(RSI_SET_MAC_ADDRESS, mac_address, (uint16_t)sizeof(mac_address));
    print_status(status);
}

void rsi_set_join_bssid(sl_cli_command_arg_t* arguments)
{
	uint8_t mac_address[6];
	char* mac_addr_str = sl_cli_get_argument_string(arguments, 0);
	for (int i = 0; i < 6; i++) {
		int val;
		sscanf(mac_addr_str + 3 * i, "%02X", &val);
		mac_address[i] = (uint8_t)val;
	}
	int32_t status = rsi_wlan_set(RSI_JOIN_BSSID, mac_address, (uint16_t)sizeof(mac_address));
	print_status(status);
}

void rsa_wlan_get_mac_address(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    uint8_t mac_address[6];
    int32_t status = rsi_wlan_get(RSI_MAC_ADDRESS, mac_address, (uint16_t)sizeof(mac_address));
    if (status == 0) {
        printf("\n%02x:%02x:%02x:%02x:%02x:%02x\n",
            mac_address[0],
            mac_address[1],
            mac_address[2],
            mac_address[3],
            mac_address[4],
            mac_address[5]);
    }
    print_status(status);
}
void rsi_get_wlan_stats(sl_cli_command_arg_t* arguments)
{
	(void)arguments;
	int32_t status = 0;
	rsi_rsp_wlan_stats_t wlan_stats;
	status = rsi_wlan_get(RSI_GET_WLAN_STATS, (uint8_t *)&wlan_stats, (uint16_t)sizeof(rsi_rsp_wlan_stats_t));
	if(!status)
	{
		printf("\nwlan stats:%d,%d,%d,%d,%d\n", wlan_stats.operating_mode, wlan_stats.dtim_period, rsi_bytes2R_to_uint16(&(wlan_stats.ideal_beacon_info[0])), rsi_bytes2R_to_uint16(&(wlan_stats.busy_beacon_info[0])), rsi_bytes2R_to_uint16(&(wlan_stats.beacon_interval[0])));
	}
	print_status(status);
}
void rsi_get_network_params(sl_cli_command_arg_t* arguments)
{
	(void)arguments;
	int32_t status = 0;
	int16_t socket_count = 0;
	uint8_t ii = 0;
	uint8_t iii = 0;
	rsi_rsp_sockets_info_t socket_info;

	status = rsi_wlan_get(RSI_SOCKETS_INFO, (uint8_t *)&socket_info, (uint16_t)sizeof(rsi_rsp_sockets_info_t));
	if(!status)
	{
		socket_count = rsi_bytes2R_to_uint16(&(socket_info.num_open_socks[0]));
		printf("\nSockets in open state:%d\n",socket_count);
		for(ii=0; ii<socket_count; ii++)
		{
			printf("\nsocket_no %d info:%d,%d,%d,%d,",(ii+1), rsi_bytes2R_to_uint16(&(socket_info.socket_info[ii].sock_id[0])), rsi_bytes2R_to_uint16(&(socket_info.socket_info[ii].sock_type[0])), rsi_bytes2R_to_uint16(&(socket_info.socket_info[ii].source_port[0])), rsi_bytes2R_to_uint16(&(socket_info.socket_info[ii].dest_port[0])));
			for(iii=0; iii<4; iii++)
			{
				printf("%d-",socket_info.socket_info[ii].dest_ip_address.ipv4_address[iii]);
			}
			printf("\n");
		}
	}
	print_status(status);
}

void rsi_get_wireless_info(sl_cli_command_arg_t* arguments)
{
	(void)arguments;
	int32_t status = 0;
	uint8_t ii = 0;
	rsi_rsp_wireless_info_t wlan_info;
	status = rsi_wlan_get(RSI_WLAN_INFO, (uint8_t *)&wlan_info, (uint16_t)sizeof(rsi_rsp_wireless_info_t));
	if(!status)
	{
		printf("\nwlan stats:%d,%d,%s,", wlan_info.wlan_state,wlan_info.channel_number, (&wlan_info.ssid[0]));
		for(ii=0; ii<6; ii++)
		{
			printf("%02x-", wlan_info.mac_address[ii]);
		}
		printf(",%d,%s,", wlan_info.sec_type, (&wlan_info.psk[0]));
		for(ii=0; ii<4; ii++)
		{
			printf("%d-", wlan_info.ipv4_address[ii]);
		}
		printf(",");
		for(ii=0; ii<16; ii++)
		{
			printf("%d-", wlan_info.ipv6_address[ii]);
		}
		printf("\n");
	}
	print_status(status);
}


void rsi_wlan_scan_command(sl_cli_command_arg_t* arguments)
{
    rsi_rsp_scan_t* scan_results = malloc(SCAN_RESULT_SIZE);
    if (scan_results == NULL) {
        printf("unable to allocate memory for scan results\n");
        return;
    }

    memset(scan_results, '\0', SCAN_RESULT_SIZE);
    char* ssid = sl_cli_get_argument_string(arguments, 0);
    uint8_t channel = sl_cli_get_argument_uint8(arguments, 1);
    int32_t status = rsi_wlan_scan((int8_t*)ssid, channel, scan_results, SCAN_RESULT_SIZE);

    if (status == 0) {
        printf("%d scan results:\n", scan_results->scan_count[0]);
        for (int a = 0; a < scan_results->scan_count[0]; ++a) {
            printf("%s,%d,%d,%02x:%02x:%02x:%02x:%02x:%02x,%d,-%u\n",
                scan_results->scan_info[a].ssid,
                scan_results->scan_info[a].security_mode,
                scan_results->scan_info[a].network_type,
                scan_results->scan_info[a].bssid[0],
                scan_results->scan_info[a].bssid[1],
                scan_results->scan_info[a].bssid[2],
                scan_results->scan_info[a].bssid[3],
                scan_results->scan_info[a].bssid[4],
                scan_results->scan_info[a].bssid[5],
                scan_results->scan_info[a].rf_channel,
                scan_results->scan_info[a].rssi_val);
        }
    }

    print_status(status);
    free(scan_results);
}

void rsi_wlan_pmk_generate_command(sl_cli_command_arg_t* arguments)
{
    uint8_t pmk_result[32] = { 0 };

    uint8_t psk_type = sl_cli_get_argument_uint8(arguments, 0);
    char* psk = sl_cli_get_argument_string(arguments, 1);
    char* ssid = sl_cli_get_argument_string(arguments, 2);

    int32_t status = rsi_wlan_pmk_generate(psk_type, (int8_t*)psk, (int8_t*)ssid, pmk_result, sizeof(pmk_result));

    if (status == 0) {
        printf("pmk:%s\n", pmk_result);
    }
    print_status(status);
}

void rsi_wlan_pmk_generate_connect_command(sl_cli_command_arg_t* arguments)
{
    uint8_t pmk_result[32] = { 0 };

    uint8_t psk_type = sl_cli_get_argument_uint8(arguments, 0);
    char* psk = sl_cli_get_argument_string(arguments, 1);
    char* ssid = sl_cli_get_argument_string(arguments, 2);

    int32_t status = rsi_wlan_pmk_generate(psk_type, (int8_t*)psk, (int8_t*)ssid, pmk_result, sizeof(pmk_result));
    if (status != RSI_SUCCESS) {
        print_status(status);
        return;
    }
    print_status(rsi_wlan_connect((int8_t*)ssid, 8, (int8_t*)pmk_result));
}

void rsi_wlan_scan_async_command(sl_cli_command_arg_t* arguments)
{
    char* ssid = sl_cli_get_argument_string(arguments, 0);
    uint8_t channel = sl_cli_get_argument_uint8(arguments, 1);
    print_status(rsi_wlan_scan_async((int8_t*)ssid, channel, scan_response_handler));
}

void rsi_wlan_connect_command(sl_cli_command_arg_t* arguments)
{
    char* ssid = sl_cli_get_argument_string(arguments, 0);
    uint8_t security = sl_cli_get_argument_uint8(arguments, 1);
    char* secret = sl_cli_get_argument_string(arguments, 2);
    g_rsi_power_level = sl_cli_get_argument_uint8(arguments, 3);
    g_rsi_join_feat_bit_map = sl_cli_get_argument_uint8(arguments, 4);
    g_rsi_listen_interval = sl_cli_get_argument_uint32(arguments, 5);
    g_rsi_data_rate = sl_cli_get_argument_uint8(arguments, 6);

    print_status(rsi_wlan_connect((int8_t*)ssid, security, (int8_t*)secret));
}

void rsi_wlan_connect_async_command(sl_cli_command_arg_t* arguments)
{
    char* ssid = sl_cli_get_argument_string(arguments, 0);
    uint8_t security = sl_cli_get_argument_uint8(arguments, 1);
    char* secret = sl_cli_get_argument_string(arguments, 2);
    print_status(rsi_wlan_connect_async((int8_t*)ssid, security, (int8_t*)secret, join_response_handler));
}

void rsi_wlan_ap_start_command(sl_cli_command_arg_t* arguments)
{
    char* ssid = sl_cli_get_argument_string(arguments, 0);
    uint8_t channel = sl_cli_get_argument_uint8(arguments, 1);
    uint8_t security = sl_cli_get_argument_uint8(arguments, 2);
    uint8_t encryption = sl_cli_get_argument_uint8(arguments, 3);
    char* secret = sl_cli_get_argument_string(arguments, 4);
    uint16_t beacon = sl_cli_get_argument_uint16(arguments, 5);
    uint8_t dtim = sl_cli_get_argument_uint8(arguments, 6);

    print_status(rsi_wlan_ap_start((int8_t*)ssid, channel, security, encryption, (uint8_t*)secret, beacon, dtim));
}

void rsi_wlan_execute_post_connect_cmds_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    print_status(rsi_wlan_execute_post_connect_cmds());
}

void rsi_wlan_disconnect_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;

    print_status(rsi_wlan_disconnect());

    // switch (rsi_wlan_disconnect()) {
    //   case RSI_ERROR_PKT_ALLOCATION_FAILURE: printf("Disconnect fail\n"); break;
    //   case RSI_ERROR_WLAN_CMD_IN_PROGRESS:   printf("Disconnect fail\n"); break;
    //   default: break;
    // }
}

void rsi_wlan_disconnect_stations_command(sl_cli_command_arg_t* arguments)
{
    size_t size = 0;
    uint8_t* mac = sl_cli_get_argument_hex(arguments, 0, &size);
    if (size == 6) {
        print_status(rsi_wlan_disconnect_stations(mac));
    }
    else {
        printf("Bad MAC address\n");
    }
}


void rsi_wlan_get_status_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    print_status(rsi_wlan_get_status());
}

void rsi_wlan_wps_generate_pin_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    uint8_t pin[RSI_WPS_PIN_LEN];
    int32_t status = rsi_wlan_wps_generate_pin(pin, (uint16_t)sizeof(pin));
    if (status == RSI_ERROR_NONE) {
        for (size_t a = 0; a < sizeof(pin); ++a) {
            printf("%c", ('0' + pin[a]));
        }
        printf("\n");
    }
    else {
        print_status(status);
    }
}

void rsi_wlan_wps_enter_pin_command(sl_cli_command_arg_t* arguments)
{
    char* pin = sl_cli_get_argument_string(arguments, 0);
    size_t pin_length = strlen(pin);
    for (size_t a = 0; a < pin_length; ++a) {
        pin[a] = pin[a] - '0';
    }
    print_status(rsi_wlan_wps_enter_pin((int8_t*)pin));
}

void rsi_wlan_wps_push_button_event_command(sl_cli_command_arg_t* arguments)
{
    char* ssid = sl_cli_get_argument_string(arguments, 0);
    print_status(rsi_wlan_wps_push_button_event((int8_t*)ssid));
}

void rsi_transmit_test_start_command(sl_cli_command_arg_t* arguments)
{
    uint16_t power = sl_cli_get_argument_uint16(arguments, 0);
    uint32_t rate = sl_cli_get_argument_uint32(arguments, 1);
    uint16_t length = sl_cli_get_argument_uint16(arguments, 2);
    uint16_t mode = sl_cli_get_argument_uint16(arguments, 3);
    uint16_t channel = sl_cli_get_argument_uint16(arguments, 4);
    print_status(rsi_transmit_test_start(power, rate, length, mode, channel));
}

void rsi_transmit_test_stop_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    print_status(rsi_transmit_test_stop());
}

void rsi_wlan_receive_stats_start_command(sl_cli_command_arg_t* arguments)
{
    uint16_t channel = sl_cli_get_argument_uint16(arguments, 0);
    print_status(rsi_wlan_receive_stats_start(channel));
}

void rsi_wlan_receive_stats_stop_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    print_status(rsi_wlan_receive_stats_stop());
}

void rsi_wlan_get_command(sl_cli_command_arg_t* arguments)
{
    uint16_t command = sl_cli_get_argument_uint16(arguments, 0);
    uint8_t response[100];
    print_status(rsi_wlan_get(command, response, sizeof(response)));
}

void rsi_wlan_set_command(sl_cli_command_arg_t* arguments)
{
    uint16_t command = sl_cli_get_argument_uint16(arguments, 0);
    print_status(rsi_wlan_set(command, NULL, 0));
}

void rsi_wlan_register_callbacks_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    printf("Not supported\n");
    //   print_status(rsi_wlan_register_callbacks());
}

void rsi_wlan_send_data_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    printf("Not supported\n");
    //   print_status(rsi_wlan_send_data());
}

void rsi_wlan_wfd_start_discovery_command(sl_cli_command_arg_t* arguments)
{
    uint16_t go_intent = sl_cli_get_argument_uint16(arguments, 0);
    char* device_name = sl_cli_get_argument_string(arguments, 1);
    uint16_t channel = sl_cli_get_argument_uint16(arguments, 2);
    char* ssid_post_fix = sl_cli_get_argument_string(arguments, 3);
    char* psk = sl_cli_get_argument_string(arguments, 4);

    print_status(rsi_wlan_wfd_start_discovery(go_intent,
        (int8_t*)device_name,
        channel,
        (int8_t*)ssid_post_fix,
        (uint8_t*)psk,
        wlan_wfd_discovery_notify_handler,
        wlan_wfd_connection_request_notify_handler));
}

void rsi_wlan_wfd_connect_command(sl_cli_command_arg_t* arguments)
{
    char* device_name = sl_cli_get_argument_string(arguments, 0);
    print_status(rsi_wlan_wfd_connect((int8_t*)device_name, join_response_handler));
}

void rsi_power_save_profile_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    //   uint8_t psp_mode = sl_cli_get_argument_uint8( arguments, 0 );
    //   uint8_t psp_type = sl_cli_get_argument_uint8( arguments, 1 );
    //   print_status( rsi_power_save_profile( psp_mode, psp_type ) );
    printf("Not supported\n");
}

void rsi_send_raw_data_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    printf("Not supported\n");
    //   print_status(rsi_send_raw_data());
}

void rsi_fill_config_profile_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    printf("Not supported\n");
    //   print_status(rsi_fill_config_profile());
}

void rsi_wlan_add_profile_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    printf("Not supported\n");
    //   print_status(rsi_wlan_add_profile());
}

void rsi_wlan_get_profile_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    printf("Not supported\n");
    //   print_status(rsi_wlan_get_profile());
}

void rsi_wlan_delete_profile_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    printf("Not supported\n");
    //   print_status(rsi_wlan_delete_profile());
}

void rsi_wlan_enable_auto_config_command(sl_cli_command_arg_t* arguments)
{
    uint8_t enable = sl_cli_get_argument_uint8(arguments, 0);
    uint32_t type = sl_cli_get_argument_uint32(arguments, 1);
    print_status(rsi_wlan_enable_auto_config(enable, type));
}

void rsi_wlan_bgscan_profile_command(sl_cli_command_arg_t* arguments)
{
    void* scan_results = malloc(SCAN_RESULT_SIZE);
    if (scan_results == NULL) {
        return;
    }

    uint8_t cmd = sl_cli_get_argument_uint8(arguments, 0);
    print_status(rsi_wlan_bgscan_profile(cmd, scan_results, SCAN_RESULT_SIZE));

    free(scan_results);
}

void rsi_wlan_update_gain_table_command(sl_cli_command_arg_t* arguments)
{

    uint8_t band = sl_cli_get_argument_uint8(arguments, 0);
    uint8_t bandwidth = sl_cli_get_argument_uint8(arguments, 1);
    uint16_t length = sl_cli_get_argument_uint16(arguments, 2);
    uint8_t* const buffer = malloc(length);
    if (buffer == NULL)
        return;

    for (uint8_t* iter = buffer; length != 0; --length) {
        *iter = (uint8_t)sli_cli_io_getchar();
        ++iter;
    }

    print_status(rsi_wlan_update_gain_table(band, bandwidth, buffer, sl_cli_get_argument_uint16(arguments, 2)));

    free(buffer);
}

void rsi_wlan_power_save_profile_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    printf("Not supported\n");
    //   print_status(rsi_wlan_power_save_profile());
}

void rsi_wlan_scan_with_bitmap_options_command(sl_cli_command_arg_t* arguments)
{
    rsi_rsp_scan_t* scan_results = malloc(SCAN_RESULT_SIZE);
    if (scan_results == NULL) {
        printf("unable to allocate memory for scan results\n");
        return;
    }

    memset(scan_results, '\0', SCAN_RESULT_SIZE);

    char* ssid = sl_cli_get_argument_string(arguments, 0);
    uint8_t channel = sl_cli_get_argument_uint8(arguments, 1);
    uint32_t scan_bitmap = sl_cli_get_argument_uint32(arguments, 2);
    print_status(rsi_wlan_scan_with_bitmap_options((int8_t*)ssid, channel, scan_results, SCAN_RESULT_SIZE, scan_bitmap));

    free(scan_results);
}

void rsi_wlan_scan_async_with_bitmap_options_command(sl_cli_command_arg_t* arguments)
{
    char* ssid = sl_cli_get_argument_string(arguments, 0);
    uint8_t channel = sl_cli_get_argument_uint8(arguments, 1);
    uint32_t scan_bitmap = sl_cli_get_argument_uint32(arguments, 2);
    print_status(rsi_wlan_scan_async_with_bitmap_options((int8_t*)ssid, channel, scan_bitmap, scan_response_handler));
}

void rsi_wlan_ping_async_command(sl_cli_command_arg_t* arguments)
{
    uint8_t flags = sl_cli_get_argument_uint8(arguments, 0);
    char* ip_string = sl_cli_get_argument_string(arguments, 1);
    uint16_t size = sl_cli_get_argument_uint16(arguments, 2);
    uint32_t ip_address = str_to_ipv4(ip_string);
    int32_t status = rsi_wlan_ping_async(flags, (uint8_t*)&ip_address, size, wlan_ping_response_handler);
    if (status != RSI_SUCCESS)
        print_status(status);
}




void rsi_wlan_eap_connect_command(sl_cli_command_arg_t* arguments)
{
    rsi_eap_credentials_t credentials;

    char* ssid = sl_cli_get_argument_string(arguments, 0);
    uint8_t security = sl_cli_get_argument_uint8(arguments, 1);
    char* user_name = sl_cli_get_argument_string(arguments, 2);
    char* eap_password = sl_cli_get_argument_string(arguments, 3);

    memset(&credentials, 0, sizeof(rsi_eap_credentials_t));
    rsi_strcpy(credentials.username, user_name);
    rsi_strcpy(credentials.password, eap_password);

    print_status(rsi_wlan_connect((int8_t*)ssid, security, (int8_t*)&credentials));
}


void rsi_wlan_eap_method(sl_cli_command_arg_t* arguments)
{
    memset(g_rsi_eap_method, 0, EAP_METHOD_LEN);
    memset(g_rsi_eap_inner_method, 0, EAP_INNER_METHOD_LEN);
    memset(g_rsi_private_key_password, 0, EAP_PASSWORD_LEN);

    char* eap_method = sl_cli_get_argument_string(arguments, 0);
    char* eap_inner_method = sl_cli_get_argument_string(arguments, 1);
    char* private_key = sl_cli_get_argument_string(arguments, 2);

    rsi_strcpy(g_rsi_eap_method, eap_method);
    rsi_strcpy(g_rsi_eap_inner_method, eap_inner_method);
    rsi_strcpy(g_rsi_private_key_password, private_key);
    print_status(RSI_ERROR_NONE);

}

void rsi_wlan_set_multicast_filter(sl_cli_command_arg_t* arguments)
{

    rsi_req_multicast_filter_info_t filter_mac_address;

    filter_mac_address.cmd_type = sl_cli_get_argument_uint8(arguments, 0);
    char* mac_addr_str = sl_cli_get_argument_string(arguments, 1);

    for (int i=0; i<6; i++) {
        int val;
        sscanf(mac_addr_str + 3 * i, "%02X", &val);
        filter_mac_address.mac_address[i] = (uint8_t)val;
    }
    int32_t status = rsi_wlan_set(RSI_MULTICAST_FILTER, (uint8_t*)&filter_mac_address, (uint16_t)sizeof(filter_mac_address));
    print_status(status);
}


void rsi_wlan_scan_features_command(sl_cli_command_arg_t* arguments)
{
    rsi_rsp_scan_t* scan_results = malloc(SCAN_RESULT_SIZE);
    if (scan_results == NULL) {
        return;
    }

    char* ssid = sl_cli_get_argument_string(arguments, 0);
    uint8_t channel = sl_cli_get_argument_uint8(arguments, 1);
    g_rsi_scan_channel_bitmap_2_4 = sl_cli_get_argument_uint16(arguments, 2);
    g_rsi_scan_channel_bitmap_5_0 = sl_cli_get_argument_uint32(arguments, 3);
    g_rsi_scan_add_feature = sl_cli_get_argument_uint8(arguments, 4);

    int32_t status = rsi_wlan_scan((int8_t*)ssid, channel, scan_results, SCAN_RESULT_SIZE);

    if (status == 0) {
        printf("%d scan results:\n", scan_results->scan_count[0]);
        for (int a = 0; a < scan_results->scan_count[0]; ++a) {
            printf("%s,%d,%d,%02x:%02x:%02x:%02x:%02x:%02x,%d,-%u\n",
                scan_results->scan_info[a].ssid,
                scan_results->scan_info[a].security_mode,
                scan_results->scan_info[a].network_type,
                scan_results->scan_info[a].bssid[0],
                scan_results->scan_info[a].bssid[1],
                scan_results->scan_info[a].bssid[2],
                scan_results->scan_info[a].bssid[3],
                scan_results->scan_info[a].bssid[4],
                scan_results->scan_info[a].bssid[5],
                scan_results->scan_info[a].rf_channel,
                scan_results->scan_info[a].rssi_val);
        }
    }

    print_status(status);
    free(scan_results);
}

void rsi_set_region_command(sl_cli_command_arg_t* arguments)
{
    g_rsi_set_region = sl_cli_get_argument_uint8(arguments, 0);
    g_rsi_region_code = sl_cli_get_argument_uint8(arguments, 1);
    g_rsi_module_type = sl_cli_get_argument_uint16(arguments, 2);

    print_status(RSI_ERROR_NONE);
}

void rsi_set_region_ap_command(sl_cli_command_arg_t* arguments)
{
	memset(g_region_code, 0, 4);
	g_region_config = sl_cli_get_argument_uint8(arguments, 0);
	char* region_code = sl_cli_get_argument_string(arguments, 1);
	rsi_strcpy(g_region_code, region_code);

	print_status(RSI_ERROR_NONE);
}

void rsi_set_default_region_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    g_rsi_set_region = 1;
    g_rsi_region_code = 1;
    g_rsi_module_type = 1;

    print_status(RSI_ERROR_NONE);
}

void rsi_set_rejoin_command(sl_cli_command_arg_t* arguments)
{
    g_rsi_rejoin_max_retry = sl_cli_get_argument_uint32(arguments, 0);
    g_rsi_rejoin_scan_interval = sl_cli_get_argument_uint32(arguments, 1);
    g_rsi_rejoin_beacon_missed_count = sl_cli_get_argument_uint32(arguments, 2);
    g_rsi_rejoin_first_time_retry = sl_cli_get_argument_uint32(arguments, 3);

    print_status(RSI_ERROR_NONE);
}

void rsi_set_ht_caps_params(sl_cli_command_arg_t* arguments)
{
    g_rsi_ht_caps_bitmap = sl_cli_get_argument_uint16(arguments, 0);
    print_status(RSI_ERROR_NONE);
}

void rsi_set_default_rejoin_command()
{
    g_rsi_rejoin_max_retry = 20;
    g_rsi_rejoin_scan_interval = 6;
    g_rsi_rejoin_beacon_missed_count = 40;
    g_rsi_rejoin_first_time_retry = 0;

    print_status(RSI_ERROR_NONE);
}

void rsi_set_rtc(sl_cli_command_arg_t* arguments)
{
    module_rtc_time_t timer;
    memset(&timer, '\0', sizeof(timer));
    uint32_t time_sec = sl_cli_get_argument_uint32(arguments, 0);
    uint32_t time_min = sl_cli_get_argument_uint32(arguments, 1);
    uint32_t time_hour = sl_cli_get_argument_uint32(arguments, 2);
    uint32_t time_month_day = sl_cli_get_argument_uint32(arguments, 3);
    uint32_t time_month = sl_cli_get_argument_uint32(arguments, 4);
    uint32_t time_year = sl_cli_get_argument_uint32(arguments, 5);
    uint32_t time_week_day = sl_cli_get_argument_uint32(arguments, 6);

    rsi_uint32_to_4bytes(timer.tm_sec, time_sec);
    rsi_uint32_to_4bytes(timer.tm_min, time_min);
    rsi_uint32_to_4bytes(timer.tm_hour, time_hour);
    rsi_uint32_to_4bytes(timer.tm_mday, time_month_day);
    rsi_uint32_to_4bytes(timer.tm_mon, time_month);
    rsi_uint32_to_4bytes(timer.tm_year, time_year);
    rsi_uint32_to_4bytes(timer.tm_wday, time_week_day);

    print_status(rsi_set_rtc_timer(&timer));
}

void rsi_get_rtc()
{
    module_rtc_time_t timer;
    memset(&timer, '\0', sizeof(timer));

    int32_t status = rsi_get_rtc_timer(&timer);
    printf("seconds:%lu\n", rsi_bytes4R_to_uint32(timer.tm_sec));
    printf("minutes:%lu\n", rsi_bytes4R_to_uint32(timer.tm_min));
    printf("hours:%lu\n", rsi_bytes4R_to_uint32(timer.tm_hour));
    printf("month_day:%lu\n", rsi_bytes4R_to_uint32(timer.tm_mday));
    printf("month:%lu\n", rsi_bytes4R_to_uint32(timer.tm_mon));
    printf("year:%lu\n", rsi_bytes4R_to_uint32(timer.tm_year));
    printf("day:%lu\n", rsi_bytes4R_to_uint32(timer.tm_wday));

    print_status(status);
}

void rsi_select_ssl_cipher(sl_cli_command_arg_t* arguments)
{
    g_rsi_ssl_ciphers = sl_cli_get_argument_uint32(arguments, 0);
    print_status(RSI_ERROR_NONE);
}

void rsi_set_default_ssl_cipher()
{
    g_rsi_ssl_ciphers = (SSL_DEFAULT_CIPHERS | BIT_TLS_RSA_WITH_AES_256_CBC_SHA256 | BIT_TLS_RSA_WITH_AES_128_CBC_SHA256 \
        | BIT_TLS_RSA_WITH_AES_256_CBC_SHA | BIT_TLS_RSA_WITH_AES_128_CBC_SHA | BIT_TLS_RSA_WITH_AES_128_CCM_8 \
        | BIT_TLS_RSA_WITH_AES_256_CCM_8);
    print_status(RSI_ERROR_NONE);
}


void rsi_set_bgscan_params(sl_cli_command_arg_t* arguments)
{
    g_rsi_bg_scan_enable = sl_cli_get_argument_uint32(arguments, 0);
    g_rsi_instant_bg = sl_cli_get_argument_uint32(arguments, 1);
    g_rsi_bg_scan_threshold = sl_cli_get_argument_uint32(arguments, 2);
    g_rsi_rssi_tolerance_threshold = sl_cli_get_argument_uint32(arguments, 3);
    g_rsi_bg_scan_periodicity = sl_cli_get_argument_uint32(arguments, 4);
    g_rsi_active_scan_duration = sl_cli_get_argument_uint32(arguments, 5);
    g_rsi_passive_scan_duration = sl_cli_get_argument_uint32(arguments, 6);
    g_rsi_multiprobe = sl_cli_get_argument_uint32(arguments, 7);

    print_status(RSI_ERROR_NONE);
}

void rsi_set_default_bgscan_params()
{
    g_rsi_bg_scan_enable = 0;
    g_rsi_instant_bg = 0;
    g_rsi_bg_scan_threshold = 63;
    g_rsi_rssi_tolerance_threshold = 4;
    g_rsi_bg_scan_periodicity = 2;
    g_rsi_active_scan_duration = 50;
    g_rsi_passive_scan_duration = 50;
    g_rsi_multiprobe = 0;

    print_status(RSI_ERROR_NONE);
}

void rsi_set_roaming_params(sl_cli_command_arg_t* arguments)
{
    g_rsi_roaming_threshold = sl_cli_get_argument_uint32(arguments, 0);
    g_rsi_roaming_hysterisis = sl_cli_get_argument_uint32(arguments, 1);

    print_status(RSI_ERROR_NONE);
}

void rsi_set_default_roaming_params()
{
    g_rsi_roaming_threshold = 67;
    g_rsi_roaming_hysterisis = 4;

    print_status(RSI_ERROR_NONE);
}


void rsi_upgrade_firmware_http(sl_cli_command_arg_t* arguments)
{
    uint8_t flags = sl_cli_get_argument_uint8(arguments, 0);
    char* server_ip = sl_cli_get_argument_string(arguments, 1);
    uint16_t server_port = sl_cli_get_argument_uint16(arguments, 2);
    char* http_url = sl_cli_get_argument_string(arguments, 3);
    char* http_host_name = sl_cli_get_argument_string(arguments, 4);
    char* http_extended_header = sl_cli_get_argument_string(arguments, 5);
    char* username = sl_cli_get_argument_string(arguments, 6);
    char* password = sl_cli_get_argument_string(arguments, 7);

    print_status(rsi_http_fw_update((uint8_t)flags, (uint8_t*)server_ip,
        (uint16_t)server_port,
        (uint8_t*)http_url,
        (uint8_t*)http_host_name,
        (uint8_t*)http_extended_header,
        (uint8_t*)username,
        (uint8_t*)password,
        http_otaf_response_handler));
}

void rsi_get_http_otaf_status()
{
    print_status(otaf_status);
    otaf_status = 0xAAAA;
}

void rsi_set_wlan_timeout(sl_cli_command_arg_t* arguments)
{
	g_rsi_timeout_bit_map = sl_cli_get_argument_uint32(arguments, 0);
	g_rsi_timeout_value = sl_cli_get_argument_uint32(arguments, 1);

	print_status(RSI_ERROR_NONE);
}

void rsi_set_default_wlan_timeout()
{
	g_rsi_timeout_bit_map = 4;
	g_rsi_timeout_value = 10;

	print_status(RSI_ERROR_NONE);
}

void rsi_set_config_save(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
	int32_t status = rsi_wlan_set(RSI_CFG_SAVE, (uint8_t *)NULL , NULL);
	print_status(status);
}

void rsi_set_auto_config(sl_cli_command_arg_t* arguments)
{
	uint8_t config_enable = sl_cli_get_argument_uint8(arguments, 0);
	uint32_t profile_type = sl_cli_get_argument_uint32(arguments, 1);
	int32_t status =  rsi_wlan_enable_auto_config(config_enable, profile_type);
	print_status(status);
}

void rsi_cfg_get_command()
{
	int32_t status = 0;
	uint32_t opermode = 0;
	uint8_t opermode_type = 0;
	rsi_cfgGetFrameRcv_t* cfg_get = malloc(sizeof(rsi_cfgGetFrameRcv_t));
	if (cfg_get == NULL) {
		printf("unable to allocate memory for cfg get results\n");
		return;
	}
	memset(cfg_get, '\0', sizeof(rsi_cfgGetFrameRcv_t));
	status = rsi_wlan_get(RSI_CFG_GET, (uint8_t *)cfg_get, sizeof(rsi_cfgGetFrameRcv_t));
	if(status !=0)
	{
		print_status(status);
	}
	else
	{
		opermode = rsi_bytes4R_to_uint32(cfg_get->opermode);
		opermode_type = (0x0000FFFF & opermode);
		if((opermode_type == 0) || (opermode_type == 2))
		{
			printf("cfg_enable:%d-opermode:%d-feature_bit_map:%d-tcp_ip_feature_bit_map:%d-custom_feature_bit_map:%d-band:%d-join_ssid:%s-csec_mode:%d-psk:%s\-scan_ssid:%s-scan_cnum:%d-dhcp_enable:%d-ip:%d.%d.%d.%d-sn_mask:%d.%d.%d.%d-dgw:%d.%d.%d.%d\
            -tcp_stack_used:%d-bgscan_magic_code:%d-bgscan_enable:%d-bgscan_threshold:%d-rssi_tolerance_threshold:%d\
            -bgscan_periodicity:%d-active_scan_duration:%d-passive_scan_duration:%d-multi_probe:%d-chan_bitmap_magic_code:%d\
            -scan_chan_bitmap_stored_2_4_GHz:%d-scan_chan_bitmap_stored_5_GHz:%d-roam_magic_code:%d-roam_enable:%d-roam_threshold:%d-roam_hysteresis:%d\
            -rejoin_magic_code:%d-rsi_max_try:%d-rsi_scan_interval:%d-rsi_beacon_missed_count:%d-rsi_first_time_retry_enable:%d-module_mac:%x.%x.%x.%x.%x.%x\
            -powermode_magic_code:%d-powermode:%d-ulp_mode:%d-listen_interval:%d-listen_interval_dtim:%d-fast_psp_enable:%d-monitor_interval:%d\
            -timeout_value:%d-timeout_bitmap:%d\-region_request_from_host:%d\-rsi_region_code_from_host:%d\-region_code:%d-eap_method:%s-inner_method:%s\
            -user_identity:%s-passwd:%s\
            \n",cfg_get->cfg_enable,\
			rsi_bytes4R_to_uint32(cfg_get->opermode),\
            rsi_bytes4R_to_uint32(cfg_get->feature_bit_map),\
            rsi_bytes4R_to_uint32(cfg_get->tcp_ip_feature_bit_map),\
            rsi_bytes4R_to_uint32(cfg_get->custom_feature_bit_map),\
            cfg_get->band,\
            cfg_get->join_ssid,\
            cfg_get->csec_mode,\
            cfg_get->psk,\
            cfg_get->scan_ssid,\
            cfg_get->scan_cnum,\
            cfg_get->dhcp_enable,\
            cfg_get->ip[0],cfg_get->ip[1],cfg_get->ip[2],cfg_get->ip[3],\
            cfg_get->sn_mask[0],cfg_get->sn_mask[1],cfg_get->sn_mask[2],cfg_get->sn_mask[3],\
            cfg_get->dgw[0],cfg_get->dgw[1],cfg_get->dgw[2],cfg_get->dgw[3],\
            cfg_get->tcp_stack_used,\
            rsi_bytes2R_to_uint16(cfg_get->bgscan_magic_code),\
            rsi_bytes2R_to_uint16(cfg_get->bgscan_enable),\
            rsi_bytes2R_to_uint16(cfg_get->bgscan_threshold),\
            rsi_bytes2R_to_uint16(cfg_get->rssi_tolerance_threshold),\
            rsi_bytes2R_to_uint16(cfg_get->bgscan_periodicity),\
            rsi_bytes2R_to_uint16(cfg_get->active_scan_duration),\
            rsi_bytes2R_to_uint16(cfg_get->passive_scan_duration),\
            cfg_get->multi_probe,\
            rsi_bytes2R_to_uint16(cfg_get->chan_bitmap_magic_code),\
            rsi_bytes4R_to_uint32(cfg_get->scan_chan_bitmap_stored_2_4_GHz),\
            rsi_bytes4R_to_uint32(cfg_get->scan_chan_bitmap_stored_5_GHz),\
            rsi_bytes2R_to_uint16(cfg_get->roam_magic_code),\
            rsi_bytes4R_to_uint32(cfg_get->roam_params_stored.roamParamsFrameSnd.roam_enable),\
            rsi_bytes4R_to_uint32(cfg_get->roam_params_stored.roamParamsFrameSnd.roam_threshold),\
            rsi_bytes4R_to_uint32(cfg_get->roam_params_stored.roamParamsFrameSnd.roam_hysteresis),\
			rsi_bytes2R_to_uint16(cfg_get->rejoin_magic_code),\
			rsi_bytes4R_to_uint32(cfg_get->rejoin_param_stored.rsi_max_try),\
			rsi_bytes4R_to_uint32(cfg_get->rejoin_param_stored.rsi_scan_interval),\
			rsi_bytes4R_to_uint32(cfg_get->rejoin_param_stored.rsi_beacon_missed_count),\
			rsi_bytes4R_to_uint32(cfg_get->rejoin_param_stored.rsi_first_time_retry_enable),\
			cfg_get->module_mac[0],cfg_get->module_mac[1],cfg_get->module_mac[2],cfg_get->module_mac[3],cfg_get->module_mac[4],cfg_get->module_mac[5],\
			rsi_bytes2R_to_uint16(cfg_get->powermode_magic_code),\
            cfg_get->powermode,\
            cfg_get->ulp_mode,\
            rsi_bytes4R_to_uint32(cfg_get->listen_interval),\
            cfg_get->listen_interval_dtim,\
            cfg_get->fast_psp_enable,\
            rsi_bytes2R_to_uint16(cfg_get->monitor_interval),\
            rsi_bytes2R_to_uint16(cfg_get->timeout_value),\
            rsi_bytes4R_to_uint32(cfg_get->timeout_bitmap),\
            cfg_get->region_request_from_host,\
            cfg_get->rsi_region_code_from_host,\
            cfg_get->region_code,\
            cfg_get->eap_method,\
            cfg_get->inner_method,\
            cfg_get->user_identity,\
            cfg_get->passwd);
		}
		else if(opermode_type == 6)
		{
			printf("cfg_enable:%d-opermode:%d-feature_bit_map:%d-tcp_ip_feature_bit_map:%d-custom_feature_bit_map:%d-band:%d-operating_channel:%d\
            -ssid_postfix:%s-psk_key:%s-pmk:%s-channel_no:%d-ssid:%s-security_type:%d-encryp_mode:%d-psk:%s-beacon_interval:%d-dtim_period:%d\
            -ap_keepalive_type:%d-ap_keepalive_period:%d-max_sta_support:%d-module_mac:%x.%x.%x.%x.%x.%x-tcp_stack_used:%d\
            \n",cfg_get->cfg_enable,\
            rsi_bytes4R_to_uint32(cfg_get->opermode),\
            rsi_bytes4R_to_uint32(cfg_get->feature_bit_map),\
            rsi_bytes4R_to_uint32(cfg_get->tcp_ip_feature_bit_map),\
            rsi_bytes4R_to_uint32(cfg_get->custom_feature_bit_map),\
            cfg_get->band,\
            rsi_bytes2R_to_uint16(cfg_get->operating_channel),\
            cfg_get->ssid_postfix,\
            cfg_get->psk_key,\
            cfg_get->pmk,\
            rsi_bytes2R_to_uint16(cfg_get->apconfig.channel_no),\
            cfg_get->apconfig.ssid,\
            cfg_get->apconfig.security_type,\
            cfg_get->apconfig.encryp_mode,\
            cfg_get->apconfig.psk,\
            rsi_bytes2R_to_uint16(cfg_get->apconfig.beacon_interval),\
            rsi_bytes2R_to_uint16(cfg_get->apconfig.dtim_period),\
            cfg_get->apconfig.ap_keepalive_type,\
            cfg_get->apconfig.ap_keepalive_period,\
            rsi_bytes2R_to_uint16(cfg_get->apconfig.max_sta_support),\
            cfg_get->module_mac[0],cfg_get->module_mac[1],cfg_get->module_mac[2],cfg_get->module_mac[3],cfg_get->module_mac[4],cfg_get->module_mac[5],\
            cfg_get->tcp_stack_used);
		}
		print_status(status);
	}
	free(cfg_get);
}
void rsi_wlan_filter_broadcast_command(sl_cli_command_arg_t* arguments)
{
   uint16_t beacon_drop_threshold = sl_cli_get_argument_uint16(arguments, 0);
   uint8_t filter_bcast_in_tim  = sl_cli_get_argument_uint8(arguments, 1);
   uint8_t filter_bcast_tim_till_next_cmd = sl_cli_get_argument_uint8(arguments, 2);
   int32_t status = rsi_wlan_filter_broadcast(beacon_drop_threshold ,filter_bcast_in_tim ,filter_bcast_tim_till_next_cmd);
   print_status(status);

}
void rsi_wireless_antenna_command(sl_cli_command_arg_t* arguments)
{
   uint8_t type = sl_cli_get_argument_uint8(arguments, 0);
   uint8_t gain_2g  = sl_cli_get_argument_uint8(arguments, 1);
   uint8_t gain_5g = sl_cli_get_argument_uint8(arguments, 2);
   int32_t status = rsi_wireless_antenna(type, gain_2g, gain_5g);
   print_status(status);
}
/*******************************************************************************
*
*                       IMPLEMENTATION: Private functions
*
*******************************************************************************/
static void scan_response_handler(uint16_t status, const uint8_t* buffer, const uint16_t length)
{
    (void)buffer;
    (void)length;
    printf("got scan result: 0x%X\n", status);
}

static void join_response_handler(uint16_t status, const uint8_t* buffer, const uint16_t length)
{
    (void)buffer;
    (void)length;
    printf("got join result: 0x%X\n", status);
}

static void wlan_wfd_discovery_notify_handler(uint16_t status, uint8_t* buffer, const uint32_t length)
{
    (void)buffer;
    (void)length;
    printf("got wfd discovery status: 0x%X\n", status);
}
static void wlan_wfd_connection_request_notify_handler(uint16_t status, uint8_t* buffer, const uint32_t length)
{
    (void)buffer;
    (void)length;
    printf("got wfd connection status: 0x%X\n", status);
}

static void wlan_ping_response_handler(uint16_t status, const uint8_t* buffer, const uint16_t length)
{
    (void)buffer;
    (void)length;
    printf("got ping response result: 0x%X\n", status);
}

static void http_otaf_response_handler(uint16_t status, const uint8_t* buffer)
{
    printf("\r\nhttp_otaf_status:0x%X\r\n", status);
    if (status == RSI_SUCCESS) {
        http_recv_status = RSI_HTTP_OTAF_UPGRADE_SUCCESS;
    }
    else {
        http_recv_status = RSI_HTTP_OTAF_UPGRADE_FAILED;
    }
    otaf_status = status;
}

