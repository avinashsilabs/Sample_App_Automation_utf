#include "rsi_data_types.h"
#include "sl_cli.h"
#include "sl_cli_types.h"
#include "sl_cli_arguments.h"

#define RSI_WLAN_RSP_WIRELESS_FWUP_OK   0x59
#define RSI_WLAN_RSP_WIRELESS_FWUP_DONE 0x5A

#define RSI_SUCCESS 0

#if RSI_PRINT_LOGS
#define LOG_PRINT(...) printf(__VA_ARGS__)
#else
#define LOG_PRINT(...)
#endif

#define RSI_PRINT_EVENTS 1

#if RSI_PRINT_EVENTS
#define LOG_EVENT(...) printf(__VA_ARGS__)
#else
#define LOG_EVENT(...)
#endif

typedef enum rsi_nwk_callback_id_e {
  RSI_NWK_ERROR_CB            = 0,
  RSI_WLAN_NWK_URL_REQ_CB     = 1,
  RSI_WLAN_NWK_JSON_UPDATE_CB = 2,
  RSI_WLAN_NWK_FW_UPGRADE_CB  = 3,
  RSI_WLAN_NWK_JSON_EVENT_CB  = 4
} rsi_nwk_callback_id_t;

//! wireless firmware upgrade handler declaration
static void rsi_wireless_fw_upgrade_handler(uint8_t type, uint32_t status);
int32_t rsi_accept_wireless_fwup_request_internal();

static uint8_t auto_accept = 0;

//Reference from Host_MCU\examples\_internal\Wireless_Examples\wlan\wireless_firmware_upgradation\rsi_wfup_app.c
void rsi_http_server_cbs_init_command(sl_cli_command_arg_t *arguments)
{
	auto_accept = sl_cli_get_argument_uint8(arguments, 0);
	print_status(rsi_wlan_nwk_register_wireless_fw_upgrade_cb(RSI_WLAN_NWK_FW_UPGRADE_CB, rsi_wireless_fw_upgrade_handler));
}

void rsi_accept_wireless_fwup_request_command(sl_cli_command_arg_t *arguments)
{
	(void)arguments;
	print_status(rsi_accept_wireless_fwup_request_internal());
}

int32_t rsi_accept_wireless_fwup_request_internal(){
	LOG_EVENT("\nSending rsi_req_wireless_fwup\n");
	int32_t status = rsi_req_wireless_fwup();
	print_status(status);
	if (status != RSI_SUCCESS) {
		LOG_PRINT("\r\nWireless Firmware Upgrade Request Failed, Error Code : 0x%lX\r\n", status);
	}else{
		LOG_PRINT("\nFirmware upgrade process started.\r\n");
	}
	return status;
}

static void rsi_wireless_fw_upgrade_handler(uint8_t type, uint32_t status)
{
	if (status != RSI_SUCCESS) {
		LOG_PRINT("\nRSI_FWUP_RSP_FAILED\n");
		LOG_PRINT("\r\nWireless Firmware Upgrade Failed, Error Code : 0x%lX\r\n", status);
		return;
	}
	switch (type) {
		case RSI_WLAN_RSP_WIRELESS_FWUP_OK:
			LOG_EVENT("\nRSI_FWUP_RSP_OK\n");
			if (auto_accept == 1){
				rsi_accept_wireless_fwup_request_internal();
			}
			break;
		case RSI_WLAN_RSP_WIRELESS_FWUP_DONE:
			LOG_EVENT("\nRSI_FWUP_RSP_DONE\n");
			LOG_PRINT("\nFirmware Upgrade Success\n");
		break;
	}
}
