#include "sl_cli_types.h"
#include "rsi_common_apis.h"
#include <stdint.h>

void demo_connected_sleep_command(sl_cli_command_arg_t *arguments)
{
  // Validate correct starting condition
  // Must be associated to an AP, softap interface must be down
  //  if (!connected) printf("You must be connected to an AP");
  //  if (softap_started) printf("Must have softap off");
  //  if (settingA == 1) printf("Thats bad");

  int beacon_drop_threshold = sl_cli_get_argument_uint32(arguments, 0);

  //! Enable Broadcast data filter
  int32_t status = rsi_wlan_filter_broadcast(beacon_drop_threshold, 1, 1);
  if (status != RSI_SUCCESS) {
    LOG_PRINT("\r\nBroadcast Data Filtering Failed with Error Code : 0x%X\r\n", status);
  }
  LOG_PRINT("\r\nBroadcast Data Filtering Enabled\r\n");

  //! Apply power save profile with connected sleep
  status = rsi_wlan_power_save_profile(RSI_SLEEP_MODE_2, RSI_MAX_PSP);
  if (status != RSI_SUCCESS) {
    LOG_PRINT("\r\nPowersave Config Failed, Error Code : 0x%X\r\n", status);
  }
}
