#include <stdint.h>
#include "rsi_wlan_apis.h"
#include "rsi_error.h"
#include "rsi_wlan.h"
#include "sl_cli.h"
#include "sl_cli_arguments.h"
#include "utilities.h"




void start_iperf_command(sl_cli_command_arg_t *arguments)
{
  int32_t status = 0;
  char* ip_string     = sl_cli_get_argument_string(arguments, 0);
  uint16_t port       = sl_cli_get_argument_uint16(arguments, 1);
  uint32_t ip_address = str_to_ipv4(ip_string);
  (void)port;
  (void)ip_address;

  print_status(status);
}
