/*******************************************************************************
* INCLUDE FILES:
*******************************************************************************/
#include "sl_cli.h"
#include "sl_cli_types.h"
#include "sl_cli_arguments.h"
#include "rsi_driver.h"
#include "string.h"
#include "rsi_ant.h"


/*******************************************************************************
*
*                       IMPLEMENTATION: Public functions
*
*******************************************************************************/

void rsi_ant_send_command(sl_cli_command_arg_t* arguments){

rsi_ant_stack_cmd_t start_cmd;

start_cmd.data[0] = sl_cli_get_argument_uint8(arguments, 0);
start_cmd.data[1] = sl_cli_get_argument_uint8(arguments, 1);
start_cmd.data[2] = sl_cli_get_argument_uint8(arguments, 2);
start_cmd.data[3] = sl_cli_get_argument_uint8(arguments, 3);
start_cmd.data[4] = sl_cli_get_argument_uint8(arguments, 4);
start_cmd.data[5] = sl_cli_get_argument_uint8(arguments, 5);
uint8_t arg2 = sl_cli_get_argument_uint8(arguments, 6);

print_status(rsi_ant_send_cmd(&start_cmd.data[0], arg2));

}
