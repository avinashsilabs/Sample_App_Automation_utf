/***************************************************************************/ /**
 * @file
 * @brief Top level application functions
 *******************************************************************************
 * # License
 * <b>Copyright 2020 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/

/*******************************************************************************
* INCLUDE FILES:
*******************************************************************************/
#include "sl_cli_command.h"
#include "sl_cli_arguments.h"
#include "sl_cli.h"
#include "rsi_bootup_config.h"
#include "sl_cmsis_os2_common.h"
#include <stdbool.h>
#include "rsi_hal.h"

/*******************************************************************************
* CONSTANTS:
*******************************************************************************/
// <o APPLICATION_TASK_PRIORITY> Task priority <0-55>
// <i> Default: 17
// <i> Priority of the application task using the CMSIS order (55 is highest priority)
#define APPLICATION_TASK_PRIORITY (15)

// <o APPLICATION_TASK_STACK_SIZE> Task stack size
// <i> Default: 400
// <i> Stack size for the application task in words.
#define APPLICATION_TASK_STACK_SIZE (1024)

/*******************************************************************************
* TYPES:
*******************************************************************************/

/*******************************************************************************
* GLOBAL VARIABLES:
*******************************************************************************/

/*******************************************************************************
* MACROS:
*******************************************************************************/
/* This Macro section should contain Macro functions used only in this module */
/******************************************************************************/

/*******************************************************************************
* LOCAL VARIABLES:
*******************************************************************************/
/* All following variables declared here must be declared 'static' */
static uint8_t app_stack[APPLICATION_TASK_STACK_SIZE];
static uint8_t thread_cb[osThreadCbSize];

/*******************************************************************************
* FUNCTION PROTOTYPES (for local functions):
*******************************************************************************/
/* All following functions declared here must be declared 'static' */
static void app_thread(void *arg);

/*******************************************************************************
*
*                       IMPLEMENTATION: Public functions
*
*******************************************************************************/
void app_init(void)
{
  osThreadAttr_t attr;

  attr.name       = "app";
  attr.priority   = APPLICATION_TASK_PRIORITY;
  attr.stack_mem  = app_stack;
  attr.stack_size = APPLICATION_TASK_STACK_SIZE;
  attr.cb_mem     = thread_cb;
  attr.cb_size    = osThreadCbSize;
  attr.attr_bits  = 0u;
  attr.tz_module  = 0u;

  osThreadNew(&app_thread, NULL, &attr);
}

/*******************************************************************************
*
*                       IMPLEMENTATION: Private functions
*
*******************************************************************************/
static void app_thread(void *arg)
{
    (void)arg;
  // Reset the 9116 on boot up to get to a known state
  rsi_bl_module_power_cycle();
  // Configure the power save GPIO
  rsi_hal_config_gpio(RSI_HAL_SLEEP_CONFIRM_PIN, 0, 0);
  rsi_hal_config_gpio(RSI_HAL_WAKEUP_INDICATION_PIN, 0, 0);
  printf("Welcome to the Wi-Fi CLI\r\n\r\n");
  
  while (true) {
    osDelay(100000);
  }
}
