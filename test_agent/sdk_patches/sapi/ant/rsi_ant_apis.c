/*******************************************************************************
* @file  rsi_ant_apis.c
* @brief 
*******************************************************************************
* # License
* <b>Copyright 2021 Silicon Laboratories Inc. www.silabs.com</b>
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
/**
 * @file     rsi_ant_apis.c
 * @version  0.1
 * @date     03 Sep 2015
 *
 *
 *
 *  @brief : This file contains ANT API's which needs to be called from application
 *
 *  @section Description  This file contains ANT API's called from application
 *
 *
 */
#ifdef RSI_PROP_PROTOCOL_ENABLE
#include "rsi_driver.h"
#include "rsi_ble.h"
#include "rsi_ant.h"
#include "rsi_ble_config.h"
#include "rsi_utils.h"

/*==============================================*/
/**
 * @fn         rsi_ant_send_cmd
 * @brief      initiate the ant cmd to the stack
 * @return     int32_t
 *             0  =  success
 *             !0 = failure
 * @section description
 * This function is used to start the ant commands to controller.
 */
int32_t rsi_ant_send_cmd(void *ant_cmd, void *ant_cmd_resp)
{
  return rsi_ant_driver_send_cmd(RSI_PROP_PROTOCOL_CMD, ant_cmd, ant_cmd_resp);
}

/*==============================================*/
/**
 * @fn         rsi_ant_send_cmd_per
 * @brief      initiate the ant per cmd to the stack
 * @return     int32_t
 *             0  =  success
 *             !0 = failure
 * @section description
 * This function is used to start the ant per commands to controller.
 */
int32_t rsi_ant_send_cmd_per(void *ant_cmd, void *ant_cmd_resp)
{
  return rsi_ant_driver_send_cmd(RSI_PROP_PROTOCOL_CMD_PER, ant_cmd, ant_cmd_resp);
}

#endif
