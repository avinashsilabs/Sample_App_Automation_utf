/***************************************************************************//**
   Copyright 2021
   Silicon Labs, Inc.
   All rights reserved.

   @file     http_commands.c

*******************************************************************************/


/*******************************************************************************
* INCLUDE FILES:
*******************************************************************************/
#include "utilities.h"
#include "rsi_wlan_apis.h"
#include "rsi_common_apis.h"
#include "rsi_error.h"
#include "rsi_wlan.h"
#include "sl_cli.h"
#include "sl_cli_arguments.h"
#include <string.h>
#include "rsi_wlan_config.h"
#include "rsi_data_types.h"
#include "rsi_http_client.h"
#include "rsi_nwk.h"
#include "rsi_os.h"

/*******************************************************************************
* CONSTANTS:
*******************************************************************************/
#define RSI_MQTT_YIELD_TASK_STACK_SIZE (384)
#define RSI_MQTT_YIELD_TASK_PRIORITY (5)

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
#define RSI_PRINT_LOGS 1
#if RSI_PRINT_LOGS
#undef LOG_PRINT
#define LOG_PRINT(...) printf(__VA_ARGS__)
#else
#define LOG_PRINT(...)
#endif

#define RSI_PRINT_EVENTS 1
#if RSI_PRINT_EVENTS
#undef LOG_EVENT
#define LOG_EVENT(...) printf(__VA_ARGS__)
#else
#define LOG_EVENT(...)
#endif

/*******************************************************************************
* LOCAL VARIABLES:
*******************************************************************************/
/* All following variables declared here must be declared 'static' */
static volatile bool s_httpReceiveComplete;
static int32_t s_httpReceiveStatus;
static bool s_moreDataPending;

/*******************************************************************************
* FUNCTION PROTOTYPES (for local functions):
*******************************************************************************/
/* All following functions declared here must be declared 'static' */
static void rsi_http_reset_handler(void);
static int32_t rsi_http_response_status(void);
static void rsi_http_response_handler(uint16_t status, const uint8_t* buffer, const uint16_t length, const uint32_t moredata);

/*******************************************************************************
*
*                       IMPLEMENTATION: Public functions
*
*******************************************************************************/
//! http put response notify call back handler
void rsi_http_client_put_response_handler(uint16_t status,
                                          const uint8_t type,
                                          const uint8_t *buffer,
                                          uint16_t length,
                                          const uint8_t end_of_put_pkt)
{
    if (status == RSI_SUCCESS)
    {
        char* b64data = base64_encode(buffer, length);
        if (b64data != NULL) {
            if (!s_moreDataPending) {
                printf("\r\nSAPI+RSI_HTTP_READ_DATA %s ", b64data);
            }
            else {
                printf("%s ", b64data);
            }
            free(b64data);
        }
        else {
            s_httpReceiveComplete = true;
            s_httpReceiveStatus = RSI_ERROR_PKT_ALLOCATION_FAILURE;
            return;
        }

        if (end_of_put_pkt == 0)
        {
            s_moreDataPending = true;
        }
        else {
            s_httpReceiveComplete = true;
            s_httpReceiveStatus = RSI_SUCCESS;
        }
    }
    else {
        s_httpReceiveComplete = true;
        s_httpReceiveStatus = status;
    }
}


void rsi_http_client_get_async_command(sl_cli_command_arg_t* arguments) {
    uint8_t flags = sl_cli_get_argument_uint8(arguments, 0);
    uint16_t port = sl_cli_get_argument_uint16(arguments, 1);
    char* hostname = sl_cli_get_argument_string(arguments, 2);
    char* ip_address = sl_cli_get_argument_string(arguments, 3);
    char* url = sl_cli_get_argument_string(arguments, 4);
    char* username = sl_cli_get_argument_string(arguments, 5);
    char* password = sl_cli_get_argument_string(arguments, 6);
    char* ext_header = sl_cli_get_argument_string(arguments, 7);

    //! resetting the variables
    rsi_http_reset_handler();
    //! send http get request for the given url
    uint16_t status = rsi_http_client_get_async((uint8_t)flags,
        (uint8_t*)ip_address,
        (uint16_t)port,
        (uint8_t*)url,
        (uint8_t*)hostname,
        (uint8_t*)(strlen(ext_header) ? ext_header : NULL),
        (uint8_t*)(strlen(username) ? username : NULL),
        (uint8_t*)(strlen(password) ? password : NULL),
        rsi_http_response_handler);
    if (status != RSI_SUCCESS) {
        print_status(status);
        return;
    }

    //! wait for the get success response
    status = rsi_http_response_status();
    print_status(status);
    rsi_http_reset_handler();
}

void rsi_http_client_post_async_command(sl_cli_command_arg_t* arguments) {
    uint8_t flags = sl_cli_get_argument_uint8(arguments, 0);
    uint16_t port = sl_cli_get_argument_uint16(arguments, 1);
    char* hostname = sl_cli_get_argument_string(arguments, 2);
    char* ip_address = sl_cli_get_argument_string(arguments, 3);
    char* url = sl_cli_get_argument_string(arguments, 4);
    char* username = sl_cli_get_argument_string(arguments, 5);
    char* password = sl_cli_get_argument_string(arguments, 6);
    char* ext_header = sl_cli_get_argument_string(arguments, 7);
    char* post_data = sl_cli_get_argument_string(arguments, 8);
   // uint32_t post_data_length = sl_cli_get_argument_string(arguments, 9);


    //! resetting the variables
    rsi_http_reset_handler();
    //! send http get request for the given url
    uint16_t status = rsi_http_client_post_async((uint8_t)flags,
        (uint8_t*)ip_address,
        (uint16_t)port,
        (uint8_t*)url,
        (uint8_t*)hostname,
        (uint8_t*)(strlen(ext_header) ? ext_header : NULL),
        (uint8_t*)(strlen(username) ? username : NULL),
        (uint8_t*)(strlen(password) ? password : NULL),
		(uint8_t*)(post_data),
		(uint32_t) (strlen(post_data)),
        rsi_http_response_handler);
    if (status != RSI_SUCCESS) {
        print_status(status);
        return;
    }

    //! wait for the get success response
    status = rsi_http_response_status();
    print_status(status);
    rsi_http_reset_handler();
}

void rsi_http_client_put_start_command(sl_cli_command_arg_t* arguments) {
    uint8_t flags = sl_cli_get_argument_uint8(arguments, 0);
    uint16_t port = sl_cli_get_argument_uint16(arguments, 1);
    char* hostname = sl_cli_get_argument_string(arguments, 2);
    char* ip_address = sl_cli_get_argument_string(arguments, 3);
    char* url = sl_cli_get_argument_string(arguments, 4);
    char* username = sl_cli_get_argument_string(arguments, 5);
    char* password = sl_cli_get_argument_string(arguments, 6);
    char* ext_header = sl_cli_get_argument_string(arguments, 7);
    uint32_t size_of_file = sl_cli_get_argument_uint32(arguments, 8);

    uint16_t status = rsi_http_client_put_start((uint8_t)flags,
        (uint8_t*)ip_address,
        (uint16_t)port,
        (uint8_t*)url,
        (uint8_t*)hostname,
        (uint8_t*)(strlen(ext_header) ? ext_header : NULL),
        (uint8_t*)(strlen(username) ? username : NULL),
        (uint8_t*)(strlen(password) ? password : NULL),
		(uint32_t) (size_of_file),
        (rsi_http_client_put_response_handler));

        print_status(status);
}

void rsi_http_client_put_pkt_command(sl_cli_command_arg_t* arguments) {
    char* file_content = sl_cli_get_argument_string(arguments, 0);
    uint16_t chunk_length = sl_cli_get_argument_uint16(arguments, 1);

    //! send http put pkt data
    uint16_t status = rsi_http_client_put_pkt((uint8_t *)file_content,
        (uint16_t)chunk_length);

    print_status(status);
}

/*******************************************************************************
*
*                       IMPLEMENTATION: Private functions
*
*******************************************************************************/
static void rsi_http_reset_handler(void)
{
    s_moreDataPending = false;
    s_httpReceiveComplete = false;
    s_httpReceiveStatus = 0;
}

static int32_t rsi_http_response_status(void)
{
    // wait for s_httpReceiveComplete to be set
    do {
        rsi_os_task_delay(10);
    } while (!s_httpReceiveComplete);

    if (s_httpReceiveStatus != RSI_SUCCESS) {
        return rsi_wlan_get_nwk_status();
    }
    else {
        return RSI_SUCCESS;
    }
}

static void rsi_http_response_handler(uint16_t status, const uint8_t* buffer, const uint16_t length, const uint32_t moredata)
{

    if (status == RSI_SUCCESS)
    {
        char* b64data = base64_encode(buffer, length);
        if (b64data != NULL) {
            if (!s_moreDataPending) {
                printf("\r\nSAPI+RSI_HTTP_READ_DATA %s ", b64data);
            }
            else {
                printf("%s ", b64data);
            }
            free(b64data);
        }
        else {
            s_httpReceiveComplete = true;
            s_httpReceiveStatus = RSI_ERROR_PKT_ALLOCATION_FAILURE;
            return;
        }

        if (moredata == 0)
        {
            s_moreDataPending = true;
        }
        else {
            s_httpReceiveComplete = true;
            s_httpReceiveStatus = RSI_SUCCESS;
        }
    }
    else {
        s_httpReceiveComplete = true;
        s_httpReceiveStatus = status;
    }
}
