/***************************************************************************//**
   Copyright 2021
   Silicon Labs, Inc.
   All rights reserved.

   @file     ftp.c

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

#define FILE_READ_SIZE 1200
#define DIRECTORY_READ_SIZE 512
uint8_t file_data[FILE_READ_SIZE] = {0};
//! This call back is called when file read opertion is in progress
void rsi_file_read_cb(uint16_t status, uint8_t *data, uint16_t length, uint8_t end_of_file)
{
  memset(file_data,'\0',FILE_READ_SIZE);
  memcpy(file_data,data,length);
//  int8_t *file_ptr;
  printf("FTP_RECEIVE_DATA-status:%d,data:%s,length:%d,eof:%d\n",status,file_data,length,end_of_file);

//  file_ptr = file_data_read;
//  if (status != RSI_SUCCESS) {
//    //! Error in file read operation
//  }
//  //! Indicates end of file
//  if (end_of_file == 1) {
//    wait_for_complete = 1;
//    file_data_offset  = 0;
//  }
//  //! Copy data from file to global array
//  if ((data != NULL) && length && (file_data_offset < FILE_CONTENT_LENGTH)) {
//    memcpy((file_ptr + file_data_offset), data, length);
//
//    file_data_offset += length;
//
//    file_read_data_length += length;
//  }
}

uint8_t dir_data[DIRECTORY_READ_SIZE] = {0};
//! This call back is called when directory list opertion is in progress
void rsi_directory_list_cb(uint16_t status, uint8_t *data, uint16_t length, uint8_t end_of_list)
{
    memset(dir_data,'\0',DIRECTORY_READ_SIZE);
    memcpy(dir_data,data,length);
    printf("FTP_RECEIVE_DIRECTORY-status:%d,data:%s,length:%d,eof:%d\n",status,dir_data,length,end_of_list);

}

void rsi_ftp_connect_command(sl_cli_command_arg_t* arguments)
{
    uint32_t server_ip_ftp = 0;
	uint16_t flags = sl_cli_get_argument_uint16(arguments, 0);
	char* server_ip = sl_cli_get_argument_string(arguments, 1);
	char* user_name = sl_cli_get_argument_string(arguments, 2);
	char* password = sl_cli_get_argument_string(arguments, 3);
	uint32_t server_port = sl_cli_get_argument_uint32(arguments, 4);
	server_ip_ftp = ip_to_reverse_hex(server_ip);
	print_status(rsi_ftp_connect(flags,&server_ip_ftp,user_name,password,server_port));
}

void rsi_set_ftp_mode(sl_cli_command_arg_t* arguments)
{
	uint8_t mode = sl_cli_get_argument_uint8(arguments, 0);
	print_status(rsi_ftp_mode_set(mode));
}

void rsi_query_directory_list(sl_cli_command_arg_t* arguments)
{
	char* directory_path = sl_cli_get_argument_string(arguments, 0);
	print_status(rsi_ftp_directory_list_async(directory_path,rsi_directory_list_cb));
}

void rsi_ftp_create_dir(sl_cli_command_arg_t* arguments)
{
	char* directory_name = sl_cli_get_argument_string(arguments, 0);
	print_status(rsi_ftp_directory_create(directory_name));
}

void rsi_ftp_set_dir(sl_cli_command_arg_t* arguments)
{
	char* directory_name = sl_cli_get_argument_string(arguments, 0);
	print_status(rsi_ftp_directory_set(directory_name));
}

void rsi_ftp_file_write_command(sl_cli_command_arg_t* arguments)
{
	char* file_name = sl_cli_get_argument_string(arguments, 0);
	print_status(rsi_ftp_file_write(file_name));
}

void rsi_ftp_file_write_content_command(sl_cli_command_arg_t* arguments)
{
	uint16_t flags = sl_cli_get_argument_uint16(arguments, 0);
	char* file_content = sl_cli_get_argument_string(arguments, 1);
	uint16_t content_length = sl_cli_get_argument_uint16(arguments, 2);
	uint8_t eof = sl_cli_get_argument_uint8(arguments, 3);

	print_status(rsi_ftp_file_write_content(flags,file_content,content_length,eof));
}

void rsi_ftp_file_rename_command(sl_cli_command_arg_t* arguments)
{
	char* old_filename = sl_cli_get_argument_string(arguments, 0);
	char* new_filename = sl_cli_get_argument_string(arguments, 1);
	print_status(rsi_ftp_file_rename(old_filename,new_filename));
}

void rsi_ftp_file_read(sl_cli_command_arg_t* arguments)
{
	char* file_name = sl_cli_get_argument_string(arguments, 0);
	print_status(rsi_ftp_file_read_aysnc(file_name,rsi_file_read_cb));
}

void rsi_ftp_file_delete_command(sl_cli_command_arg_t* arguments)
{
	char* file_name = sl_cli_get_argument_string(arguments, 0);
	print_status(rsi_ftp_file_delete(file_name));
}

void rsi_ftp_directory_delete_command(sl_cli_command_arg_t* arguments)
{
	char* directory_name = sl_cli_get_argument_string(arguments, 0);
	print_status(rsi_ftp_directory_delete(directory_name));
}

void rsi_ftp_disconnect_command()
{
	print_status(rsi_ftp_disconnect());
}