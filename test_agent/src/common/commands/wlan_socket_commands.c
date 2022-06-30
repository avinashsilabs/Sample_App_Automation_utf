#include <stdint.h>
#include "rsi_socket.h"
#include "rsi_wlan_apis.h"
#include "rsi_driver.h"
#include "rsi_multicast.h"
#include "sl_cli.h"
#include "sl_cli_arguments.h"
#include "utilities.h"
#include <string.h>

#define RSI_SNTP_RSP_BUFFER_LENGTH 30
#define RSI_MAX_SOCKETS 10
//global variable used by socket_async_udp_recive
uint32_t num_bytes_async[RSI_MAX_SOCKETS] = {0};

//global variables used in set_fd_command function
rsi_fd_set read_fds;
rsi_fd_set write_fds;
rsi_fd_set except_fds;

//global variable used in async_socket_select function
uint8_t socket_select_response = 0;

extern int read_variable(uint32_t nvm_key, uint8_t* buffer, size_t* length);
extern uint8_t remote_terminate;

void rsi_socket_command(sl_cli_command_arg_t* arguments);
void rsi_bind_command(sl_cli_command_arg_t* arguments);
void rsi_connect_command(sl_cli_command_arg_t* arguments);
void rsi_listen_command(sl_cli_command_arg_t* arguments);
void rsi_accept_command(sl_cli_command_arg_t* arguments);
void rsi_recvfrom_command(sl_cli_command_arg_t* arguments);
void rsi_recv_command(sl_cli_command_arg_t* arguments);
void rsi_sendto_command(sl_cli_command_arg_t* arguments);
void rsi_send_command(sl_cli_command_arg_t* arguments);
void rsi_send_large_data_async_command(sl_cli_command_arg_t* arguments);
void rsi_select_command(sl_cli_command_arg_t* arguments);
void rsi_shutdown_command(sl_cli_command_arg_t* arguments);
void rsi_socket_async_command(sl_cli_command_arg_t* arguments);
void rsi_config_ipaddress_command(sl_cli_command_arg_t* arguments);
void rsi_check_state_command(sl_cli_command_arg_t* arguments);
//void rsi_socket_create_command(sl_cli_command_arg_t *arguments);
void rsi_get_application_socket_descriptor_command(sl_cli_command_arg_t* arguments);
void rsi_clear_sockets_command(sl_cli_command_arg_t* arguments);
void calculate_buffers_required_command(sl_cli_command_arg_t* arguments);
void calculate_length_to_send_command(sl_cli_command_arg_t* arguments);
void rsi_send_async_command(sl_cli_command_arg_t* arguments);
void rsi_sendto_async_command(sl_cli_command_arg_t* arguments);
void rsi_setsockopt_command(sl_cli_command_arg_t* arguments);
void rsi_get_app_socket_descriptor_command(sl_cli_command_arg_t* arguments);
void rsi_get_primary_socket_id_command(sl_cli_command_arg_t* arguments);
void rsi_fd_isset_command(sl_cli_command_arg_t* arguments);
void rsi_set_fd_command(sl_cli_command_arg_t* arguments);
void rsi_fd_clr_command(sl_cli_command_arg_t* arguments);
void rsi_recvfrom_iperf_command(sl_cli_command_arg_t* arguments);
void rsi_sendto_iperf_command(sl_cli_command_arg_t* arguments);
void socket_async_data_recive(uint32_t sock_no, uint8_t* buffer, uint32_t length);
void rsi_websocket_data_receive_handler(uint32_t sock_no, uint8_t *buffer, uint32_t length);

//! SNTP response handler
void rsi_sntp_client_create_response_handler(uint16_t status, const uint8_t cmd_type, const uint8_t *buffer);
static void measure_throughput(int32_t total_bytes, int32_t start_time, int32_t end_time, int32_t pkt_cnt, char* command);

static const sl_cli_command_info_t rsi_socket_command_info = SL_CLI_COMMAND(rsi_socket_command, "Create a socket", "family" SL_CLI_UNIT_SEPARATOR "type" SL_CLI_UNIT_SEPARATOR "protocol", { SL_CLI_ARG_INT32, SL_CLI_ARG_INT32, SL_CLI_ARG_INT32, SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_bind_command_info = SL_CLI_COMMAND(rsi_bind_command, "Bind socket to port", "socket" SL_CLI_UNIT_SEPARATOR "port" SL_CLI_UNIT_SEPARATOR "ip", { SL_CLI_ARG_INT32, SL_CLI_ARG_UINT16, SL_CLI_ARG_STRING, SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_connect_command_info = SL_CLI_COMMAND(rsi_connect_command, "Connect to a remote socket", "socket" SL_CLI_UNIT_SEPARATOR "ip" SL_CLI_UNIT_SEPARATOR "port", { SL_CLI_ARG_INT32, SL_CLI_ARG_STRING, SL_CLI_ARG_UINT16, SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_listen_command_info = SL_CLI_COMMAND(rsi_listen_command, "Listen", "socket" SL_CLI_UNIT_SEPARATOR "backlog", { SL_CLI_ARG_INT32, SL_CLI_ARG_INT32, SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_accept_command_info = SL_CLI_COMMAND(rsi_accept_command, "Accept", "socket", { SL_CLI_ARG_INT32, SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_recvfrom_command_info = SL_CLI_COMMAND(rsi_recvfrom_command, "Receive from", "socket" SL_CLI_UNIT_SEPARATOR "data_len", { SL_CLI_ARG_INT32, SL_CLI_ARG_INT32, SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_recv_command_info = SL_CLI_COMMAND(rsi_recv_command, "", "socket" SL_CLI_UNIT_SEPARATOR "data_len", { SL_CLI_ARG_INT32, SL_CLI_ARG_INT32, SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_sendto_command_info = SL_CLI_COMMAND(rsi_sendto_command, "send to remote server", "sockID" SL_CLI_UNIT_SEPARATOR "data_len" SL_CLI_UNIT_SEPARATOR "remote_ip_string" SL_CLI_UNIT_SEPARATOR "remote_port", { SL_CLI_ARG_INT32, SL_CLI_ARG_INT32, SL_CLI_ARG_STRING, SL_CLI_ARG_UINT16, SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_send_command_info = SL_CLI_COMMAND(rsi_send_command, "send", "sockID" SL_CLI_UNIT_SEPARATOR "data_len" SL_CLI_UNIT_SEPARATOR, { SL_CLI_ARG_INT32, SL_CLI_ARG_INT32, SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_send_large_data_async_command_info = SL_CLI_COMMAND(rsi_send_large_data_async_command, "", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_select_command_info = SL_CLI_COMMAND(rsi_select_command, "", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_shutdown_command_info = SL_CLI_COMMAND(rsi_shutdown_command, "close socket", "sockID", { SL_CLI_ARG_INT32, SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_socket_async_command_info = SL_CLI_COMMAND(rsi_socket_async_command, "", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_config_ipaddress_command_info = SL_CLI_COMMAND(rsi_config_ipaddress_command, "Configure the client IP", "[dhcp, static]", { SL_CLI_ARG_STRING, SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_check_state_command_info = SL_CLI_COMMAND(rsi_check_state_command, "", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_get_application_socket_descriptor_command_info = SL_CLI_COMMAND(rsi_get_application_socket_descriptor_command, "", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_clear_sockets_command_info = SL_CLI_COMMAND(rsi_clear_sockets_command, "", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t calculate_buffers_required_command_info = SL_CLI_COMMAND(calculate_buffers_required_command, "", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t calculate_length_to_send_command_info = SL_CLI_COMMAND(calculate_length_to_send_command, "", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_send_async_command_info = SL_CLI_COMMAND(rsi_send_async_command, "", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_sendto_async_command_info = SL_CLI_COMMAND(rsi_sendto_async_command, "", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_setsockopt_command_info = SL_CLI_COMMAND(rsi_setsockopt_command, "", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_get_app_socket_descriptor_command_info = SL_CLI_COMMAND(rsi_get_app_socket_descriptor_command, "", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_get_primary_socket_id_command_info = SL_CLI_COMMAND(rsi_get_primary_socket_id_command, "", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_fd_isset_command_info = SL_CLI_COMMAND(rsi_fd_isset_command, "", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_set_fd_command_info = SL_CLI_COMMAND(rsi_set_fd_command, "", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_fd_clr_command_info = SL_CLI_COMMAND(rsi_fd_clr_command, "", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_recvfrom_iperf_command_info = SL_CLI_COMMAND(rsi_recvfrom_iperf_command, "receive from iperf", "protocol_family" SL_CLI_UNIT_SEPARATOR "type" SL_CLI_UNIT_SEPARATOR "protocol" SL_CLI_UNIT_SEPARATOR "local_port" SL_CLI_UNIT_SEPARATOR "local_ip" SL_CLI_UNIT_SEPARATOR "data_len" SL_CLI_UNIT_SEPARATOR "ttl_sec" SL_CLI_UNIT_SEPARATOR "debug_output" SL_CLI_UNIT_SEPARATOR "is_async", { SL_CLI_ARG_UINT32, SL_CLI_ARG_UINT32, SL_CLI_ARG_UINT32, SL_CLI_ARG_UINT16, SL_CLI_ARG_STRING, SL_CLI_ARG_UINT32, SL_CLI_ARG_UINT16, SL_CLI_ARG_UINT16, SL_CLI_ARG_UINT16, SL_CLI_ARG_END, });
static const sl_cli_command_info_t rsi_sendto_iperf_command_info = SL_CLI_COMMAND(rsi_sendto_iperf_command, "send to iperf server", "protocol_family" SL_CLI_UNIT_SEPARATOR "type" SL_CLI_UNIT_SEPARATOR "protocol" SL_CLI_UNIT_SEPARATOR "local_port" SL_CLI_UNIT_SEPARATOR "local_ip" SL_CLI_UNIT_SEPARATOR "remote_ip" SL_CLI_UNIT_SEPARATOR "remote_port" SL_CLI_UNIT_SEPARATOR "data_len" SL_CLI_UNIT_SEPARATOR "ttl_sec" SL_CLI_UNIT_SEPARATOR "compute_throughput" SL_CLI_UNIT_SEPARATOR "debug_output" SL_CLI_UNIT_SEPARATOR "is_async", { SL_CLI_ARG_UINT32, SL_CLI_ARG_INT32, SL_CLI_ARG_UINT32, SL_CLI_ARG_UINT16, SL_CLI_ARG_STRING, SL_CLI_ARG_STRING, SL_CLI_ARG_UINT16, SL_CLI_ARG_INT32, SL_CLI_ARG_UINT16, SL_CLI_ARG_UINT16, SL_CLI_ARG_UINT16, SL_CLI_ARG_UINT16, SL_CLI_ARG_END, });

//static const sl_cli_command_info_t rsi_socket_create_command_info                     = SL_CLI_COMMAND( rsi_socket_create_command, "Create a socket?", "socket" SL_CLI_UNIT_SEPARATOR "type" SL_CLI_UNIT_SEPARATOR "backlog", { SL_CLI_ARG_INT32, SL_CLI_ARG_INT32, SL_CLI_ARG_INT32, SL_CLI_ARG_END, });


sl_cli_command_entry_t wlan_socket_command_table[] =
{
   { "rsi_socket",                            &rsi_socket_command_info,                            false },
   { "rsi_bind",                              &rsi_bind_command_info,                              false },
   { "rsi_connect",                           &rsi_connect_command_info,                           false },
   { "rsi_listen",                            &rsi_listen_command_info,                            false },
   { "rsi_accept",                            &rsi_accept_command_info,                            false },
   { "rsi_recvfrom",                          &rsi_recvfrom_command_info,                          false },
   { "rsi_recv",                              &rsi_recv_command_info,                              false },
   { "rsi_sendto",                            &rsi_sendto_command_info,                            false },
   { "rsi_send",                              &rsi_send_command_info,                              false },
   { "rsi_send_large_data_async",             &rsi_send_large_data_async_command_info,             false },
   { "rsi_select",                            &rsi_select_command_info,                            false },
   { "rsi_shutdown",                          &rsi_shutdown_command_info,                          false },
   { "rsi_socket_async",                      &rsi_socket_async_command_info,                      false },
   { "rsi_config_ipaddress",                  &rsi_config_ipaddress_command_info,                  false },
   { "rsi_check_state",                       &rsi_check_state_command_info,                       false },
   { "rsi_get_application_socket_descriptor", &rsi_get_application_socket_descriptor_command_info, false },
   { "rsi_clear_sockets",                     &rsi_clear_sockets_command_info,                     false },
   { "calculate_buffers_required",            &calculate_buffers_required_command_info,            false },
   { "calculate_length_to_send",              &calculate_length_to_send_command_info,              false },
   { "rsi_send_async",                        &rsi_send_async_command_info,                        false },
   { "rsi_sendto_async",                      &rsi_sendto_async_command_info,                      false },
   { "rsi_setsockopt",                        &rsi_setsockopt_command_info,                        false },
   { "rsi_get_app_socket_descriptor",         &rsi_get_app_socket_descriptor_command_info,         false },
   { "rsi_get_primary_socket_id",             &rsi_get_primary_socket_id_command_info,             false },
   { "rsi_fd_isset",                          &rsi_fd_isset_command_info,                          false },
   { "rsi_set_fd",                            &rsi_set_fd_command_info,                            false },
   { "rsi_fd_clr",                            &rsi_fd_clr_command_info,                            false },
   { "rsi_recvfrom_iperf",                    &rsi_recvfrom_iperf_command_info,                    false },
   { "rsi_sendto_iperf",                      &rsi_sendto_iperf_command_info,                      false }
};


rsi_rsp_ipv4_parmas_t current_ip;

void print_data(int8_t* send_buf, int data_len)
{
    int32_t i;
    for (i = 0; i < data_len; i++) {
        printf("%d", (int8_t)send_buf[i]);
    }
}

// generate random buffer
void set_random_bytes(int8_t* send_buf, int data_len) {
    int32_t i;
    for (i = 0;i < data_len;i++) {
        // we want only in bytes
        send_buf[i] = (int8_t)(rand() % 10);
    }
}

void rsi_socket_command(sl_cli_command_arg_t* arguments)
{
	int32_t protocol_family = sl_cli_get_argument_int32(arguments, 0);
	int32_t type = sl_cli_get_argument_int32(arguments, 1);
	int32_t protocol = sl_cli_get_argument_int32(arguments, 2);
	uint8_t socket_flag = sl_cli_get_argument_int32(arguments, 3);
	int32_t result = 0;

	if(socket_flag == 0)
	{
		result = rsi_socket(protocol_family, type, protocol);
	}
	else
	{
		result = rsi_socket_async(protocol_family, type, protocol, socket_async_data_recive);
	}

	if (result >= 0)
	{
		printf("\r\n socket #: %ld\n", result);
		print_status(RSI_ERROR_NONE);
	}
	else
	{
		print_status(result);
	}
}

void rsi_bind_command(sl_cli_command_arg_t* arguments)
{
    int32_t sock_id = sl_cli_get_argument_int32(arguments, 0);
    uint16_t local_port = sl_cli_get_argument_int16(arguments, 1);
    char* local_ip_string = sl_cli_get_argument_string(arguments, 2);

    uint32_t local_ip = str_to_ipv4(local_ip_string);

    struct rsi_sockaddr_in address = {
       .sin_family = AF_INET,
       .sin_port = local_port,
       .sin_addr = {
           .s_addr = local_ip
       },
    };
    print_status(rsi_bind(sock_id, (struct rsi_sockaddr*)&address, sizeof(address)));
}

void rsi_connect_command(sl_cli_command_arg_t* arguments)
{
    int32_t sock_id = sl_cli_get_argument_int32(arguments, 0);
    char* remote_ip_string = sl_cli_get_argument_string(arguments, 1);
    uint16_t remote_port = sl_cli_get_argument_uint16(arguments, 2);

    uint32_t remote_ip = str_to_ipv4(remote_ip_string);
    if (remote_ip == 0)
    {
        print_status(RSI_ERROR_INVALID_PARAM);
        return;
    }

    struct rsi_sockaddr_in remote_address = {
        .sin_family = AF_INET,
        .sin_port = remote_port,
        .sin_addr = {
            .s_addr = remote_ip
        },
    };
    uint32_t status = rsi_connect(sock_id, (struct rsi_sockaddr*)&remote_address, sizeof(remote_address));
    if (status != RSI_ERROR_NONE) {
        status = rsi_wlan_socket_get_status(sock_id);
    }
    print_status(status);
}

void rsi_listen_command(sl_cli_command_arg_t* arguments)
{
    int32_t sockID = sl_cli_get_argument_int32(arguments, 0);
    int32_t backlog = sl_cli_get_argument_int32(arguments, 1);
    print_status(rsi_listen(sockID, backlog));
}

void rsi_accept_command(sl_cli_command_arg_t* arguments)
{
    int32_t sockID = sl_cli_get_argument_int32(arguments, 0);
    struct rsi_sockaddr_in client_address = {0};
    int32_t address_length = sizeof(client_address);
    int32_t status = rsi_accept(sockID, (struct rsi_sockaddr*)&client_address, &address_length);
    if (status >=0 ) {
        printf("\r\n socket #: %ld\n", status);
        printf("\r\n Successfully accepted connection from 0x%x\n", (unsigned int)client_address.sin_addr.s_addr);
        print_status(RSI_ERROR_NONE);
    }
    else {
        printf("\r\n Failed to accept connection from 0x%x\n", (unsigned int)client_address.sin_addr.s_addr);
        print_status(status);
    }

}

void rsi_recvfrom_command(sl_cli_command_arg_t *arguments)
{
	int32_t flags = 0;
	int32_t sockID = sl_cli_get_argument_int32(arguments, 0);
	int32_t buffer_size = sl_cli_get_argument_int32(arguments, 1);

	if (buffer_size == 0) {
		buffer_size = 1024;
	}
	int8_t *buffer = malloc(buffer_size);
	if (buffer == NULL)
		return;

	struct rsi_sockaddr_in client_address;
	int32_t addr_size = sizeof(sockID);

	uint32_t status = rsi_recvfrom(sockID, buffer, buffer_size, flags, (struct rsi_sockaddr*)&client_address, &addr_size);
	if (status) {
		buffer[status] = '\0';
		printf("buffer_size:%ld\nbuffer:%s\n",status,buffer);
		print_status(RSI_ERROR_NONE);
	}
	else {
		print_status(status);
	}

	free(buffer);
}

void rsi_recv_command(sl_cli_command_arg_t *arguments)
{
	int32_t flags = 0;
	int32_t sockID = sl_cli_get_argument_int32(arguments, 0);
	int32_t buffer_size = sl_cli_get_argument_int32(arguments, 1);
	if (buffer_size == 0) {
		buffer_size = 1024;
	}
	int8_t *buffer = malloc(buffer_size);
	if (buffer == NULL)
		return;

	uint32_t status = rsi_recv(sockID, buffer, buffer_size, flags);
	if (status) {
		buffer[status] = '\0';
		printf("buffer_size:%ld\nbuffer:%s\n", status, buffer);
		print_status(RSI_ERROR_NONE);
	}
	else {
		print_status(status);
	}

	free(buffer);
}

void rsi_sendto_command(sl_cli_command_arg_t* arguments)
{

    int32_t sockID = sl_cli_get_argument_int32(arguments, 0);
    int32_t data_len = sl_cli_get_argument_int32(arguments, 1);
    char* remote_ip_string = sl_cli_get_argument_string(arguments, 2);
    uint16_t remote_port = sl_cli_get_argument_uint16(arguments, 3);

    // should we include any max size check? and throw error incase it is more
    if (data_len == 0) {
        data_len = 1024;
    }

    uint32_t server_ip = str_to_ipv4(remote_ip_string);
    if (server_ip == 0) {
        printf("%d", (int)RSI_ERROR_INVALID_PARAM);
        return;
    }

    int8_t* buffer = malloc(data_len);
    if (buffer == NULL) {
        printf("\r\n Unable to allocate memory for data_length: %ld", data_len);
        return;
    }
    // generate random buffer
    set_random_bytes(buffer, data_len);

    struct rsi_sockaddr_in server_address = { .sin_family = AF_INET, .sin_port = remote_port, .sin_addr = {.s_addr = server_ip }, };
    int32_t status = rsi_sendto(sockID, buffer, data_len, 0, (struct rsi_sockaddr*)&server_address, sizeof(server_address));

    if (status) {
        printf("\r\n Successfully sent data to : %s with status %ld \r\n", remote_ip_string, status);
        print_status(RSI_ERROR_NONE);
    }
    else {
        printf("\r\n Failed to send data to ip: %s with status %ld \r\n", remote_ip_string, status);
        print_status(status);
    }

    free(buffer);
}

void rsi_send_command(sl_cli_command_arg_t* arguments)
{
    int32_t sockID = sl_cli_get_argument_int32(arguments, 0);
    int32_t data_len = sl_cli_get_argument_int32(arguments, 1);

    int8_t* buffer = malloc(data_len);
    if (buffer == NULL) {
        printf("\r\n Unable to allocate memory for data_length: %ld", data_len);
        return;
    }

    // generate random buffer
    set_random_bytes(buffer, data_len);
    int32_t status = rsi_send(sockID, buffer, data_len, 0);
    if (status) {
        printf("\r\n Successfully sent data with status %ld \r\n", status);
        print_status(RSI_ERROR_NONE);
    }
    else {
        printf("\r\n Failed to send data to ip: %ld \r\n", status);
        print_status(status);
    }

    free(buffer);
}

void rsi_send_large_data_async_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
}

void rsi_select_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
}

void rsi_shutdown_command(sl_cli_command_arg_t* arguments)
{
    int32_t sockID = sl_cli_get_argument_int32(arguments, 0);
    int32_t result;
    if (sockID >= 0) {
        result = rsi_shutdown(sockID, 0);
        if (result >= 0) {
            printf("\r\n socket closed #: %ld \r\n", result);
            print_status(RSI_ERROR_NONE);
        }
        else {
            printf("\r\n unable to close socket, error #: %ld \r\n", result);
            print_status(result);
        }
    }
    else {
        printf("\r\n invalid socket Id from input #: %ld \r\n", sockID);
        print_status(RSI_ERROR_INVALID_PARAM);
    }
}


void rsi_socket_async_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
}


typedef struct {
    uint8_t ip_address[4];
    uint8_t netmask[4];
    uint8_t gateway[4];
} ipv4_address_setting_t;

void rsi_config_ipaddress_command(sl_cli_command_arg_t* arguments)
{
	ipv4_address_setting_t ip;
	uint8_t mode;
	uint32_t ip_address;
	uint32_t subnet_mask;
	uint32_t gateway;
	char* mode_string = sl_cli_get_argument_string(arguments, 0);
	char* ip_string = sl_cli_get_argument_string(arguments, 1);
	char* subnet_string = sl_cli_get_argument_string(arguments, 2);
	char* gateway_ip_string = sl_cli_get_argument_string(arguments, 3);
	uint8_t vap_id = sl_cli_get_argument_string(arguments, 4);

	printf("\r\n rsi_config_ipaddress_command invoked\r\n");

	if (strncmp(mode_string, "static", 6) == 0) {
		mode = RSI_STATIC;
		ip_address = str_to_ipv4(ip_string);
		subnet_mask = str_to_ipv4(subnet_string);
		gateway = str_to_ipv4(gateway_ip_string);
	}
	else if (strncmp(mode_string, "dhcp", 4) == 0) {
		mode = RSI_DHCP;
		memset(&ip, 0, sizeof(ip));
	}
	else {
		print_status(RSI_ERROR_INVALID_PARAM);
		return;
	}
	int32_t status = rsi_config_ipaddress(RSI_IP_VERSION_4, mode, (uint8_t *)&ip_address, (uint8_t *)&subnet_mask, (uint8_t *)&gateway, (uint8_t *)&current_ip, sizeof(current_ip), vap_id);
	if (status == RSI_ERROR_NONE) {
		printf("\r\n RSI_CONFIG_IP:IP:      %d.%d.%d.%d\n", current_ip.ipaddr[0], current_ip.ipaddr[1], current_ip.ipaddr[2], current_ip.ipaddr[3]);
		printf("\r\n RSI_CONFIG_IP:netmask: %d.%d.%d.%d\n", current_ip.netmask[0], current_ip.netmask[1], current_ip.netmask[2], current_ip.netmask[3]);
		printf("\r\n RSI_CONFIG_IP:gateway: %d.%d.%d.%d\n", current_ip.gateway[0], current_ip.gateway[1], current_ip.gateway[2], current_ip.gateway[3]);
        printf("\r\n RSI_CONFIG_IP:Success\n");
	}
	print_status(status);
}

void rsi_check_state_command(sl_cli_command_arg_t* arguments)
{
    int32_t type = sl_cli_get_argument_int32(arguments, 0);
    print_status(rsi_check_state(type));
}

//void rsi_socket_create_command(sl_cli_command_arg_t *arguments)
//{
//   int32_t socket  = sl_cli_get_argument_int32(arguments, 0);
//   int32_t type    = sl_cli_get_argument_int32(arguments, 1);
//   int32_t backlog = sl_cli_get_argument_int32(arguments, 2);
//
//   print_status( rsi_socket_create(socket, type, backlog) );
//}

void rsi_get_application_socket_descriptor_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
}

void rsi_clear_sockets_command(sl_cli_command_arg_t* arguments)
{
    int32_t sock_id = sl_cli_get_argument_int32(arguments, 0);
    rsi_clear_sockets(sock_id);
    print_status(RSI_ERROR_NONE);
}

void calculate_buffers_required_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
}

void calculate_length_to_send_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
}

void rsi_send_async_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
}

void rsi_sendto_async_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
}

void rsi_setsockopt_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
}

void rsi_get_app_socket_descriptor_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
}

void rsi_get_primary_socket_id_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
}

void rsi_fd_isset_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
}

void rsi_set_fd_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
}

void rsi_fd_clr_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
}

uint32_t received_length = 0;

// Call back for Socket Async
void socket_async_recive(uint32_t sock_no, uint8_t* buffer, uint32_t length)
{
    UNUSED_PARAMETER(sock_no);
    UNUSED_PARAMETER(buffer);
    printf("\r\n received %ld bytes ", length);
    received_length += length;
    printf("\r\n total bytes received so far are %ld bytes ", received_length);
}


/**
 * to be moved to utils
 */
int32_t checkStatus(int32_t status, char* msg, int32_t socketId, int8_t close_on_failure, int8_t debug)
{
    int32_t error_code;
    // <0, if fails  and 0 if success
    if (status < 0) {
        error_code = rsi_wlan_get_status();
        printf("\r\n Failed in %s operation with Error Code : 0x%lX, and status is %ld \r\n", msg, error_code, status);
        if (close_on_failure == 1) {
            rsi_shutdown(socketId, 0);
            printf("\r\n closed the socket with socked id: %ld", socketId);
        }
        return -1;
    }
    else {
        if (debug == 1)
            printf("\r\n operation: %s is successful with status %ld \r\n", msg, status);
    }
    return status;
}

void rsi_recvfrom_iperf_command(sl_cli_command_arg_t* arguments)
{
    int32_t protocol_family = sl_cli_get_argument_int32(arguments, 0);
    int32_t type = sl_cli_get_argument_int32(arguments, 1); /* scoket_type tcp is 1, udp 2 */
    int32_t protocol = sl_cli_get_argument_int32(arguments, 2);
    uint16_t local_port = sl_cli_get_argument_int16(arguments, 3);
    char* local_ip_string = sl_cli_get_argument_string(arguments, 4);
    int32_t data_len = sl_cli_get_argument_uint16(arguments, 5);
    uint16_t ttl_sec = sl_cli_get_argument_uint16(arguments, 6);
    uint16_t debug_output = sl_cli_get_argument_int16(arguments, 7);
    uint16_t is_async = sl_cli_get_argument_uint16(arguments, 8);
    UNUSED_PARAMETER(is_async);

    int32_t status;
    int32_t new_socket;
    int32_t recv_size = data_len;
    uint32_t local_ip = str_to_ipv4(local_ip_string);
    int32_t socketID = 0;
    int8_t receive_completed = 0;
    int32_t total_bytes_tx = 0;
    int32_t tt_start = 0;
    int32_t tt_end = 0;
    int32_t pkt_cnt = 0;
    int32_t client_address_length;

    if (debug_output == 1) {
        printf("\r\n socket_type is :%s", (type == 1 ? "TCP" : "UDP"));
        printf("\r\n protocol_family is :%ld", protocol_family);
        printf("\r\n protocol is :%ld", protocol);
        printf("\r\n local_ip is :%s", local_ip_string);
        printf("\r\n local_port is :%d", local_port);
        printf("\r\n data_len is :%ld", data_len);
        printf("\r\n ttl_sec is :%d", ttl_sec);
        printf("\r\n debug_output is :%d", debug_output);
    }

    printf("\r\n rsi_recvfrom_iperf_command invoked \r\n");
    switch (type) {
    case 2: {
        printf("\r\nUDP RX start\r\n");
        receive_completed = 0;
        // Create socket, need to extend this for async support in future
        socketID = checkStatus(rsi_socket(AF_INET, SOCK_DGRAM, 0), "rsi_socket", socketID, 0, debug_output);
        if (socketID == -1)
            return;

        struct rsi_sockaddr_in local_address = { .sin_family = AF_INET, .sin_port = local_port, .sin_addr = {.s_addr = local_ip }, };
        total_bytes_tx = 0, tt_start = 0, tt_end = 0, pkt_cnt = 0;

        // Bind socket
        status = rsi_bind(socketID, (struct rsi_sockaddr*)&local_address, sizeof(local_address));
        if (checkStatus(status, "rsi_bind", socketID, 1, 1) == -1)
            return;

        client_address_length = sizeof(local_address);
        tt_start = rsi_hal_gettickcount();

        uint8_t* recv_buffer = malloc(recv_size);
        if (recv_buffer == NULL) {
            checkStatus(-1, "malloc(recv_size)", socketID, 1, 1);
            return;
        }

        while (1) {
            recv_size = data_len;

            status = rsi_recvfrom(socketID, (int8_t*)recv_buffer, recv_size, 0, (struct rsi_sockaddr*)&local_address, &client_address_length);
            if (debug_output == 1)
                printf("number of bytes received from server are: %ld, 0x%lX (HEX) \r\n", status, status);
            if (status < 0) {
                receive_completed = 1;
            }

            tt_end = rsi_hal_gettickcount();
            total_bytes_tx = total_bytes_tx + status;
            pkt_cnt++;
            if (((tt_end - tt_start) / 1000 > ttl_sec) || receive_completed == 1)
                break;
        }
        measure_throughput(total_bytes_tx, tt_start, tt_end, pkt_cnt, "IPERF_RECV_FROM");

        //close socket
        checkStatus(rsi_shutdown(socketID, 0), "rsi_shutdown", socketID, 1, 1);
        free(recv_buffer);
        break;
    }
    case 1: {
        printf("\r\nTCP RX start\r\n");
        receive_completed = 0;
        struct rsi_sockaddr_in local_address;
        total_bytes_tx = 0, tt_start = 0, tt_end = 0, pkt_cnt = 0;

        // Set server structure
        memset(&local_address, 0, sizeof(local_address));

        // Set family type
        local_address.sin_family = AF_INET;

        // Set local port number
        local_address.sin_port = htons(local_port);

        // Create socket
        socketID = checkStatus(rsi_socket(protocol_family, type, protocol), "rsi_socket", socketID, 0, debug_output);

        if (socketID == -1)
            return;

        status = rsi_bind(socketID, (struct rsi_sockaddr*)&local_address, sizeof(local_address));
        if (checkStatus(status, "rsi_bind", socketID, 1, debug_output) == -1)
            return;

        // Socket listen
        status = rsi_listen(socketID, 1);
        if (checkStatus(status, "rsi_listen", socketID, 1, debug_output) == -1)
            return;

        struct rsi_sockaddr_in local_address1;
        int32_t addr_size = sizeof(local_address1);

        // Socket accept
        new_socket = rsi_accept(socketID, (struct rsi_sockaddr*)&local_address1, (rsi_socklen_t*)&addr_size);
        if (checkStatus(status, "rsi_accept", socketID, 1, debug_output) == -1)
            return;

        uint8_t* recv_buffer = malloc(recv_size);
        if (recv_buffer == NULL) {
            checkStatus(-1, "malloc(recv_size)", socketID, 1, 1);
            return;
        }

        tt_start = rsi_hal_gettickcount();
        while (1) {
            recv_size = data_len;
            // Receive data on socket
            status = rsi_recvfrom(new_socket, (int8_t*)recv_buffer, recv_size, 0, (struct rsi_sockaddr*)&local_address1, &addr_size);
            if (debug_output == 1)
                printf("number of bytes received from server are: %ld, 0x%lX (HEX) \r\n", status, status);
            if (status < 0) {
                receive_completed = 1;
            }
            total_bytes_tx = total_bytes_tx + status;
            tt_end = rsi_hal_gettickcount();
            pkt_cnt++;
            if (((tt_end - tt_start) / 1000 > ttl_sec) || receive_completed == 1)
                break;
        }
        measure_throughput(total_bytes_tx, tt_start, tt_end, pkt_cnt, "IPERF_RECV_FROM");
        //close socket
        if(!receive_completed)
        {
        checkStatus(rsi_shutdown(new_socket, 0), "rsi_shutdown", socketID, 1, 1);
        }
        checkStatus(rsi_shutdown(socketID, 0), "rsi_shutdown", socketID, 1, 1);
        free(recv_buffer);
        break;
    }
    }
}

void rsi_sendto_iperf_command(sl_cli_command_arg_t* arguments)
{
    int32_t protocol_family = sl_cli_get_argument_int32(arguments, 0);
    int32_t type = sl_cli_get_argument_int32(arguments, 1); /* scoket_type tcp is 1, udp 2 */
    int32_t protocol = sl_cli_get_argument_int32(arguments, 2);
    uint16_t local_port = sl_cli_get_argument_int16(arguments, 3);
    char* local_ip_string = sl_cli_get_argument_string(arguments, 4);
    char* remote_ip_string = sl_cli_get_argument_string(arguments, 5);
    uint16_t remote_port = sl_cli_get_argument_uint16(arguments, 6);
    int32_t data_len = sl_cli_get_argument_uint32(arguments, 7);
    uint16_t ttl_sec = sl_cli_get_argument_uint16(arguments, 8);
    uint16_t compute_throughput = sl_cli_get_argument_uint16(arguments, 9);
    uint16_t debug_output = sl_cli_get_argument_int16(arguments, 10);
    // yet to be implemented
    uint16_t is_async = sl_cli_get_argument_uint16(arguments, 11);
    UNUSED_PARAMETER(is_async);

    int8_t receive_completed = 0;
    int32_t status;
    int32_t socketID = 0;
    uint32_t local_ip = str_to_ipv4(local_ip_string);
    uint32_t remote_ip = str_to_ipv4(remote_ip_string);

    if (local_ip == 0 || remote_ip == 0) {
        print_status(RSI_ERROR_INVALID_PARAM);
        return;
    }

    if (data_len == 0) {
        if (type == 1)
            data_len = 1460;
        else
            data_len = 1470;
    }
    if (ttl_sec == 0) {
        ttl_sec = 30;
    }

    int32_t total_bytes_tx = 0, tt_start = 0, tt_end = 0, pkt_cnt = 0;

    if (debug_output == 1) {
        printf("\r\n scoket_type is :%s", (type == 1 ? "TCP" : "UDP"));
        printf("\r\n protocol_family is :%ld", protocol_family);
        printf("\r\n protocol is :%ld", protocol);
        printf("\r\n local_port is :%d", local_port);
        printf("\r\n local_ip is :%s", local_ip_string);
        printf("\r\n remote_port is :%d", remote_port);
        printf("\r\n remote_ip is :%s", remote_ip_string);
        printf("\r\n data_len is :%ld", data_len);
        printf("\r\n ttl_sec is :%d", ttl_sec);
        printf("\r\n compute_throughput flag is :%d", compute_throughput);
        printf("\r\n debug_output is :%d", debug_output);
    }

    int8_t* buffer = malloc(data_len);
    if (buffer == NULL) {
        printf("\r\n Unable to allocate the required buffer for the requested data size, %ld bytes", data_len);
        checkStatus(-1, "malloc(recv_size)", socketID, 0, 1);
        return;
    }

    // generate random buffer
    set_random_bytes(buffer, data_len);
    if (debug_output == 1) {
        printf("device is sending below data to server\n");
        print_data(buffer, data_len);
    }


    printf("\r\n rsi_sendto_iperf_command invoked \r\n");
    switch (type) {
    case 2: {
        printf("\r\nUDP_TX TEST\r\n");
        receive_completed = 0;
        // Create socket
        socketID = checkStatus(rsi_socket(protocol_family, type, protocol), "rsi_socket", socketID, 0, debug_output);
        if (socketID == -1)
        {
            free(buffer);
            return;
        }

        struct rsi_sockaddr_in remote_address = { .sin_family = AF_INET, .sin_port = remote_port, .sin_addr = {.s_addr = remote_ip }, };

        total_bytes_tx = 0, tt_start = 0, tt_end = 0, pkt_cnt = 0;
        tt_start = rsi_hal_gettickcount();

        while (1) {

            // Send data on socket
            status = rsi_sendto(socketID, buffer, data_len, 0, (struct rsi_sockaddr*)&remote_address, sizeof(remote_address));
            if (checkStatus(status, "rsi_sendto", socketID, 1, debug_output) == -1) {
                receive_completed = 1;
            }

            total_bytes_tx = total_bytes_tx + status;
            tt_end = rsi_hal_gettickcount();
            pkt_cnt++;
            if (((tt_end - tt_start) / 1000 > ttl_sec) || receive_completed == 1)
                break;
        }

        if (compute_throughput == 1) {
            measure_throughput(total_bytes_tx, tt_start, tt_end, pkt_cnt, "IPERF_SEND_TO:");
        }

        //close socket
        checkStatus(rsi_shutdown(socketID, 0), "rsi_shutdown", socketID, 1, 1);

        break;
    }
    case 1: {
        struct rsi_sockaddr_in local_address = { .sin_family = AF_INET, .sin_port = local_port, .sin_addr = {.s_addr = local_ip }, };
        total_bytes_tx = 0, tt_start = 0, tt_end = 0, pkt_cnt = 0;
        receive_completed = 0;
        printf("\r\nTCP_TX TEST\r\n");

        // Create socket
        socketID = checkStatus(rsi_socket(protocol_family, type, protocol), "rsi_socket", socketID, 0, debug_output);
        if (socketID == -1)
        {
            free(buffer);
            return;
        }

        // Bind socket
        status = rsi_bind(socketID, (struct rsi_sockaddr*)&local_address, sizeof(local_address));
        if (checkStatus(status, "rsi_bind", socketID, 1, 1) == -1)
        {
            free(buffer);
            return;
        }

        // connect
        struct rsi_sockaddr_in remote_address = { .sin_family = AF_INET, .sin_port = remote_port, .sin_addr = {.s_addr = remote_ip }, };
        status = rsi_connect(socketID, (struct rsi_sockaddr*)&remote_address, sizeof(remote_address));
        if (checkStatus(status, "rsi_connect", socketID, 1, 1) == -1)
        {
            free(buffer);
            return;
        }

        // take the current time
        tt_start = rsi_hal_gettickcount();
        while (1) {
         if(remote_terminate)
        {
        break;
        }
            // Send data on socket
            status = rsi_send(socketID, buffer, data_len, 0);
            if (checkStatus(status, "rsi_send", socketID, 1, debug_output) == -1) {
                receive_completed = 1;
            }
            total_bytes_tx = total_bytes_tx + status;
            tt_end = rsi_hal_gettickcount();
            pkt_cnt++;
            if (((tt_end - tt_start) / 1000 > ttl_sec) || receive_completed == 1)
                break;

        }
        if(!remote_terminate)
        {
        //close socket
        checkStatus(rsi_shutdown(socketID, 0), "rsi_shutdown", socketID, 1, 1);
        }
        if (compute_throughput == 1) {
            measure_throughput(total_bytes_tx, tt_start, tt_end, pkt_cnt, "IPERF_SEND_TO:");
        }
        break;
    }
    }
remote_terminate=0;
    free(buffer);
}

static void measure_throughput(int32_t total_bytes, int32_t start_time, int32_t end_time, int32_t pkt_cnt, char* command)
{
    double total_sec = ((end_time - start_time) / 1000);
    if (total_sec > 0) {
        double through_put = ((double)(total_bytes * 8)) / total_sec;
        printf("\r\n %sthrough_put : %f ",command,  (double)through_put);
        printf("\r\n %sTest start time in ms :%ld",command,  start_time);
        printf("\r\n %sTest end time in ms :%ld",command,  end_time);
        printf("\r\n %sNumber of interactions with server are : %ld",command,  pkt_cnt);
        printf("\r\n %sTime taken in sec: %lu \r\n",command,  (uint32_t)((end_time - start_time) / 1000));
        //printf("\r\n Throughput in kbps (KiloBitsPerSec) is : %.5f \r\n", (float)through_put);
        printf("\r\n %sThroughput in kbps (KiloBits/Second) is : %d \r\n",command,  (int)through_put / 1000);
        printf("\r\n %sTotal bytes  : %ld \r\n", command, total_bytes);
    }
    else {
        printf("\r\n %sSeems test didn't run successfully, please try again !!");
        printf("\r\n %sTest start time in ms :%ld",command,  start_time);
        printf("\r\n %sTest end time in ms :%ld",command,  end_time);
        printf("\r\n %sNumber of interactions with server are : %ld",command,  pkt_cnt);
        printf("\r\n %sTime taken in sec: %lu \r\n",command,  (uint32_t)((end_time - start_time) / 1000));
        printf("\r\n %sTotal bytes  : %ld \r\n",command,  command, total_bytes);
    }
}

void rsi_multicast_join_command(sl_cli_command_arg_t* arguments)
{
    int8_t flags = sl_cli_get_argument_int8(arguments, 0);
    char* multicast_ip_string = sl_cli_get_argument_string(arguments, 1);
    uint32_t multicast_ip = str_to_ipv4(multicast_ip_string);
    print_status(rsi_multicast_join(flags, (int8_t*)&multicast_ip));
}

void rsi_multicast_leave_command(sl_cli_command_arg_t* arguments)
{
    int8_t flags = sl_cli_get_argument_int8(arguments, 0);
    char* multicast_ip_string = sl_cli_get_argument_string(arguments, 1);
    uint32_t multicast_ip = str_to_ipv4(multicast_ip_string);
    print_status(rsi_multicast_leave(flags, (int8_t*)&multicast_ip));
}

void socket_async_data_recive(uint32_t sock_no, uint8_t* buffer, uint32_t length)
{
	UNUSED_PARAMETER(buffer);
	num_bytes_async[sock_no] += length;
}


void rsi_socket_async_udp_command(sl_cli_command_arg_t* arguments)
{

    int32_t protocol_family = sl_cli_get_argument_int32(arguments, 0);
    int32_t type = sl_cli_get_argument_int32(arguments, 1);
    int32_t protocol = sl_cli_get_argument_int32(arguments, 2);

    int result = rsi_socket_async(protocol_family, type, protocol, socket_async_data_recive);
    if (result >= 0)
    {
        printf("socket #: %d\n", result);
    }
    else
    {
        print_status(result);
    }

}

void rsi_async_data_receive(sl_cli_command_arg_t* arguments)
{
	int32_t sockID = sl_cli_get_argument_int32(arguments, 0);
	printf("\r\n Total bytes received #: %lu \r\n", num_bytes_async[sockID]);
	num_bytes_async[sockID] = 0;
}


void rsi_send_data_command(sl_cli_command_arg_t* arguments)
{

	int32_t sockID = sl_cli_get_argument_int32(arguments, 0);
	int32_t data_len = sl_cli_get_argument_int32(arguments, 1);
	char* data = sl_cli_get_argument_string(arguments, 2);

	int32_t status = rsi_send(sockID, data, data_len, 0);
	if (status) {
		printf("\r\n bytes_sent:%ld \r\n", status);
		print_status(RSI_ERROR_NONE);
	}
	else {
		print_status(status);
	}
}

void rsi_set_socket_option(sl_cli_command_arg_t* arguments)
{
	int32_t sockID = sl_cli_get_argument_int32(arguments, 0);
	int16_t sock_option1 = sl_cli_get_argument_int16(arguments, 1);
	int16_t sock_option2 = sl_cli_get_argument_int16(arguments, 2);
	uint8_t ssl_bitmap = sl_cli_get_argument_int8(arguments, 3);

	int32_t status = rsi_setsockopt(sockID, sock_option1, sock_option2, &ssl_bitmap, sizeof(ssl_bitmap));
	print_status(status);
}



void rsi_send_data_config_pkts(sl_cli_command_arg_t* arguments)
{
	int32_t socketID = sl_cli_get_argument_uint32(arguments, 0);
	int32_t data_len = sl_cli_get_argument_uint32(arguments, 1);
	int32_t no_of_pkts = sl_cli_get_argument_uint32(arguments, 2);
	int32_t ttl_sec = sl_cli_get_argument_uint32(arguments, 3);
	int32_t status = 0;
    uint32_t count = 0;
    int32_t tt_start = 0, tt_end = 0;
    uint32_t sent_bytes = 0;

    if (data_len == 0) {
    	data_len = 1460;
    }

    int8_t* buffer = malloc(data_len);
    if (buffer == NULL) {
    	printf("\r\n Unable to allocate the required buffer for the requested data size, %ld bytes", data_len);
    	checkStatus(-1, "malloc(recv_size)", socketID, 0, 1);
    	return;
    }

    // generate random buffer
    set_random_bytes(buffer, data_len);
    tt_start = rsi_hal_gettickcount();
    for(count = 0; count < (uint32_t)no_of_pkts ; count++)
    {
        if(((tt_end - tt_start) / 1000) > ttl_sec)
        {
        break;
        }
    	status = rsi_send(socketID, buffer, data_len, 0);
    	if(status < 0)
    	{
    	    status = rsi_wlan_get_status();
    		print_status(status);
    		free(buffer);
    		return;
    	}
    	sent_bytes += status;
    	tt_end = rsi_hal_gettickcount();
    }

    if(status)
    {
        printf("Bytes sent:%u\n",sent_bytes);
    	print_status(0);
    }

    free(buffer);
}

void rsi_dns_enable(sl_cli_command_arg_t* arguments)
{
	rsi_rsp_dns_query_t dns_query_resp;
	uint32_t primary_dns_address;
	uint32_t secondary_dns_address;
	uint32_t primary_dns_address_ptr;
	uint32_t secondary_dns_address_ptr;
	uint8_t ip_version = sl_cli_get_argument_uint8(arguments, 0);
	uint8_t* domain_name = sl_cli_get_argument_string(arguments, 1);
	char* primary_dns_address_str = sl_cli_get_argument_string(arguments, 2);
	char* secondary_dns_address_str = sl_cli_get_argument_string(arguments, 3);
	uint16_t length = 0;
	length = sizeof(dns_query_resp);
	uint32_t status = 0;
	uint8_t count = 0, ii = 0;
	if(!(strncmp(primary_dns_address_str, "NULL", 4)))
	{
		primary_dns_address_ptr = (uint32_t)NULL;
	}
	else
	{
		primary_dns_address = str_to_ipv4(primary_dns_address_str);
		primary_dns_address_ptr = &primary_dns_address;
	}
	if(!(strncmp(secondary_dns_address_str, "NULL", 4)))
	{
		secondary_dns_address_ptr = (uint32_t)NULL;
	}
	else
	{
		secondary_dns_address = str_to_ipv4(secondary_dns_address_str);
		secondary_dns_address_ptr = (uint32_t *)&secondary_dns_address;
	}
	status = rsi_dns_req((int8_t*)ip_version, domain_name, primary_dns_address_ptr, secondary_dns_address_ptr, &dns_query_resp, length);

	print_status(status);
	if(status == 0)
	{
		printf("\r\n No of addresses resolved %d\n", dns_query_resp.ip_count[0]);
		for (count = 0; count < (dns_query_resp.ip_count[0]); count++)
		{
			printf("ip address %d:", (count+1));
			for(ii = 0 ; ii < 4; ii++)
			{
				printf("%d", dns_query_resp.ip_address[count].ipv4_address[ii]);
				if(ii < 3)
				{
					printf(".");
				}
			}
			printf("\n");
		}
	}
	print_status(status);
}

void rsi_sntp_create(sl_cli_command_arg_t* arguments)
{
	uint32_t server_ip = 0;
	int8_t flags = sl_cli_get_argument_int8(arguments, 0);
	char* server_ip_str = sl_cli_get_argument_string(arguments, 1);
	int8_t sntp_method = sl_cli_get_argument_int8(arguments, 0);
	int16_t sntp_timeout = sl_cli_get_argument_int16(arguments, 0);

	server_ip = str_to_ipv4(server_ip_str);
	int32_t status = rsi_sntp_client_create_async((uint8_t)flags,
	                                        (uint8_t*)&server_ip,
	                                        (uint8_t)sntp_method,
	                                        (uint16_t)sntp_timeout,
	                                        rsi_sntp_client_create_response_handler);
	print_status(status);
}

void rsi_get_sntp_time(sl_cli_command_arg_t* arguments)
{
	(void)arguments;
	uint8_t sntp_time[RSI_SNTP_RSP_BUFFER_LENGTH];
	int32_t status = rsi_sntp_client_gettime((uint16_t)sizeof(sntp_time), (uint8_t *)sntp_time);
	if(!status)
	{
		printf("\nsntp time->%d;%s\n", sntp_time[0], &sntp_time[1]);
	}
	print_status(status);
}

void rsi_get_sntp_timedate(sl_cli_command_arg_t* arguments)
{
	(void)arguments;
	uint8_t sntp_date_time[RSI_SNTP_RSP_BUFFER_LENGTH];
	int32_t status = rsi_sntp_client_gettime_date((uint16_t)sizeof(sntp_date_time), (uint8_t *)sntp_date_time);
	if(!status)
	{
		printf("\nsntp date_time->%d;%s\n", sntp_date_time[0], &sntp_date_time[1]);
	}
	print_status(status);
}

void rsi_get_sntp_server_info(sl_cli_command_arg_t* arguments)
{
	(void)arguments;
	rsi_sntp_server_info_rsp_t sntp_server_info_rsp;
	uint8_t ii = 0;
	int32_t status = rsi_sntp_client_server_info((uint16_t)sizeof(sntp_server_info_rsp), (uint8_t *)&sntp_server_info_rsp);
	if(!status)
	{
		printf("\nsntp server info:%d,%d,", sntp_server_info_rsp.command_type, sntp_server_info_rsp.ip_version);
		if((sntp_server_info_rsp.ip_version) == 4)
		{
			for(ii = 0; ii < 4; ii++)
			{
				printf("%d.", sntp_server_info_rsp.server_ip_address.ipv4_address[ii]);
			}
		}
		else
		{
			for(ii = 0; ii < 16; ii++)
			{
				printf("%d.", sntp_server_info_rsp.server_ip_address.ipv6_address[ii]);
			}
		}
		printf(",%d\n", sntp_server_info_rsp.sntp_method);
	}
	print_status(status);
}

void rsi_sntp_delete(sl_cli_command_arg_t* arguments)
{
	(void)arguments;
	int32_t status = rsi_sntp_client_delete_async();
	print_status(status);
}

void set_fd_command(sl_cli_command_arg_t* arguments)
{
	int8_t socket_id = sl_cli_get_argument_int8(arguments, 0);
	int8_t start_sock_no = sl_cli_get_argument_int8(arguments, 1);
	uint8_t count = 0;

	memset(&read_fds, 0, sizeof(rsi_fd_set));
	for (count = start_sock_no; count < (socket_id+start_sock_no); count++)
	{
		if (!(rsi_getsockopt(count, SOL_SOCKET, SO_CHECK_CONNECTED_STATE, NULL, (rsi_socklen_t)NULL)))
		{
			RSI_FD_SET(count, &read_fds);
		}
	}
	print_status(0);
}

void async_socket_select(rsi_fd_set *fd_read, rsi_fd_set *fd_write, rsi_fd_set *fd_except, int32_t status)
{
	UNUSED_PARAMETER(fd_except); //This statement is added only to resolve compilation warning, value is unchanged
	UNUSED_PARAMETER(fd_write);  //This statement is added only to resolve compilation warning, value is unchanged
	UNUSED_PARAMETER(status);    //This statement is added only to resolve compilation warning, value is unchanged
	memset(&read_fds, 0, sizeof(rsi_fd_set));
	memcpy(&read_fds, fd_read, sizeof(rsi_fd_set));
	socket_select_response = 1;
	printf("\r\nSOCKET_SELECT_EVENT fd_size:%ld,fd_id:%ld\r\n", read_fds.fd_count, read_fds.fd_array[0]);
	socket_select_response = 0;
}

void rsi_socket_select(sl_cli_command_arg_t* arguments)
{
	int8_t socket_id = sl_cli_get_argument_int8(arguments, 0);
	int32_t timeout = sl_cli_get_argument_int32(arguments, 1);
	uint8_t async = sl_cli_get_argument_int8(arguments, 2);
	struct rsi_timeval timeout_sec_usec;
	memset(&timeout_sec_usec, 0, sizeof(timeout_sec_usec));
	uint32_t timeout_ptr = 0;
	uint32_t async_socket_select_ptr = 0;
	if(timeout)
	{
		timeout_sec_usec.tv_sec = timeout;
		timeout_ptr = (uint32_t *)&timeout_sec_usec;
	}
	else
	{
		timeout_ptr = (uint32_t)NULL;
	}
	if(async)
	{
		async_socket_select_ptr = (uint32_t)async_socket_select;
	}
	else
	{
		async_socket_select_ptr = (uint32_t)NULL;
	}
	int32_t status = rsi_select((socket_id+1), &read_fds, NULL, NULL, (struct rsi_timeval*) timeout_ptr, async_socket_select_ptr);
	if(async)
	{
		print_status(status);
	}
	else
	{
		if(status < 0)
		{
			print_status(status);
		}
		else
		{
			printf("\nstatus:%ld\n", status);
			print_status(RSI_ERROR_NONE);
		}
	}
}

void rsi_sntp_client_create_response_handler(uint16_t status, const uint8_t cmd_type, const uint8_t *buffer)
{
	uint8_t rsp_received;
	rsi_sntp_server_rsp_t sntp_server_async_rsp;
	if (status == RSI_SUCCESS) {
		//! Set SUCCESS response
		rsp_received = 1;
		switch (cmd_type) {
		case RSI_SNTP_CREATE: {
			//! SNTP Create response
			} break;
			case RSI_SNTP_DELETE: {
				//! SNTP Delete response
				} break;
				case RSI_SNTP_GETSERVER_ADDRESS:
					case RSI_SNTP_SERVER_ASYNC_RSP: {
						memcpy(&sntp_server_async_rsp, buffer, sizeof(rsi_sntp_server_rsp_t));
						//! SNTP server asynchronous response
						//! Set FAILURE ASYNCresponse
						rsp_received = 3;
					} break;
					default:
						break;
		}
	}
	else {
		//! Set FAILURE response
		rsp_received = 2;
	}
	printf("\r\nSAPI+SNTP_STATUS: %d\r\n", rsp_received);
}


void send_data_on_multiple_sockets(sl_cli_command_arg_t *arguments)
{
	int32_t sock_list = sl_cli_get_argument_int32(arguments, 0);
	int32_t data_len = sl_cli_get_argument_int32(arguments, 1);
	uint16_t ttl_sec = sl_cli_get_argument_uint16(arguments, 2);
	int32_t no_of_pkts = sl_cli_get_argument_int32(arguments, 3);

	int32_t tt_start = 0, tt_end = 0;
	uint8_t sock_no = 0;
	uint32_t status = 0;
	uint32_t tx_stats[10][5] = {0};
	uint8_t max_sock = 0;
	uint8_t flag = 0;
    rsi_rsp_sockets_info_t socket_info;

    status = rsi_wlan_get(RSI_SOCKETS_INFO, (uint8_t *)&socket_info, (uint16_t)sizeof(rsi_rsp_sockets_info_t));
	if(!status)
	{
		max_sock = rsi_bytes2R_to_uint16(&(socket_info.num_open_socks[0]));
	}
	else
	{
	    print_status(status);
	    return;
	}

	if (data_len == 0) {
		data_len = 1460;
	}

	int8_t* buffer = malloc(data_len);
	if (buffer == NULL) {
		printf("\r\n Unable to allocate the required buffer for the requested data size, %ld bytes", data_len);
		//checkStatus(-1, "malloc(recv_size)", socketID, 0, 1);
		return;
	}
	// generate random buffer
	set_random_bytes(buffer, data_len);

	tt_start = rsi_hal_gettickcount();
	while(1)
	{
		if((((tt_end - tt_start) / 1000) > ttl_sec) || (flag == max_sock))
		{
			break;
		}
		if((sock_list & (1<<sock_no)) && (!(tx_stats[sock_no][4])))
		{
			status = rsi_send(sock_no, buffer, data_len, 0);
			if(status)
			{
				tx_stats[sock_no][0] += status;
				tx_stats[sock_no][1] = tt_end - tt_start;
				tx_stats[sock_no][3]++;
				if(tx_stats[sock_no][3] == (uint32_t)no_of_pkts)
				{
					tx_stats[sock_no][4] = 1;
					flag++;
				}
			}
			else {
				tx_stats[sock_no][1] = tt_end - tt_start;
				tx_stats[sock_no][2] = status;
				tx_stats[sock_no][4] = 1;
				flag++;
			}
		}
		sock_no++;
		if(sock_no == max_sock)
		{
			sock_no = 0;
		}
		tt_end = rsi_hal_gettickcount();
	}
	free(buffer);
	printf("\ntx_stats:");

	for(sock_no = 0; sock_no <max_sock; sock_no++)
	{
		printf("%ld,%ld,%ld-", tx_stats[sock_no][0], tx_stats[sock_no][1], tx_stats[sock_no][2]);
	}
	printf("\n");
	print_status(RSI_ERROR_NONE);
}

void rsi_websocket_data_receive_handler(uint32_t sock_no, uint8_t *buffer, uint32_t length)
{
	printf("\r\nWEBSOCKET_DATA_RECEIVE sock_no:%d, buffer:%s, length:%d\r\n",sock_no,buffer,length);
}

void rsi_web_socket_create_command(sl_cli_command_arg_t* arguments)
{
	int32_t status = 0;
	uint32_t socket_id;
	uint8_t flags = sl_cli_get_argument_uint8(arguments, 0);
	char* server_ip_address = sl_cli_get_argument_string(arguments, 1);
	uint16_t server_port = sl_cli_get_argument_uint16(arguments, 2);
	uint16_t device_port = sl_cli_get_argument_uint16(arguments, 3);
	char* web_resource_name = sl_cli_get_argument_string(arguments, 4);
	char* web_host_name = sl_cli_get_argument_string(arguments, 5);

	uint32_t remote_ip = str_to_ipv4(server_ip_address);
	if (remote_ip == 0)
	{
		print_status(RSI_ERROR_INVALID_PARAM);
        return;
	}

	status = rsi_web_socket_create(flags,
                                 (uint8_t *)&remote_ip,
                                 (uint16_t)server_port,
                                 (uint16_t)device_port,
                                 web_resource_name,
                                 web_host_name,
                                 &socket_id,
                                 rsi_websocket_data_receive_handler);

	if(status == 0)
	{
		printf("socket_id:%d\n", socket_id);
	}
	print_status(status);
}

void rsi_web_socket_send_command(sl_cli_command_arg_t* arguments)
{
	int32_t status = 0;
	uint32_t socket_id = sl_cli_get_argument_uint32(arguments, 0);
	uint8_t opcode = sl_cli_get_argument_uint8(arguments, 1);
	char* message = sl_cli_get_argument_string(arguments, 2);

	status = rsi_web_socket_send_async(socket_id, opcode, (int8_t *)message, strlen(message));
	if(status >=0)
	{
		printf("message_length:%d\n", status);
		print_status(RSI_ERROR_NONE);
	}
	else
	{
		print_status(status);
	}
}

void rsi_web_socket_close_command(sl_cli_command_arg_t* arguments)
{
	uint32_t socket_id = sl_cli_get_argument_uint32(arguments, 0);
	print_status(rsi_web_socket_close(socket_id));
}
