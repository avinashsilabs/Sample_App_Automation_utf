#include "sl_cli.h"
#include "sl_cli_types.h"
#include "sl_cli_arguments.h"
#include "rsi_bt.h"
#include "rsi_ble_apis.h"
#include "rsi_ble_config.h"
#include "rsi_bt_common.h"
#include "rsi_utils.h"
#include "rsi_driver.h"
#include "rsi_common_apis.h"
#include "utilities.h"
#include "stdint.h"
#include "string.h"

//REFERENCED FROM
//Host_MCU\examples\_internal\Wireless_Examples\ble\simple_smp\rsi_ble_smp.c
//Host_MCU\examples\_internal\Wireless_Examples\ble\peripheral_secureconnection\rsi_ble_sc.c

//! application event list
#define RSI_APP_EVENT_ADV_REPORT            0
#define RSI_BLE_CONN_EVENT                  1
#define RSI_BLE_DISCONN_EVENT               2
#define RSI_BLE_SMP_REQ_EVENT               3
#define RSI_BLE_SMP_RESP_EVENT              4
#define RSI_BLE_SMP_PASSKEY_EVENT           5
#define RSI_BLE_SMP_FAILED_EVENT            6
#define RSI_BLE_ENCRYPT_STARTED_EVENT       7
#define RSI_BLE_SMP_PASSKEY_DISPLAY_EVENT   8
#define RSI_BLE_SC_PASSKEY_EVENT            9
#define RSI_BLE_LTK_REQ_EVENT               10
#define RSI_BLE_MTU_EVENT                   11
#define RSI_BLE_GATT_WRITE_EVENT            12
#define RSI_BLE_DATA_LENGTH_CHANGE_EVENT    13

#define RSI_PRINT_LOGS 0

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


#define RSI_BLE_TASK_STACK_SIZE  (1024/4)
#define RSI_BLE_TASK_PRIORITY    2
#define STACK_BTLE_MODE 0x02
#define MITM_REQ 0x01

#define RSI_DEV_ADDR_LEN 6

//! local device IO capability
#define RSI_BLE_SMP_IO_CAPABILITY 0x03 //3 - NoInputNoOutput
#define RSI_BLE_SMP_PASSKEY       0
//TODO make the above definitions to dynamic variable

// global for ble capabilities
uint8_t g_ble_capability=3;

//! max data length
#define RSI_BLE_MAX_DATA_LEN 20

#define RSI_BLE_TASK_STACK_SIZE  (1024/4)
#define RSI_BLE_TASK_PRIORITY    2

//! BLE attribute service types uuid values
#define RSI_BLE_CHAR_SERV_UUID   0x2803
#define RSI_BLE_CLIENT_CHAR_UUID 0x2902

//! attribute properties
#define RSI_BLE_ATT_PROPERTY_READ   0x02
#define RSI_BLE_ATT_PROPERTY_WRITE  0x08
#define RSI_BLE_ATT_PROPERTY_NOTIFY 0x10

//! Notify status
#define NOTIFY_DISABLE 0x00
#define NOTIFY_ENABLE  0x01

// Callbacks
static void rsi_ble_app_init_events();
static int32_t rsi_ble_app_get_event(void);
static void rsi_ble_app_clear_event(uint32_t event_num);
static void rsi_ble_app_set_event(uint32_t event_num);

void rsi_ble_simple_central_on_adv_report_event(rsi_ble_event_adv_report_t *adv_report);
void rsi_ble_on_enhance_conn_status_event(rsi_ble_event_enhance_conn_status_t *resp_enh_conn);
void rsi_ble_data_length_change_event(rsi_ble_event_data_length_update_t *rsi_ble_data_length_update);
static void rsi_ble_on_connect_event(rsi_ble_event_conn_status_t *resp_conn);
static void rsi_ble_on_disconnect_event(rsi_ble_event_disconnect_t *resp_disconnect, uint16_t reason);
void rsi_ble_on_smp_request(rsi_bt_event_smp_req_t *remote_dev_address);
void rsi_ble_on_smp_response(rsi_bt_event_smp_resp_t *remote_dev_address);
void rsi_ble_on_smp_passkey(rsi_bt_event_smp_passkey_t *remote_dev_address);
void rsi_ble_on_smp_passkey_display(rsi_bt_event_smp_passkey_display_t *smp_passkey_display);
void rsi_ble_on_sc_passkey(rsi_bt_event_sc_passkey_t *sc_passkey);
void rsi_ble_on_smp_failed(uint16_t status, rsi_bt_event_smp_failed_t *remote_dev_address);
void rsi_ble_on_encrypt_started(uint16_t status, rsi_bt_event_encryption_enabled_t *enc_enabled);
static void rsi_ble_on_le_ltk_req_event(rsi_bt_event_le_ltk_request_t *le_ltk_req);
void rsi_ble_on_le_security_keys(rsi_bt_event_le_security_keys_t *rsi_ble_event_le_security_keys);
static void rsi_ble_on_mtu_event(rsi_ble_event_mtu_t *rsi_ble_mtu);
static void rsi_ble_on_gatt_write_event(uint16_t event_id, rsi_ble_event_write_t *rsi_ble_write);

static uint32_t rsi_app_async_event_map = 0;

static uint8_t device_found          = 0;
static uint8_t remote_addr_type = 0;

// unused at this time
//static uint8_t remote_name[31];

static uint8_t ble_str_conn_bd_addr[18]   = { 0 };
static uint8_t ble_remote_dev_addr[RSI_DEV_ADDR_LEN] = { 0 };

// unused at this time
//static uint8_t target_ble_remote_dev_addr_type = LE_PUBLIC_ADDRESS;
//static uint8_t target_remote_name[31];

uint8_t target_ble_remote_dev_addr[18] = { 0 };

rsi_ble_resp_add_serv_t new_serv_resp = { 0 };

static uint32_t numeric_value;
static uint8_t rsi_app_resp_device_state = 0;
rsi_bt_event_encryption_enabled_t glbl_enc_enabled;
rsi_bt_event_le_ltk_request_t temp_le_ltk_req;
static rsi_bt_event_le_security_keys_t app_ble_sec_keys;
rsi_ble_event_mtu_t app_ble_mtu_event;
static uint16_t rsi_ble_att_val_hndl;
static uint16_t rsi_ble_att2_val_hndl;
static rsi_ble_event_write_t app_ble_write_event;
uint16_t notification_tx_handle = 0;



rsi_semaphore_handle_t ble_thread_sem;
//globals for ble advertising parameters, referenced by #defines in rsi_ble_config.h
uint8_t		g_rsi_ble_adv_type;
uint8_t		g_rsi_ble_adv_filter_type;
uint8_t		g_rsi_ble_addr_type;
uint8_t		g_rsi_ble_dir_addr[RSI_DEV_ADDR_LEN];

uint16_t	g_rsi_ble_adv_int_min;
uint16_t	g_rsi_ble_adv_int_max;
uint8_t 	g_rsi_own_addr_type;
uint8_t		g_rsi_ble_adv_channel_map;
//globals for ble scan parameters, referenced by #defines in rsi_ble_config.h
uint8_t g_ble_scan_type = 1;
uint8_t g_ble_scan_filter_type = 0;
uint16_t g_le_scan_interval = 0x100;
uint16_t g_le_scan_window = 0x0050;
uint8_t g_le_public_address = 0;

uint16_t g_connection_interval_min;
uint16_t  g_connection_interval_max;
uint16_t g_connection_latency;
uint16_t g_supervision_timeout;

rsi_task_handle_t ble_task_handle = NULL;

typedef enum {
    BLE_MASTER_ROLE = 0,
    BLE_SLAVE_ROLE = 1,
    BLE_DUAL_ROLE = 2
} rsi_ble_role_t;
static rsi_ble_role_t current_ble_role;

int8_t ble_gatt_data[RSI_BLE_MAX_DATA_LEN] = { 0 };

static void ble_task(void* arg)
{
    UNUSED_PARAMETER(arg);
    int32_t temp_event_map = 0;
    uint8_t already_paired = 0;
    rsi_ble_resp_local_att_value_t local_att_val;

    while (1) {
        // checking for received events
        temp_event_map = rsi_ble_app_get_event();
        if (temp_event_map == RSI_FAILURE) {
            // if events are not received loop will be continued.
            rsi_semaphore_wait(&ble_thread_sem, 0);
            continue;
        }
        switch (temp_event_map) {
            case RSI_APP_EVENT_ADV_REPORT:
                //! advertise report event.
                LOG_EVENT("\nRSI_APP_EVENT_ADV_REPORT \n");
                rsi_ble_app_clear_event(RSI_APP_EVENT_ADV_REPORT);
                //TODO: Do we keep this here are move it outside and call from UTF
                // LOG_PRINT("\nSending rsi_ble_connect\n");
                // print_status(rsi_ble_connect(remote_addr_type, (int8_t *)ble_remote_dev_addr));
                break;

            case RSI_BLE_CONN_EVENT:
                //! event invokes when connection was completed
                LOG_EVENT("\nRSI_BLE_CONN_EVENT \n");
                rsi_ble_app_clear_event(RSI_BLE_CONN_EVENT);
                break;

            case RSI_BLE_DISCONN_EVENT:
                //! event invokes when disconnection was completed
                LOG_EVENT("\nRSI_BLE_DISCONN_EVENT \n");
                rsi_ble_app_clear_event(RSI_BLE_DISCONN_EVENT);
                device_found = 0;
                // if(current_ble_role == BLE_SLAVE_ROLE){
                //     //! start the advertising
                //     LOG_PRINT("\nSending rsi_ble_start_advertising\n");
                //     print_status(rsi_ble_start_advertising());
                // }
                // if (current_ble_role == BLE_MASTER_ROLE){
                //     //! start scanning
                //     device_found = 0;
                //     LOG_PRINT("\nSending rsi_ble_start_scanning\n");
                //     print_status(rsi_ble_start_scanning());
                // }
                break;

            case RSI_BLE_DATA_LENGTH_CHANGE_EVENT: {
                //! Data change event
                LOG_EVENT("\nRSI_BLE_DATA_LENGTH_CHANGE_EVENT \n");
                //! clear the event.
                rsi_ble_app_clear_event(RSI_BLE_DATA_LENGTH_CHANGE_EVENT);
            } break;

            case RSI_BLE_MTU_EVENT:
                //! event invokes when write/notification events received
                LOG_EVENT("\nRSI_BLE_MTU_EVENT \n");
                rsi_ble_app_clear_event(RSI_BLE_MTU_EVENT);
                if (current_ble_role == BLE_MASTER_ROLE){
                    if (!already_paired) {
                        //! If not paired even once
                        //! initiating the SMP pairing process
                        LOG_PRINT("\nSending rsi_ble_smp_pair_request\n");
                        print_status(rsi_ble_smp_pair_request(app_ble_mtu_event.dev_addr , g_ble_capability, MITM_REQ));
                    }
                }
                break;

            case RSI_BLE_LTK_REQ_EVENT:
                //! event invokes when disconnection was completed
                LOG_EVENT("\nRSI_BLE_LTK_REQ_EVENT \n");
                rsi_ble_app_clear_event(RSI_BLE_LTK_REQ_EVENT);
                if(current_ble_role == BLE_SLAVE_ROLE){
                    if ((temp_le_ltk_req.localediv == glbl_enc_enabled.localediv)
                        && !((memcmp(temp_le_ltk_req.localrand, glbl_enc_enabled.localrand, 8)))) {
                        LOG_PRINT("\nRSI_BLE_LTK_REQ_EVENT positive reply\n");
                        //! give le ltk req reply cmd with positive reply
                        LOG_PRINT("\nSending rsi_ble_ltk_req_reply\n");
                        print_status(rsi_ble_ltk_req_reply(temp_le_ltk_req.dev_addr, 1, glbl_enc_enabled.localltk));
                    } else {
                        LOG_PRINT("\nRSI_BLE_LTK_REQ_EVENT negative reply\n");
                        //! give le ltk req reply cmd with negative reply
                        LOG_PRINT("\nSending rsi_ble_ltk_req_reply\n");
                        print_status(rsi_ble_ltk_req_reply(temp_le_ltk_req.dev_addr, 0, NULL));
                    }
                }
                break;

            case RSI_BLE_SMP_REQ_EVENT:
                //! initiate SMP protocol as a Master
                LOG_EVENT("\nRSI_BLE_SMP_REQ_EVENT \n");
                rsi_ble_app_clear_event(RSI_BLE_SMP_REQ_EVENT);
                if(current_ble_role == BLE_MASTER_ROLE){
                    if (already_paired){
                        //! If once paired
                        //! initiating the SMP pairing process
                        LOG_PRINT("\nSending rsi_ble_smp_pair_request\n");
                        print_status(rsi_ble_smp_pair_request(ble_remote_dev_addr, g_ble_capability, MITM_REQ));
                    }
                }
                break;

            case RSI_BLE_SMP_RESP_EVENT:
                //! initiate SMP protocol as a Master
                LOG_EVENT("\nRSI_BLE_SMP_RESP_EVENT \n");
                rsi_ble_app_clear_event(RSI_BLE_SMP_RESP_EVENT);
                LOG_PRINT("\nSending rsi_ble_smp_pair_response\n");
                print_status(rsi_ble_smp_pair_response(ble_remote_dev_addr, g_ble_capability, MITM_REQ));
                break;

            case RSI_BLE_SMP_PASSKEY_EVENT:
                LOG_EVENT("\nRSI_BLE_SMP_PASSKEY_EVENT \n");
                rsi_ble_app_clear_event(RSI_BLE_SMP_PASSKEY_EVENT);
                //! initiating the SMP pairing process
                print_status(rsi_ble_smp_passkey(ble_remote_dev_addr, RSI_BLE_SMP_PASSKEY));
                break;

            case RSI_BLE_SMP_PASSKEY_DISPLAY_EVENT:
                LOG_EVENT("\nRSI_BLE_SMP_PASSKEY_DISPLAY_EVENT \n");
                rsi_ble_app_clear_event(RSI_BLE_SMP_PASSKEY_DISPLAY_EVENT);
                break;

            case RSI_BLE_SC_PASSKEY_EVENT:
                LOG_EVENT("\nRSI_BLE_SC_PASSKEY_EVENT\n");
                rsi_ble_app_clear_event(RSI_BLE_SC_PASSKEY_EVENT);
                LOG_PRINT("\nrsi_ble_smp_passkey\n");
                print_status(rsi_ble_smp_passkey(ble_remote_dev_addr, numeric_value));
                break;

            case RSI_BLE_SMP_FAILED_EVENT:
                LOG_EVENT("\nRSI_BLE_SMP_FAILED_EVENT \n");
                rsi_ble_app_clear_event(RSI_BLE_SMP_FAILED_EVENT);
                break;

            case RSI_BLE_ENCRYPT_STARTED_EVENT:
                //! start the encrypt event
                LOG_EVENT("\nRSI_BLE_ENCRYPT_STARTED_EVENT \n");
                rsi_ble_app_clear_event(RSI_BLE_ENCRYPT_STARTED_EVENT);
                already_paired = 1;
                break;

            case RSI_BLE_GATT_WRITE_EVENT:
                //! event invokes when write/notification events received
                //! clear the served event
                LOG_EVENT("\nRSI_BLE_GATT_WRITE_EVENT \n");
                rsi_ble_app_clear_event(RSI_BLE_GATT_WRITE_EVENT);

                LOG_PRINT("\n rsi_ble_att_val_hndl = %d, rsi_ble_att2_val_hndl = %d, *((uint16_t *)app_ble_write_event.handle) = %d\n",
                rsi_ble_att_val_hndl, rsi_ble_att2_val_hndl, *((uint16_t *)app_ble_write_event.handle));

                if(rsi_ble_att_val_hndl == *((uint16_t *)app_ble_write_event.handle)) {
                     LOG_PRINT("\n Preparing and setting the data as local attribute value\n");
                    //! prepare the data to set as local attribute value.
                    memset(ble_gatt_data, 0, sizeof(ble_gatt_data));
                    memcpy(ble_gatt_data, app_ble_write_event.att_value, app_ble_write_event.length);

                    rsi_ble_get_local_att_value(rsi_ble_att_val_hndl, &local_att_val);
                    //! set the local attribute value.
                    rsi_ble_set_local_att_value(rsi_ble_att_val_hndl, RSI_BLE_MAX_DATA_LEN, (uint8_t *)ble_gatt_data);
                    rsi_ble_get_local_att_value(rsi_ble_att_val_hndl, &local_att_val);
                }
                if(rsi_ble_att_val_hndl == *((uint16_t *)app_ble_write_event.handle)-1) {
                    //This block is executed when Notification are turned on/off by remote device
                    //check for valid notifications
                    if (app_ble_write_event.att_value[0] == NOTIFY_ENABLE) {
                        notification_tx_handle = *((uint16_t *)app_ble_write_event.handle)-1;
                        LOG_PRINT("\n Remote device enabled the notification\n");
                    } else if (app_ble_write_event.att_value[0] == NOTIFY_DISABLE) {
                        notification_tx_handle = 0;
                        LOG_PRINT("\n Remote device disabled the notification\n");
                    }
                }
                break;

            default:{

            }
        }
    }
}

void init_ble_command(sl_cli_command_arg_t *arguments)
{
    if (ble_task_handle != NULL) {
        // already initialized
        print_status(RSI_ERROR_NONE);
        return;
    }
    g_ble_capability = sl_cli_get_argument_uint8(arguments, 0);
    int32_t status = intialize_bt_stack(STACK_BTLE_MODE);
    if (status == RSI_SUCCESS) {
        //set default role to master
        current_ble_role = BLE_MASTER_ROLE;

        rsi_task_create((rsi_task_function_t)ble_task,
                        (uint8_t*)"ble_task",
                        RSI_BLE_TASK_STACK_SIZE,
                        NULL,
                        RSI_BLE_TASK_PRIORITY, &ble_task_handle);
        //! registering the GAP callback functions
        rsi_ble_gap_register_callbacks(rsi_ble_simple_central_on_adv_report_event,
                                        rsi_ble_on_connect_event,
                                        rsi_ble_on_disconnect_event,
                                        NULL,
                                        NULL,
                                        rsi_ble_data_length_change_event,
                                        rsi_ble_on_enhance_conn_status_event,
                                        NULL,
                                        NULL,
                                        NULL);

        //! registering the SMP callback functions
        rsi_ble_smp_register_callbacks(rsi_ble_on_smp_request,
                                        rsi_ble_on_smp_response,
                                        rsi_ble_on_smp_passkey,
                                        rsi_ble_on_smp_failed,
                                        rsi_ble_on_encrypt_started,
                                        rsi_ble_on_smp_passkey_display,
                                        rsi_ble_on_sc_passkey,
                                        rsi_ble_on_le_ltk_req_event,
                                        rsi_ble_on_le_security_keys,
                                        NULL,
                                        NULL);

        //! registering the GATT callback functions
        rsi_ble_gatt_register_callbacks(NULL,
                                        NULL,
                                        NULL,
                                        NULL,
                                        NULL,
                                        NULL,
                                        NULL,
                                        rsi_ble_on_gatt_write_event,
                                        NULL,
                                        NULL,
                                        NULL,
                                        rsi_ble_on_mtu_event,
                                        NULL,
                                        NULL,
                                        NULL,
                                        NULL,
                                        NULL,
                                        NULL,
                                        NULL,
                                        NULL,
                                        NULL,
                                        NULL,
                                        NULL);

        //!  initializing the application events map
        rsi_ble_app_init_events();
    }
    print_status(status);
}

void rsi_bt_deinit_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    print_status(rsi_bt_deinit());
}

void rsi_bt_set_local_name_command(sl_cli_command_arg_t* arguments)
{
    char* name = sl_cli_get_argument_string(arguments, 0);
    print_status(rsi_bt_set_local_name((uint8_t*)name));
}

void rsi_ble_start_scanning_command(sl_cli_command_arg_t* arguments){
    printf("\r\n rsi_ble_start_scanning_command invoked \r\n");
	char* remote_dev_addr = sl_cli_get_argument_string(arguments, 0);
	g_ble_scan_type = sl_cli_get_argument_uint8(arguments, 1);
	g_ble_scan_filter_type = sl_cli_get_argument_uint8(arguments, 2);
	g_le_scan_interval = sl_cli_get_argument_uint16(arguments, 3);
	g_le_scan_window = sl_cli_get_argument_uint16(arguments, 4);
	g_le_public_address = sl_cli_get_argument_uint8(arguments, 5);

	strcpy((char *)target_ble_remote_dev_addr,remote_dev_addr);

    device_found = 0;
	int32_t status = rsi_ble_start_scanning();
	//This assignment may change when we implement dual role
	if(status == RSI_SUCCESS){
		current_ble_role = BLE_MASTER_ROLE;
	}
	print_status(status);
}

void rsi_ble_stop_scanning_command(sl_cli_command_arg_t* arguments){
    (void)arguments;
    print_status(rsi_ble_stop_scanning());
}

void rsi_ble_connect_comamnd(sl_cli_command_arg_t* arguments){
	char* remote_dev_addr = sl_cli_get_argument_string(arguments, 0);
	g_connection_interval_min = sl_cli_get_argument_uint16(arguments, 1);
	g_connection_interval_max = sl_cli_get_argument_uint16(arguments, 2);
	g_connection_latency = sl_cli_get_argument_uint16(arguments, 3);
	g_supervision_timeout = sl_cli_get_argument_uint16(arguments, 4);

	uint8_t device_address[6];
	rsi_ascii_dev_address_to_6bytes_rev(device_address, (int8_t*)remote_dev_addr);
	print_status(rsi_ble_connect(remote_addr_type, (int8_t *)device_address));
}


void rsi_ble_disconnect_comamnd(sl_cli_command_arg_t* arguments){
    char* remote_dev_addr = sl_cli_get_argument_string(arguments, 0);

    uint8_t device_address[6];
    for (int i = 0; i < 6; i++) {
        int val;
        sscanf(remote_dev_addr + 3 * i, "%02X", &val);
        device_address[5-i] = (uint8_t)val;
    }

    print_status(rsi_ble_disconnect((int8_t *)device_address));
}


void rsi_ble_get_device_state_command(sl_cli_command_arg_t* arguments){
    (void)arguments;
    int32_t status = rsi_ble_get_device_state(&rsi_app_resp_device_state);
    if (status == RSI_SUCCESS) {
       printf("\n%d\n",rsi_app_resp_device_state);
    }
    print_status(status);
}

void rsi_bt_set_eir_data_command(sl_cli_command_arg_t* arguments)
{
    char* data = sl_cli_get_argument_string(arguments, 0);
    const uint8_t data_length = strlen(data);
    uint8_t eir_data[50] = { 2, 1, 0 };

    // prepare Extended Response Data
    eir_data[3] = data_length + 1;
    eir_data[4] = 9;
    strcpy((char*)&eir_data[5], data);
    print_status(rsi_bt_set_eir_data(eir_data, data_length + 5));
}

void rsi_bt_get_local_name_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    rsi_bt_resp_get_local_name_t name = { 0 };
    int32_t status = rsi_bt_get_local_name(&name);
    if (status == RSI_SUCCESS) {
    	printf("\n%s\n", name.name);
    }
    print_status(status);
}

void rsi_bt_get_local_device_address_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    uint8_t device_address[6] = { 0 };

    int32_t status = rsi_bt_get_local_device_address(device_address);
    if (status == RSI_SUCCESS) {
        printf("\n%02X:%02X:%02X:%02X:%02X:%02X\n", device_address[5], device_address[4], device_address[3], device_address[2], device_address[1], device_address[0]);
    }
    print_status(status);
}

void rsi_bt_start_discoverable_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    print_status(rsi_bt_start_discoverable());
}

void rsi_bt_set_connectable_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    print_status(rsi_bt_set_connectable());
}

void rsi_ble_set_address(sl_cli_command_arg_t* arguments)
{
    uint8_t device_address[6];
    char* device_addr_str = sl_cli_get_argument_string(arguments, 0);
    for (int i = 0; i < 6; i++) {
        int val;
        sscanf(device_addr_str + 3 * i, "%02X", &val);
        device_address[5-i] = (uint8_t)val;
    }
    int32_t status = rsi_ble_set_random_address_with_value(device_address);
    if (status == RSI_SUCCESS) {
        status = rsi_bt_set_bd_addr(device_address);
    }
    print_status(status);
}

void rsi_ble_start_advertising_command(sl_cli_command_arg_t* arguments)
{
	char* data = sl_cli_get_argument_string(arguments, 0);

	g_rsi_ble_adv_type 		= sl_cli_get_argument_uint8(arguments, 1);
	g_rsi_ble_adv_filter_type = sl_cli_get_argument_uint8(arguments, 2);
	g_rsi_ble_addr_type		= sl_cli_get_argument_uint8(arguments, 3);

	strcpy((char *)g_rsi_ble_dir_addr, sl_cli_get_argument_string(arguments, 4));

	g_rsi_ble_adv_int_min		= sl_cli_get_argument_uint16(arguments, 5);
	g_rsi_ble_adv_int_max		= sl_cli_get_argument_uint16(arguments, 6);
	g_rsi_own_addr_type		= sl_cli_get_argument_uint8(arguments, 7);
	g_rsi_ble_adv_channel_map = sl_cli_get_argument_uint8(arguments, 8);



    const uint8_t data_length = strlen(data);
    uint8_t adv[64] = { 2, 1, 6 };

    // prepare advertise data //local/device name
    adv[3] = data_length + 1;
    adv[4] = 9;
    strcpy((char*)&adv[5], data);

    // set advertise data
    int32_t status = rsi_ble_set_advertise_data(adv, data_length + 5);

    // set device in advertising mode.
    if (status == RSI_SUCCESS) {
        status = rsi_ble_start_advertising();
        //This assignment may have to be changed when we implement dual role
        if(status == RSI_SUCCESS){
            current_ble_role = BLE_SLAVE_ROLE;
        }
    }

    print_status(status);
}

void rsi_ble_stop_advertising_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    int32_t status = rsi_ble_stop_advertising();
    print_status(status);
}


void rsi_ble_add_service_command(sl_cli_command_arg_t* arguments)
{
    uint16_t uuid = sl_cli_get_argument_uint16(arguments, 0);

    //! adding new service
    uuid_t new_uuid                       = { 0 };
    new_uuid.size      = 2;
    new_uuid.val.val16 = uuid;
    print_status(rsi_ble_add_service(new_uuid, &new_serv_resp));
}

int32_t rsi_ble_notify_value_internal()
{
    if(notification_tx_handle == 0){
        LOG_PRINT("\nNotifications are turned off on remote device.\n");
        return RSI_ERROR_COMMAND_GIVEN_IN_WRONG_STATE;
    }
    int32_t status = rsi_ble_notify_value(ble_remote_dev_addr,
                                    notification_tx_handle,
                                    sizeof(ble_gatt_data),
                                    (uint8_t *)ble_gatt_data);
    return status;
}

void rsi_ble_notify_value_command(sl_cli_command_arg_t* arguments)
{
    (void)arguments;
    print_status(rsi_ble_notify_value_internal());
}

void rsi_ble_start_notify_value_command(sl_cli_command_arg_t* arguments)
{
    uint16_t time_out_ms = sl_cli_get_argument_uint16(arguments, 0);
    uint16_t count = sl_cli_get_argument_uint16(arguments, 1);
    if(notification_tx_handle == 0){
        LOG_PRINT("\nNotifications are turned off on remote device.\n");
        print_status(RSI_ERROR_COMMAND_GIVEN_IN_WRONG_STATE);
        return;
    }
    int32_t status;
    while(count > 0){
        status = rsi_ble_notify_value_internal();
        if (status != RSI_ERROR_NONE){
            break;
        }
        rsi_delay_ms(time_out_ms);
        count--;
    }
    print_status(status);
}

void rsi_ble_add_char_serv_att_command(sl_cli_command_arg_t* arguments)
{
    uint16_t uuid = sl_cli_get_argument_uint16(arguments, 0);
    uint8_t val_prop = sl_cli_get_argument_uint8(arguments, 1);
    uint16_t serv_handle_num = sl_cli_get_argument_uint8(arguments, 2);
    uint16_t val_handle_num = sl_cli_get_argument_uint8(arguments, 3);

    //! adding characteristic service attribute to the service
    uuid_t new_uuid                       = { 0 };
    new_uuid.size      = 2;
    new_uuid.val.val16 = uuid;
    print_status(rsi_ble_add_char_serv_att(new_serv_resp.serv_handler,
                                new_serv_resp.start_handle + serv_handle_num,
                                val_prop,
                                new_serv_resp.start_handle + val_handle_num,
                                new_uuid));
}

void rsi_ble_add_char_val_att_command(sl_cli_command_arg_t* arguments)
{
    uint16_t uuid = sl_cli_get_argument_uint16(arguments, 0);
    uint8_t val_prop = sl_cli_get_argument_uint8(arguments, 1);
    uint16_t val_handle_num = sl_cli_get_argument_uint8(arguments, 2);
    char* data = sl_cli_get_argument_string(arguments, 3);

    memset(ble_gatt_data, 0, sizeof(ble_gatt_data));
    memcpy(ble_gatt_data, data, sizeof(data));

    //! adding characteristic value attribute to the service
    uuid_t new_uuid                       = { 0 };
    rsi_ble_att_val_hndl = new_serv_resp.start_handle + val_handle_num;
    new_uuid.size         = 2;
    new_uuid.val.val16    = uuid;
    print_status(rsi_ble_add_char_val_att(new_serv_resp.serv_handler,
                            new_serv_resp.start_handle + val_handle_num,
                            new_uuid,
                            val_prop,
                            (uint8_t *)ble_gatt_data,
                            sizeof(ble_gatt_data)));
}

//get profiles async command written for multi connection gatt example
void rsi_ble_get_profiles_async_command(sl_cli_command_arg_t* arguments){
	char* remote_dev_bd_addr = sl_cli_get_argument_string(arguments, 0);

  uint8_t rsi_connected_dev_addr[6] = { 0 };
  rsi_ascii_dev_address_to_6bytes_rev(rsi_connected_dev_addr,
                                              (int8_t *)remote_dev_bd_addr);
  print_status(rsi_ble_get_profiles_async(rsi_connected_dev_addr, 1, 0xffff, NULL));
}

void rsi_ble_get_profile_async_command(sl_cli_command_arg_t* arguments){

	char* remote_dev_bd_addr = sl_cli_get_argument_string(arguments, 0);


  uuid_t search_serv                               = { 0 };
  search_serv.size = 2;
  search_serv.val.val16 = sl_cli_get_argument_uint16(arguments, 1);

  uint8_t rsi_connected_dev_addr[6] = { 0 };
  rsi_ascii_dev_address_to_6bytes_rev(rsi_connected_dev_addr, (int8_t *)remote_dev_bd_addr);
  print_status(rsi_ble_get_profile_async(rsi_connected_dev_addr, search_serv, NULL));
}

void rsi_ble_get_char_services_async_command(sl_cli_command_arg_t* arguments){
  char* remote_dev_bd_addr = sl_cli_get_argument_string(arguments, 0);
  uint16_t start_handle = sl_cli_get_argument_uint16(arguments, 1);
  uint16_t end_handle = sl_cli_get_argument_uint16(arguments, 2);

  uint8_t rsi_connected_dev_addr[6] = { 0 };
  rsi_ascii_dev_address_to_6bytes_rev(rsi_connected_dev_addr, (int8_t *)remote_dev_bd_addr);

  //! Get characteristic services of searched profile
  uint8_t status = rsi_ble_get_char_services_async(rsi_connected_dev_addr, start_handle, end_handle, NULL);
  print_status(status);
}

void rsi_ble_get_att_value_async_command(sl_cli_command_arg_t* arguments){
    char* remote_dev_bd_addr = sl_cli_get_argument_string(arguments, 0);
    uint16_t handle = sl_cli_get_argument_uint16(arguments, 1);

    uint8_t rsi_connected_dev_addr[6] = { 0 };
    rsi_ascii_dev_address_to_6bytes_rev(rsi_connected_dev_addr, (int8_t *)remote_dev_bd_addr);

    //! Get characteristic services of searched profile
    print_status(rsi_ble_get_att_value_async(rsi_connected_dev_addr, handle, NULL));
}

void rsi_ble_set_att_value_async_command(sl_cli_command_arg_t* arguments){
    char* remote_dev_bd_addr = sl_cli_get_argument_string(arguments, 0);
    uint16_t handle = sl_cli_get_argument_uint16(arguments, 1);
    uint8_t data = sl_cli_get_argument_uint8(arguments, 2);

    uint8_t data_to_send[1] = {data};

    uint8_t rsi_connected_dev_addr[6] = { 0 };
    rsi_ascii_dev_address_to_6bytes_rev(rsi_connected_dev_addr, (int8_t *)remote_dev_bd_addr);
    print_status(rsi_ble_set_att_value_async(rsi_connected_dev_addr, handle, sizeof(data_to_send), (uint8_t *)data_to_send));
}




/*==============================================*/
/**
 * @fn         rsi_ble_add_char_serv_att
 * @brief      this function is used to add characteristic service attribute..
 * @param[in]  serv_handler, service handler.
 * @param[in]  handle, characteristic service attribute handle.
 * @param[in]  val_prop, characteristic value property.
 * @param[in]  att_val_handle, characteristic value handle
 * @param[in]  att_val_uuid, characteristic value uuid
 * @return     none.
 * @section description
 * This function is used at application to add characteristic attribute
 */
void rsi_ble_add_char_serv_att(void *serv_handler,
                                      uint16_t handle,
                                      uint8_t val_prop,
                                      uint16_t att_val_handle,
                                      uuid_t att_val_uuid)
{
    rsi_ble_req_add_att_t new_att = { 0 };

    //! preparing the attribute service structure
    new_att.serv_handler       = serv_handler;
    new_att.handle             = handle;
    new_att.att_uuid.size      = 2;
    new_att.att_uuid.val.val16 = RSI_BLE_CHAR_SERV_UUID;
    new_att.property           = RSI_BLE_ATT_PROPERTY_READ;

    //! preparing the characteristic attribute value
    new_att.data_len = 6;
    new_att.data[0]  = val_prop;
    rsi_uint16_to_2bytes(&new_att.data[2], att_val_handle);
    rsi_uint16_to_2bytes(&new_att.data[4], att_val_uuid.val.val16);

    //! Add attribute to the service
    rsi_ble_add_attribute(&new_att);

    return;
}

/*==============================================*/
/**
 * @fn         rsi_ble_add_char_val_att
 * @brief      this function is used to add characteristic value attribute.
 * @param[in]  serv_handler, new service handler.
 * @param[in]  handle, characteristic value attribute handle.
 * @param[in]  att_type_uuid, attribute uuid value.
 * @param[in]  val_prop, characteristic value property.
 * @param[in]  data, characteristic value data pointer.
 * @param[in]  data_len, characteristic value length.
 * @return     none.
 * @section description
 * This function is used at application to create new service.
 */

void rsi_ble_add_char_val_att(void *serv_handler,
                                     uint16_t handle,
                                     uuid_t att_type_uuid,
                                     uint8_t val_prop,
                                     uint8_t *data,
                                     uint8_t data_len)
{
  rsi_ble_req_add_att_t new_att = { 0 };

  //! preparing the attributes
  new_att.serv_handler = serv_handler;
  new_att.handle       = handle;
  memcpy(&new_att.att_uuid, &att_type_uuid, sizeof(uuid_t));
  new_att.property = val_prop;

  //! preparing the attribute value
  new_att.data_len = RSI_MIN(sizeof(new_att.data), data_len);
  memcpy(new_att.data, data, new_att.data_len);

  //! add attribute to the service
  rsi_ble_add_attribute(&new_att);

  //! check the attribute property with notification
  if (val_prop & RSI_BLE_ATT_PROPERTY_NOTIFY) {
    //! if notification property supports then we need to add client characteristic service.

    //! preparing the client characteristic attribute & values
    memset(&new_att, 0, sizeof(rsi_ble_req_add_att_t));
    new_att.serv_handler       = serv_handler;
    new_att.handle             = handle + 1;
    new_att.att_uuid.size      = 2;
    new_att.att_uuid.val.val16 = RSI_BLE_CLIENT_CHAR_UUID;
    new_att.property           = RSI_BLE_ATT_PROPERTY_READ | RSI_BLE_ATT_PROPERTY_WRITE;
    new_att.data_len           = 2;

    //! add attribute to the service
    rsi_ble_add_attribute(&new_att);
  }

  return;
}

/**
 * @fn         rsi_ble_app_init_events
 * @brief      initializes the event parameter.
 * @param[in]  none.
 * @return     none.
 * @section description
 * This function is used during BLE initialization.
 */
static void rsi_ble_app_init_events()
{
    rsi_app_async_event_map = 0;
}

/*==============================================*/
/**
 * @fn         rsi_ble_app_set_event
 * @brief      set the specific event.
 * @param[in]  event_num, specific event number.
 * @return     none.
 * @section description
 * This function is used to set/raise the specific event.
 */
static void rsi_ble_app_set_event(uint32_t event_num)
{
    rsi_app_async_event_map |= BIT(event_num);
    rsi_semaphore_post(&ble_thread_sem);
    return;
}

/*==============================================*/
/**
 * @fn         rsi_ble_app_clear_event
 * @brief      clear the specific event.
 * @param[in]  event_num, specific event number.
 * @return     none.
 * @section description
 * This function is used to clear the specific event.
 */
static void rsi_ble_app_clear_event(uint32_t event_num)
{
    rsi_app_async_event_map &= ~BIT(event_num);
    return;
}

/*==============================================*/
/**
 * @fn         rsi_ble_app_get_event
 * @brief      returns the first set event based on priority
 * @param[in]  none.
 * @return     int32_t
 *             > 0  = event number
 *             -1   = not received any event
 * @section description
 * This function returns the highest priority event among all the set events
 */
static int32_t rsi_ble_app_get_event(void)
{
    uint32_t ix;

    for (ix = 0; ix < 32; ix++) {
        if (rsi_app_async_event_map & (1 << ix)) {
            return ix;
        }
    }

    return (-1);
}

/*==============================================*/
/**
 * @fn         rsi_ble_simple_central_on_adv_report_event
 * @brief      invoked when advertise report event is received
 * @param[in]  adv_report, pointer to the received advertising report
 * @return     none.
 * @section description
 * This callback function updates the scanned remote devices list
 */
void rsi_ble_simple_central_on_adv_report_event(rsi_ble_event_adv_report_t *adv_report)
{
    uint8_t count = 0;
//    if (device_found == 1) {
//        return;
//    }

    // memset(remote_name, 0, 31);
    // BT_LE_ADPacketExtract(remote_name, adv_report->adv_data, adv_report->adv_data_len);

    // remote_addr_type = adv_report->dev_addr_type;
    memcpy(ble_remote_dev_addr, (uint8_t *)adv_report->dev_addr, RSI_DEV_ADDR_LEN);

    rsi_6byte_dev_address_to_ascii(ble_str_conn_bd_addr, adv_report->dev_addr);

    LOG_EVENT("Found : %s\n",ble_str_conn_bd_addr);

    if(current_ble_role == BLE_MASTER_ROLE){
        bool device_was_not_found_yet = device_found == 0;
        // bool found_desired_remote_name = strcmp(remote_name, target_remote_name) == 0;
        // bool found_desired_remote_type = remote_addr_type == target_ble_remote_dev_addr_type;
        bool found_desired_remote_addr = strcmp((const char *)ble_str_conn_bd_addr, (const char *)target_ble_remote_dev_addr) == 0;
        //if (device_was_not_found_yet && found_desired_remote_name || (found_desired_remote_type && found_desired_remote_addr)) {
        if (device_was_not_found_yet && found_desired_remote_addr) {
            device_found = 1;
            // LOG_EVENT("\nrsi_ble_simple_central_on_adv_report_event- dev_addr: %s, dev_addr_type: %s, remote_name: %s\n",
            //     ble_str_conn_bd_addr,
            //     remote_addr_type, remote_name);
//            LOG_EVENT("\nrsi_ble_simple_central_on_adv_report_event- dev_addr: %s\n",
//                ble_str_conn_bd_addr);
            LOG_EVENT("\nrsi_ble_simple_central_on_adv_report_event- dev_addr: %s, dev_addr_type: %d, adv_data_len: %d, rssi:%d, report_type:%d,",
                ble_str_conn_bd_addr,
                adv_report->dev_addr_type,
                adv_report->adv_data_len,
                adv_report->rssi,
                adv_report->report_type
                );
            LOG_EVENT("adv_data:");
            for(count = 0; count < RSI_MAX_ADV_REPORT_SIZE; count++)
            {
            LOG_EVENT("%d-",adv_report->adv_data[count]);
            }
            LOG_EVENT("\n");
            rsi_ble_app_set_event(RSI_APP_EVENT_ADV_REPORT);
        }
    }
}

/*==============================================*/
/**
 * @fn         rsi_ble_data_length_change_event
 * @brief      invoked when data length is set
  * @section description
 * This Callback function indicates data length is set
 */
void rsi_ble_data_length_change_event(rsi_ble_event_data_length_update_t *rsi_ble_data_length_update)
{
    LOG_EVENT("\nrsi_ble_data_length_change_event- dev_addr: %s\n",
            rsi_6byte_dev_address_to_ascii(ble_str_conn_bd_addr, rsi_ble_data_length_update->dev_addr));
    rsi_ble_app_set_event(RSI_BLE_DATA_LENGTH_CHANGE_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_enhance_conn_status_event
 * @brief      invoked when enhanced connection complete event is received
 * @param[out] resp_conn, connected remote device information
 * @return     none.
 * @section description
 * This callback function indicates the status of the connection
 */
void rsi_ble_on_enhance_conn_status_event(rsi_ble_event_enhance_conn_status_t *resp_enh_conn)
{
    memcpy((int8_t *)ble_remote_dev_addr, resp_enh_conn->dev_addr, RSI_DEV_ADDR_LEN);
    LOG_EVENT("\nrsi_ble_on_enhance_conn_status_event- dev_addr: %s\n",
            rsi_6byte_dev_address_to_ascii(ble_str_conn_bd_addr, resp_enh_conn->dev_addr));
    rsi_ble_app_set_event(RSI_BLE_CONN_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_connect_event
 * @brief      invoked when connection complete event is received
 * @param[out] resp_conn, connected remote device information
 * @return     none.
 * @section description
 * This callback function indicates the status of the connection
 */
static void rsi_ble_on_connect_event(rsi_ble_event_conn_status_t *resp_conn)
{
    memcpy((int8_t *)ble_remote_dev_addr, resp_conn->dev_addr, RSI_DEV_ADDR_LEN);
    LOG_EVENT("\nrsi_ble_on_connect_event- dev_addr: %s\n",
                rsi_6byte_dev_address_to_ascii(ble_str_conn_bd_addr, resp_conn->dev_addr));

    rsi_ble_app_set_event(RSI_BLE_CONN_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_disconnect_event
 * @brief      invoked when disconnection event is received
 * @param[in]  resp_disconnect, disconnected remote device information
 * @param[in]  reason, reason for disconnection.
 * @return     none.
 * @section description
 * This callback function indicates disconnected device information and status
 */
static void rsi_ble_on_disconnect_event(rsi_ble_event_disconnect_t *resp_disconnect, uint16_t reason)
{
    memcpy((int8_t *)ble_remote_dev_addr, resp_disconnect->dev_addr, RSI_DEV_ADDR_LEN);
    LOG_EVENT("\nrsi_ble_on_disconnect_event- dev_addr: %s, reason: 0x%x\n",
                rsi_6byte_dev_address_to_ascii(ble_str_conn_bd_addr, resp_disconnect->dev_addr), reason);

    rsi_ble_app_set_event(RSI_BLE_DISCONN_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_smp_request
 * @brief      its invoked when smp request event is received.
 * @param[in]  remote_dev_address, it indicates remote bd address.
 * @return     none.
 * @section description
 * This callback function is invoked when SMP request events is received(we are in Master mode)
 * Note: slave requested to start SMP request, we have to send SMP request command
 */
void rsi_ble_on_smp_request(rsi_bt_event_smp_req_t *remote_dev_address)
{
    memcpy((int8_t *)ble_remote_dev_addr, remote_dev_address->dev_addr, RSI_DEV_ADDR_LEN);
    LOG_EVENT("\nrsi_ble_on_smp_request- dev_addr: %s\n",
                rsi_6byte_dev_address_to_ascii(ble_str_conn_bd_addr, remote_dev_address->dev_addr));
    rsi_ble_app_set_event(RSI_BLE_SMP_REQ_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_smp_response
 * @brief      its invoked when smp response event is received.
 * @param[in]  remote_dev_address, it indicates remote bd address.
 * @return     none.
 * @section description
 * This callback function is invoked when SMP response events is received(we are in slave mode)
 * Note: Master initiated SMP protocol, we have to send SMP response command
 */
void rsi_ble_on_smp_response(rsi_bt_event_smp_resp_t *remote_dev_address)
{
    memcpy((int8_t *)ble_remote_dev_addr, remote_dev_address->dev_addr, RSI_DEV_ADDR_LEN);
    LOG_EVENT("\nrsi_ble_on_smp_response- dev_addr: %s\n",
                rsi_6byte_dev_address_to_ascii(ble_str_conn_bd_addr, remote_dev_address->dev_addr));
    rsi_ble_app_set_event(RSI_BLE_SMP_RESP_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_smp_passkey
 * @brief      its invoked when smp passkey event is received.
 * @param[in]  remote_dev_address, it indicates remote bd address.
 * @return     none.
 * @section description
 * This callback function is invoked when SMP passkey events is received
 * Note: We have to send SMP passkey command
 */
void rsi_ble_on_smp_passkey(rsi_bt_event_smp_passkey_t *remote_dev_address)
{
    memcpy((int8_t *)ble_remote_dev_addr, remote_dev_address->dev_addr, RSI_DEV_ADDR_LEN);
    LOG_EVENT("\nrsi_ble_on_smp_passkey- dev_addr: %s\n",
                rsi_6byte_dev_address_to_ascii(ble_str_conn_bd_addr, remote_dev_address->dev_addr));
    rsi_ble_app_set_event(RSI_BLE_SMP_PASSKEY_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_smp_passkey_display
 * @brief      its invoked when smp passkey event is received.
 * @param[in]  remote_dev_address, it indicates remote bd address.
 * @return     none.
 * @section description
 * This callback function is invoked when SMP passkey events is received
 * Note: We have to send SMP passkey command
 */
void rsi_ble_on_smp_passkey_display(rsi_bt_event_smp_passkey_display_t *smp_passkey_display)
{
    LOG_EVENT("\nrsi_ble_on_smp_passkey_display- passkey: %s\n", smp_passkey_display->passkey);
    rsi_ble_app_set_event(RSI_BLE_SMP_PASSKEY_DISPLAY_EVENT);
}

void rsi_ble_on_sc_passkey(rsi_bt_event_sc_passkey_t *sc_passkey)
{
    memcpy(ble_remote_dev_addr, sc_passkey->dev_addr, 6);
    LOG_EVENT("\nrsi_ble_on_sc_passkey- dev_addr: %s, passkey: %06ld \r\n",
                rsi_6byte_dev_address_to_ascii(ble_str_conn_bd_addr, sc_passkey->dev_addr),
                sc_passkey->passkey);
    numeric_value = sc_passkey->passkey;
    rsi_ble_app_set_event(RSI_BLE_SC_PASSKEY_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_smp_failed
 * @brief      its invoked when smp failed event is received.
 * @param[in]  remote_dev_address, it indicates remote bd address.
 * @return     none.
 * @section description
 * This callback function is invoked when SMP failed events is received
 */
void rsi_ble_on_smp_failed(uint16_t resp_status, rsi_bt_event_smp_failed_t *remote_dev_address)
{
    memcpy((int8_t *)ble_remote_dev_addr, remote_dev_address->dev_addr, RSI_DEV_ADDR_LEN);
    LOG_EVENT("\nrsi_ble_on_smp_failed- resp_status: 0x%x, dev_addr: %s\n", resp_status,
                rsi_6byte_dev_address_to_ascii(ble_str_conn_bd_addr, remote_dev_address->dev_addr));
    rsi_ble_app_set_event(RSI_BLE_SMP_FAILED_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_encrypt_started
 * @brief      its invoked when encryption started event is received.
 * @param[in]  remote_dev_address, it indicates remote bd address.
 * @return     none.
 * @section description
 * This callback function is invoked when encryption started events is received
 */
void rsi_ble_on_encrypt_started(uint16_t status, rsi_bt_event_encryption_enabled_t *enc_enabled)
{
    (void)status;
    LOG_EVENT("\nrsi_ble_on_encrypt_started- resp_status: 0x%x\n", status);
    memcpy(&glbl_enc_enabled, enc_enabled, sizeof(rsi_bt_event_encryption_enabled_t));
    rsi_ble_app_set_event(RSI_BLE_ENCRYPT_STARTED_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_le_ltk_req_event
 * @brief      invoked when disconnection event is received
 * @param[in]  resp_disconnect, disconnected remote device information
 * @param[in]  reason, reason for disconnection.
 * @return     none.
 * @section description
 * This callback function indicates disconnected device information and status
 */
static void rsi_ble_on_le_ltk_req_event(rsi_bt_event_le_ltk_request_t *le_ltk_req)
{
    LOG_EVENT("\nrrsi_ble_on_le_ltk_req_event\n");
    memcpy(&temp_le_ltk_req, le_ltk_req, sizeof(rsi_bt_event_le_ltk_request_t));
    rsi_ble_app_set_event(RSI_BLE_LTK_REQ_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_le_security_keys
 * @brief      its invoked when le secure keys events is received.
 * @param[in]  rsi_ble_event_le_security_keys, secure event parameters.
 * @return     none.
 * @section description
 * This callback function is invoked when security keys event is received after encription started.
 */
void rsi_ble_on_le_security_keys(rsi_bt_event_le_security_keys_t *rsi_ble_event_le_security_keys)
{
    memcpy(&app_ble_sec_keys, rsi_ble_event_le_security_keys, sizeof(rsi_bt_event_le_security_keys_t));
    LOG_EVENT("\nrsi_ble_on_encrypt_started- remote_ediv: 0x%x\r\n", app_ble_sec_keys.remote_ediv);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_mtu_event
 * @brief      its invoked when write/notify/indication events are received.
 * @param[in]  event_id, it indicates write/notification event id.
 * @param[in]  rsi_ble_write, write event parameters.
 * @return     none.
 * @section description
 * This callback function is invoked when write/notify/indication events are received
 */
static void rsi_ble_on_mtu_event(rsi_ble_event_mtu_t *rsi_ble_mtu)
{
    LOG_EVENT("\nrsi_ble_on_le_ltk_req_event\n");
    memcpy(&app_ble_mtu_event, rsi_ble_mtu, sizeof(rsi_ble_event_mtu_t));
    rsi_ble_app_set_event(RSI_BLE_MTU_EVENT);
}


/*==============================================*/
/**
 * @fn         rsi_ble_on_gatt_write_event
 * @brief      its invoked when write/notify/indication events are received.
 * @param[in]  event_id, it indicates write/notification event id.
 * @param[in]  rsi_ble_write, write event parameters.
 * @return     none.
 * @section description
 * This callback function is invoked when write/notify/indication events are received
 */
static void rsi_ble_on_gatt_write_event(uint16_t event_id, rsi_ble_event_write_t *rsi_ble_write)
{
    LOG_EVENT("\nrsi_ble_on_gatt_write_event\n");
    (void)event_id; //This statement is added only to resolve compilation warning, value is unchanged
    memcpy(&app_ble_write_event, rsi_ble_write, sizeof(rsi_ble_event_write_t));
    rsi_ble_app_set_event(RSI_BLE_GATT_WRITE_EVENT);
}

void rsi_ble_set_data_len_command(sl_cli_command_arg_t* arguments)
{
    char* remote_dev_addr = sl_cli_get_argument_string(arguments, 0);
    uint16_t tx_len = sl_cli_get_argument_uint16(arguments, 1);
    uint16_t tx_time = sl_cli_get_argument_uint16(arguments, 2);

    uint8_t device_address[6];
	rsi_ascii_dev_address_to_6bytes_rev(device_address, (int8_t*)remote_dev_addr);
    print_status(rsi_ble_set_data_len(device_address,tx_len,tx_time));
}

void rsi_ble_read_max_data_len_command(sl_cli_command_arg_t* arguments)
{
    uint32_t status = 0;
    rsi_ble_read_max_data_length_t blereadmaxdatalen;

    status = rsi_ble_read_max_data_len(&blereadmaxdatalen);
    if(status == 0)
    {
    printf("maxtx_octets:%d, maxtx_time:%d, maxrx_octets:%d, maxrx_time:%d\n",blereadmaxdatalen.maxtxoctets,blereadmaxdatalen.maxtxtime,blereadmaxdatalen.maxrxoctets, blereadmaxdatalen.maxrxtime);
    }
    print_status(status);

}

void rsi_ble_set_phy_command(sl_cli_command_arg_t* arguments)
{
    char* remote_dev_addr = sl_cli_get_argument_string(arguments, 0);
    uint8_t tx_phy = sl_cli_get_argument_uint8(arguments, 1);
    uint8_t rx_phy = sl_cli_get_argument_uint8(arguments, 2);
    uint16_t coded_phy = sl_cli_get_argument_uint16(arguments, 3);

    uint8_t device_address[6];
	rsi_ascii_dev_address_to_6bytes_rev(device_address, (int8_t*)remote_dev_addr);
    print_status(rsi_ble_setphy(device_address,tx_phy,rx_phy,coded_phy));
}

void rsi_ble_read_phy_command(sl_cli_command_arg_t* arguments)
{
    uint32_t status = 0;
    rsi_ble_resp_read_phy_t read_phy_resp;

    char* remote_dev_addr = sl_cli_get_argument_string(arguments, 0);
    uint8_t dev_addr[6];
	rsi_ascii_dev_address_to_6bytes_rev(dev_addr, (int8_t*)remote_dev_addr);
    status = rsi_ble_readphy(dev_addr, &read_phy_resp);
    if(status == 0)
    {
    printf("dev_addr:%02x:%02x:%02x:%02x:%02x:%02x, tx_phy:%d, maxrx_time:%d\n",read_phy_resp.dev_addr[0],read_phy_resp.dev_addr[1],read_phy_resp.dev_addr[2], read_phy_resp.dev_addr[3], read_phy_resp.dev_addr[4], read_phy_resp.dev_addr[5], read_phy_resp.tx_phy, read_phy_resp.rx_phy);
    }
    print_status(status);

}