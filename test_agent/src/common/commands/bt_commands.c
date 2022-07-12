#include "sl_cli.h"
#include "sl_cli_types.h"
#include "sl_cli_arguments.h"
#include "rsi_bt_apis.h"
#include "rsi_bt_common_apis.h"
#include "rsi_bt_common.h"
#include "rsi_bt_config.h"
#include "rsi_bt.h"
#include "rsi_utils.h"
#include "rsi_driver.h"

#include "rsi_data_types.h"
#include "rsi_bt_sdp.h"

#include "string.h"
#include "stdint.h"

#include "rsi_bt_sbc_codec.h"
#include "pcm_data_buff.h"

#define RSI_PRINT_LOGS 0
#if RSI_PRINT_LOGS
#define LOG_PRINT printf
#else
#define LOG_PRINT
#endif

#define RSI_PRINT_EVENTS 1
#if RSI_PRINT_EVENTS
#define LOG_EVENT printf
#else
#define LOG_EVENT
#endif

//General defines
#define RSI_BT_TASK_STACK_SIZE                  (1024/4)
#define RSI_BT_TASK_PRIORITY                    1
#define RSI_DEV_ADDR_LEN                        6
#define RSI_LINKKEY_REPLY_SIZE                  16
#define RSI_DEV_NAME_LEN                        50
#define STACK_BT_MODE                           0x01

//! BT task priority
#define RSI_BT_TASK_PRIORITY                    1

//! APP generic events list
#define RSI_APP_EVENT_INQ_COMPLT	            0
#define RSI_APP_EVENT_INQ_RESP	                1
#define RSI_APP_EVENT_UNBOND	                2
#define RSI_APP_EVENT_QUERY_SERVICES	        3
#define RSI_APP_EVENT_REMOTE_NAME_RESP	        4
#define RSI_APP_EVENT_REMOTE_NAME_CANCEL_RESP	5
#define RSI_APP_EVENT_PASSKEY_DISPLAY	        6
#define RSI_APP_EVENT_PASSKEY_REQUEST	        7
#define RSI_APP_EVENT_MODE_CHANGED	            8
#define RSI_APP_EVENT_SNIFF_SUBRATING	        9
#define RSI_APP_EVENT_ROLE_CHANGE	            10
#define RSI_APP_EVENT_SEARCH_SERVICE	        11
#define RSI_APP_EVENT_CONNECTED	                12
#define RSI_APP_EVENT_PINCODE_REQ	            13
#define RSI_APP_EVENT_LINKKEY_SAVE	            14
#define RSI_APP_EVENT_AUTH_COMPLT	            15
#define RSI_APP_EVENT_DISCONNECTED	            16
#define RSI_APP_EVENT_LINKKEY_REQ	            17
#define RSI_APP_EVENT_CONFIRM_REQUEST	        18
#define RSI_APP_EVENT_SSP_COMPLETE	            19

//! SPP events list
#define RSI_APP_EVENT_SPP_CONN	                20
#define RSI_APP_EVENT_SPP_DISCONN	            21
#define RSI_APP_EVENT_SPP_RX	                22

//! A2DP AVRCP events list
#define RSI_APP_EVENT_A2DP_ABORT	            23
#define RSI_APP_EVENT_A2DP_CLOSE	            24
#define RSI_APP_EVENT_A2DP_SBC_DATA	            25
#define RSI_APP_EVENT_A2DP_PCM_DATA	            26
#define RSI_APP_EVENT_A2DP_CONFIGURE	        27
#define RSI_APP_EVENT_A2DP_OPEN	                28
#define RSI_APP_EVENT_A2DP_CONN	                29
#define RSI_APP_EVENT_A2DP_DISCONN	            30
#define RSI_APP_EVENT_AVRCP_CONN	            31
#define RSI_APP_EVENT_AVRCP_DISCONN	            32
#define RSI_APP_EVENT_AVRCP_PLAY	            33
#define RSI_APP_EVENT_AVRCP_PAUSE	            34
#define RSI_APP_EVENT_AVRCP_GET_REM_CAP	        35
#define RSI_APP_EVENT_AVRCP_GET_CAP	            36
#define RSI_APP_EVENT_AVRCP_GET_ATTS	        37
#define RSI_APP_EVENT_AVRCP_GET_ATT_VALS	    38
#define RSI_APP_EVENT_AVRCP_CUR_ATT_VALS	    39
#define RSI_APP_EVENT_AVRCP_SET_ATT_VALS	    40
#define RSI_APP_EVENT_AVRCP_ATT_TEXT	        41
#define RSI_APP_EVENT_AVRCP_ATT_VALS_TEXT	    42
#define RSI_APP_EVENT_AVRCP_NEXT	            43
#define RSI_APP_EVENT_AVRCP_PREVIOUS	        44
#define RSI_APP_EVENT_AVRCP_SONG_ATTS	        45
#define RSI_APP_EVENT_AVRCP_PLAY_STATUS	        46
#define RSI_APP_EVENT_AVRCP_REG_EVENT	        47
#define RSI_APP_EVENT_A2DP_SUSPEND	            48
#define RSI_APP_EVENT_A2DP_RECONFIG	            49
#define RSI_APP_EVENT_A2DP_START	            50
#define RSI_APP_EVENT_AVRCP_VOL_UP	            51
#define RSI_APP_EVENT_AVRCP_VOL_DOWN	        52
#define RSI_APP_EVENT_AVRCP_SET_ABS_VOL	        53
#define RSI_APP_EVENT_AVRCP_GET_REM_VER	        54
#define RSI_APP_EVENT_AVRCP_NOTIFY	            55
#define RSI_APP_EVENT_A2DP_MORE_DATA_REQ	    56
#define RSI_APP_EVENT_A2DP_SBC_ENCODE	        57


//! Sniff Parameters
#define SNIFF_MAX_INTERVAL 0xA0
#define SNIFF_MIN_INTERVAL 0XA0
#define SNIFF_ATTEMPT      0X04
#define SNIFF_TIME_OUT     0X02

//! Power Save Profile Mode
#define RSI_MAX_PSP 0

					   
#define DEFAULT_MTU_SIZE       310

#define PKT_HEADER_AND_CRC 11 // 11 --> l2cap+controller header + crc
#define RTP_HEADER         13 // 13 --> rtp_header
							 
									 

//! Error codes
/*********************/
#define RSI_APP_ERR_NONE                       0x0000
#define RSI_APP_ERR_SOCK_DISCONN               0x4062
#define RSI_APP_ERR_SOCK_TIMEOUT               0x4063
#define RSI_APP_ERR_SDP_SRV_NOT_FOUND          0x4102
#define RSI_APP_ERR_PAGE_TIMEOUT               0x4E04
#define RSI_APP_ERR_PIN_MISSING                0x4E06
#define RSI_APP_ERR_CONN_TIMEOUT               0x4E08
#define RSI_APP_ERR_ACL_CONN_ALREADY_EXISTS    0x4E0B
#define RSI_APP_ERR_LIMITED_RESOURCE           0x4E0D
#define RSI_APP_ERR_REMOTE_TERMINATED_CONN     0x4E13
#define RSI_APP_ERR_LOCAL_TERMINATED_CONN      0x4E16
#define RSI_APP_ERR_REPEATED_ATTEMPTS          0x4E17
#define RSI_APP_ERR_LMP_RESP_TIMEOUT           0x4E22
#define RSI_APP_ERR_HW_BUFFER_OVERFLOW         0x4057
#define RSI_APP_ERR_HW_BUFFER_OVERFLOW_TIMEOUT 0x405D
#define RSI_APP_ERR_A2DP_CONN_ALRDY_EXISTS     0x4511
#define RSI_APP_ERR_A2DP_NOT_STREAMING         0x4512
#define RSI_APP_ERR_A2DP_INVALID_SOCKET        0x4049
#define RSI_APP_ERR_A2DP_SBC_SAME_CODEC_PARAMS 0x4513
#define RSI_APP_ERR_A2DP_RECONFIG_CMD_TIMEOUT  0x4514

#define RSI_APP_ERR_A2DP_SBC_BUFF_OVERFLOW  0xA1
#define RSI_APP_ERR_A2DP_SBC_BUFF_UNDERFLOW 0xA2
#define RSI_APP_ERR_INVALID_INPUT           0xA3
#define RSI_APP_ERR_AUDIO_EOF               0xA0

#define BT_AVRCP_MEDIA_ATTR_ID_MEDIA_TITLE     0x01
#define BT_AVRCP_MEDIA_ATTR_ID_ARTIST_NAME     0x02
#define BT_AVRCP_MEDIA_ATTR_ID_ALBUM_NAME      0x03
#define BT_AVRCP_MEDIA_ATTR_ID_TRACK_NUM       0x04
#define BT_AVRCP_MEDIA_ATTR_ID_NUM_OF_TRACK    0x05
#define BT_AVRCP_MEDIA_ATTR_ID_GENRE           0x06
#define BT_AVRCP_MEDIA_ATTR_ID_PLAYING_TIME_MS 0x07

#define AVRCP_EVENT_PLAYBACK_STATUS_CHANGED            0x01
#define AVRCP_EVENT_TRACK_CHANGED                      0x02
#define AVRCP_EVENT_TRACK_REACHED_END                  0x03
#define AVRCP_EVENT_TRACK_REACHED_START                0x04
#define AVRCP_EVENT_PLAYBACK_POS_CHANGED               0x05
#define AVRCP_EVENT_BATT_STATUS_CHANGED                0x06
#define AVRCP_EVENT_SYSTEM_STATUS_CHANGED              0x07
#define AVRCP_EVENT_PLAYER_APPLICATION_SETTING_CHANGED 0x08
#define AVRCP_EVENT_NOW_PLAYING_CONTENT_CHANGED        0x09
#define AVRCP_EVENT_AVAILABLE_PLAYERS_CHANGED          0x0a
#define AVRCP_EVENT_ADDRESSED_PLAYER_CHANGED           0x0b
#define AVRCP_EVENT_UIDS_CHANGED                       0x0c
#define AVRCP_EVENT_VOLUME_CHANGED                     0x0d

#define AVRCP_CAP_ID_COMPANY_ID       0x2
#define AVRCP_CAP_ID_EVENTS_SUPPORTED 0x3

#define SAMPLE_ARTIST_NAME  "SAMPLE_ARTIST_NAME"
#define SAMPLE_ALBUM_NAME   "SAMPLE_ALBUM_NAME"
#define SAMPLE_GENRE        "SAMPLE_GENRE"

#define PCM_DATA_LEN_PER_MS (44100 * 2 * 2)

#define BT_AVRCP_MEDIA_ATTR_ID_MAX_COUNT 0x07
#define SONG_LIST_MAX_COUNT 3


/*********** BEGIN OF CALLBACKS DECLARATIONS *******************/
static void rsi_bt_app_init_events();
static void rsi_bt_app_set_event(uint32_t event_num);
static void rsi_bt_app_clear_event(uint32_t event_num);
static int32_t rsi_bt_app_get_event(void);

// GAP Callbacks
void rsi_bt_on_conn_status_event(uint16_t resp_status, rsi_bt_event_bond_t *bond_response);
void rsi_bt_on_unbond_status_event(uint16_t resp_status, rsi_bt_event_unbond_t *unbond_status);
void rsi_bt_on_pincode_req_event(uint16_t resp_status, rsi_bt_event_user_pincode_request_t *user_pincode_request);
void rsi_bt_on_linkkey_req_event(uint16_t resp_status, rsi_bt_event_user_linkkey_request_t *user_linkkey_request);
void rsi_bt_on_linkkey_save_event(uint16_t status, rsi_bt_event_user_linkkey_save_t *user_linkkey_save);
void rsi_bt_on_inq_complete_event(uint16_t resp_status);
void rsi_bt_on_auth_complete_event(uint16_t resp_status, rsi_bt_event_auth_complete_t *auth_complete);
void rsi_bt_on_remote_name_resp_event(uint16_t resp_status, rsi_bt_event_remote_device_name_t *remote_name);
void rsi_bt_on_remote_name_cancel_resp_event(uint16_t resp_status,
                                           rsi_bt_event_remote_name_request_cancel_t *remote_name_cancel);
void rsi_bt_on_inq_resp_event(uint16_t resp_status, rsi_bt_event_inquiry_response_t *inq_resp);
void rsi_bt_on_disconn_event(uint16_t resp_status, rsi_bt_event_disconnect_t *bt_disconnected);
void rsi_bt_on_query_services_event(uint16_t resp_status, rsi_bt_resp_query_services_t *query_services);
void rsi_bt_on_search_service_event (uint16_t resp_status, uint8_t *remote_dev_addr, uint8_t status);
void rsi_bt_on_passkey_display_event(uint16_t resp_status, rsi_bt_event_user_passkey_display_t *bt_event_user_passkey_display);
void rsi_bt_on_confirm_request_event(uint16_t resp_status,
                         rsi_bt_event_user_confirmation_request_t *user_confirmation_request);
void rsi_bt_on_passkey_request_event(uint16_t resp_status, rsi_bt_event_user_passkey_request_t *user_passkey_request);
void rsi_bt_on_ssp_complete_event(uint16_t resp_status, rsi_bt_event_ssp_complete_t *ssp_complete);
void rsi_bt_on_mode_change_event (uint16_t resp_status, rsi_bt_event_mode_change_t  *mode_change);
void rsi_bt_on_sniff_subrating_event (uint16_t resp_status,rsi_bt_event_sniff_subrating_t  *mode_change);

//SPP Callbacks
void rsi_bt_on_spp_connect(uint16_t resp_status, rsi_bt_event_spp_connect_t *spp_connect);
void rsi_bt_on_spp_disconnect(uint16_t resp_status, rsi_bt_event_spp_disconnect_t *spp_disconn);
void rsi_bt_on_spp_data_rx(uint16_t resp_status, rsi_bt_event_spp_receive_t *spp_receive);

//A2DP Callbacks
void rsi_bt_on_a2dp_connect(uint16_t resp_status, rsi_bt_event_a2dp_connect_t *a2dp_connect);
void rsi_bt_on_a2dp_disconnect(uint16_t resp_status, rsi_bt_event_a2dp_disconnect_t *a2dp_disconnect);
void rsi_bt_on_a2dp_configure(uint16_t resp_status, rsi_bt_event_a2dp_configure_t *a2dp_configure);
void rsi_bt_on_a2dp_open(uint16_t resp_status, rsi_bt_event_a2dp_open_t *a2dp_oen);
void rsi_bt_on_a2dp_start(uint16_t resp_status, rsi_bt_event_a2dp_start_t *a2dp_start);
void rsi_bt_on_a2dp_suspend(uint16_t resp_status, rsi_bt_event_a2dp_suspend_t *a2dp_suspend);
void rsi_bt_on_a2dp_abort(uint16_t resp_status, rsi_bt_event_a2dp_abort_t *a2dp_abort);
void rsi_bt_on_a2dp_close(uint16_t resp_status, rsi_bt_event_a2dp_close_t *a2dp_close);
void rsi_bt_on_a2dp_encode_data(uint16_t resp_status, rsi_bt_event_a2dp_encode_data_t *a2dp_encode_data);
void rsi_bt_on_a2dp_pcm_data(uint16_t resp_status, rsi_bt_event_a2dp_pcm_data_t *a2dp_pcm_data);
void rsi_bt_on_a2dp_more_data_req(uint16_t resp_status, rsi_bt_event_a2dp_more_data_req_t *a2dp_more_data_req);
void rsi_bt_on_a2dp_reconfig(uint16_t resp_status, rsi_bt_event_a2dp_reconfig_t *a2dp_reconfig);
void rsi_bt_app_on_avrcp_connect(uint16_t resp_status, rsi_bt_event_avrcp_connect_t *avrcp_connect);
void rsi_bt_app_on_avrcp_disconnect(uint16_t resp_status, rsi_bt_event_avrcp_disconnect_t *avrcp_disconn);
void rsi_bt_app_on_avrcp_play(uint16_t resp_status, rsi_bt_event_avrcp_play_t *avrcp_play);
void rsi_bt_app_on_avrcp_pause(uint16_t resp_status, rsi_bt_event_avrcp_pause_t *avrcp_pause);
void rsi_bt_app_on_avrcp_stop(uint16_t resp_status, rsi_bt_event_avrcp_stop_t *avrcp_stop);
void rsi_bt_app_on_avrcp_next(uint16_t resp_status, rsi_bt_event_avrcp_next_t *avrcp_next);
void rsi_bt_app_on_avrcp_previous(uint16_t resp_status, rsi_bt_event_avrcp_previous_t *avrcp_prev);
void rsi_bt_app_on_avrcp_vol_up(uint16_t resp_status, rsi_bt_event_avrcp_vol_up_t *avrcp_vol_up);
void rsi_bt_app_on_avrcp_vol_down(uint16_t resp_status, rsi_bt_event_avrcp_vol_down_t *avrcp_vol_down);
void rsi_bt_on_avrcp_set_app_cur_att_val_event(rsi_bt_event_avrcp_set_att_val_t *p_att_list);
void rsi_bt_on_avrcp_get_app_att_text_event(rsi_bt_event_avrcp_get_cur_att_val_t *p_att_text_list);
void rsi_bt_on_avrcp_get_app_att_vals_text_event(rsi_bt_event_avrcp_vals_text_req_t *p_vals_list);
void rsi_bt_on_avrcp_notify_event(uint16_t resp_status, rsi_bt_event_avrcp_notify_t *p_notify);
uint8_t app_cap_type;
uint8_t app_att_id;
rsi_bt_event_avrcp_ele_att_t app_song_atts;
rsi_bt_event_avrcp_get_cur_att_val_t app_att_list;
rsi_bt_event_avrcp_get_cur_att_val_t app_att_text_list;
rsi_bt_event_avrcp_vals_text_req_t app_vals_list;

void rsi_bt_on_avrcp_get_cap_event(uint8_t *bd_addr, uint8_t cap_type);
void rsi_bt_on_avrcp_get_app_supp_atts_event(uint8_t *bd_addr);
void rsi_bt_on_avrcp_get_app_suup_att_vals_event(uint8_t *bd_addr, uint8_t att_id);
void rsi_bt_on_avrcp_get_app_cur_att_val_event(rsi_bt_event_avrcp_get_cur_att_val_t *p_att_list);
void rsi_bt_on_avrcp_get_song_atts_event(rsi_bt_event_avrcp_ele_att_t *p_song_atts);
void rsi_bt_on_avrcp_get_play_status_event(uint8_t *bd_addr);
uint8_t app_event_id[5];
uint8_t app_reg_events;
void rsi_bt_on_avrcp_reg_notify_event(uint8_t *bd_addr, uint8_t event_id);
void rsi_bt_on_avrcp_set_abs_vol_event(rsi_bt_event_avrcp_set_abs_vol_t *p_abs_vol);

void rsi_bt_on_role_change_event(uint16_t resp_status, rsi_bt_event_role_change_t *role_change_status);
/*********** END OF CALLBACKS DECLARATIONS *******************/


/*********** BEGIN OF Variables *******************/
static rsi_task_handle_t bt_task_handle = NULL;
static uint32_t bt_rsi_app_async_event_map        = 0;
static uint32_t bt_rsi_app_async_event_map1        = 0;

static uint8_t bt_str_conn_bd_addr[18];
static uint8_t bt_remote_dev_addr[RSI_DEV_ADDR_LEN] = { 0 };
static uint8_t bt_data[RSI_BT_MAX_PAYLOAD_SIZE];
static uint16_t bt_data_len;
static uint8_t sniff_mode;

static rsi_bt_event_inquiry_response_t bt_rsi_bt_inquiry_response = { 0 };
static rsi_bt_event_remote_device_name_t bt_remote_device_name    = { 0 };
static attr_list_t attr_list[BT_AVRCP_MEDIA_ATTR_ID_MAX_COUNT] = { 0 };
static rsi_bt_resp_query_services_t bt_resp_query_services     = { 0 };
static int8_t bt_rsi_app_resp_rssi                                = 0;
static uint8_t pin_code[RSI_MAX_PINCODE_REPLY_SIZE] = { '0', '0', '0', '0' };

uint8_t linkkey_bt[RSI_LINKKEY_REPLY_SIZE];
uint16_t NbrBytesReqd;
uint16_t sample_freq;
uint8_t abs_vol;
uint8_t play_status;
uint16_t headset_max_mtu_size = 0;
uint16_t rem_mtu_size = DEFAULT_MTU_SIZE;
uint8_t first_buff_overflow = 1;
uint8_t underflow           = 0;
uint16_t overflow_count = 0, bt_disable_triggered = 0;
uint32_t pcm_data_buff_size = sizeof(pcm_data_buff);
static uint32_t bytes_to_read;
static uint8_t frame_size;
static uint8_t no_of_sbc_frames;
static uint8_t no_of_channels;
static uint8_t no_of_subbands;
static uint8_t no_of_blocks;

rsi_bt_a2dp_sbc_codec_cap_t audio_codec_cap = { SBC_CHANNEL_MODE_JOINT_STEREO,
                                                SBC_SAMPLING_FREQ_44100,
                                                SBC_ALLOCATION_LOUDNESS,
                                                SBC_SUBBANDS_8,
                                                SBC_BLOCK_LENGTH_16,
                                                SBC_MIN_BITPOOL,
                                                53 };

static rsi_bt_a2dp_sbc_codec_cap_t set_sbc_cap;
static rsi_bt_resp_a2dp_get_config_t sbc_resp_cap;
static rsi_bt_event_avrcp_notify_t avrcp_notify;
static uint32_t avrcp_version;

typedef enum {
  INQUIRY,
  CONNECTED,
  AUTHENTICATED,
  A2DP_CONNECTED,
  A2DP_STREAM_OPEN,
  A2DP_STREAM_START,
  AVRCP_CONNECTED,
} app_state_t;
app_state_t app_state                          = 0;

rsi_semaphore_handle_t bt_thread_sem;

typedef enum {
    BT_MASTER_ROLE = 0,
    BT_SLAVE_ROLE = 1
} rsi_bt_role_t;
static rsi_bt_role_t current_bt_role;

typedef enum {
    BT_DEFAULT = 0,
    BT_SPP = 1,
    BT_A2DP_SRC = 2,
    BT_A2DP_AVRCP_SRC = 3
} rsi_bt_profile_t;
static rsi_bt_profile_t current_profile;

static uint32_t pcm_offset = 0;

/*********** END OF Variables *******************/


/*********** BEGIN OF HELPER FUNCTIONS *******************/
int32_t rsi_bt_app_sbc_encode()
{
    int16_t err             = 0;
    uint16_t bytes_consumed = 0;

    if (pcm_offset + bytes_to_read <= sizeof(pcm_data_buff)) {
        uint8_t *pcm_data_ptr = pcm_data_buff + pcm_offset;

        LOG_PRINT("\nSending rsi_bt_sbc_encode");
        LOG_PRINT("\npcm_data_buff pcm_offset: %d | pcm_data_ptr: %d | bytes_to_read: %d | bytes_consumed: %d\n",
                        pcm_offset, pcm_data_ptr, bytes_to_read, bytes_consumed);

        err = rsi_bt_sbc_encode(bt_remote_dev_addr, pcm_data_ptr, bytes_to_read, &bytes_consumed);
        pcm_offset += bytes_to_read;

        if (pcm_offset >= sizeof(pcm_data_buff)) //check whether offset reaches to end of the array
        {
         return RSI_APP_ERR_AUDIO_EOF;
        }
    } else { //skip the last chunk since it is less than bytes_to_read
        return RSI_APP_ERR_AUDIO_EOF;
    }
    if (err)
        return err;

    return 0;
}

int32_t rsi_bt_a2dp_start_sbc_encoding(){
    LOG_PRINT("\nSending rsi_bt_app_sbc_encode\n");
    int16_t status = rsi_bt_app_sbc_encode();
    LOG_PRINT(status);

    if (status == RSI_APP_ERR_AUDIO_EOF) {
        //reset_audio_params (); //! wlan_bt glitch.
        //! close current and open next song
        //Since we are using byte array we have to set the offset to 0
        pcm_offset = 0;
        rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_MORE_DATA_REQ);
    } else if ((status == RSI_SUCCESS) || (status == RSI_APP_ERR_INVALID_INPUT)) {
        rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_SBC_ENCODE);
        if (underflow) {
            rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_MORE_DATA_REQ);
            underflow = 0;
        }
    } else if (status == RSI_APP_ERR_A2DP_SBC_BUFF_OVERFLOW) {
        if (first_buff_overflow) {
            rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_MORE_DATA_REQ);
            first_buff_overflow = 0;
        }
    }
    return status;
}

int32_t calculate_sbc_frame_size(rsi_bt_a2dp_sbc_codec_cap_t *sbc_cap)
{
    int32_t ret = 0;
    uint8_t block_mode, mode, subband_mode, subbands, channels, blocks, joint, bitpool;

    block_mode = sbc_cap->BlockLength;
    switch (block_mode) {
        default:
        case SBC_BLOCK_LENGTH_4:
            blocks = 4;
            break;
        case SBC_BLOCK_LENGTH_8:
            blocks = 8;
            break;
        case SBC_BLOCK_LENGTH_12:
            blocks = 12;
            break;
        case SBC_BLOCK_LENGTH_16:
            blocks = 16;
            break;
    }

    mode = sbc_cap->ChannelMode;
    switch (mode) {
        default:
        case SBC_CHANNEL_MODE_MONO:
            channels = 1;
            break;
        case SBC_CHANNEL_MODE_DUAL_CHANNEL: /* fall-through */
        case SBC_CHANNEL_MODE_STEREO:
        case SBC_CHANNEL_MODE_JOINT_STEREO:
            channels = 2;
            break;
    }

    subband_mode = sbc_cap->SubBands;
    switch (subband_mode) {
        default:
        case SBC_SUBBANDS_4:
            subbands = 4;
            break;
        case SBC_SUBBANDS_8:
            subbands = 8;
            break;
    }

    bitpool = sbc_cap->MaxBitPool;

    if ((mode == SBC_CHANNEL_MODE_MONO || mode == SBC_CHANNEL_MODE_DUAL_CHANNEL) && (bitpool > (16 * subbands)))
        return -4;

    if ((mode == SBC_CHANNEL_MODE_STEREO || mode == SBC_CHANNEL_MODE_JOINT_STEREO) && (bitpool > (32 * subbands)))
        return -4;

    joint = mode == SBC_CHANNEL_MODE_JOINT_STEREO ? 1 : 0;

    ret = 4 + (4 * subbands * channels) / 8;
    /* This term is not always evenly divide so we round it up */
    if (channels == 1)
        ret += ((blocks * channels * bitpool) + 7) / 8;
    else
        ret += (((joint ? subbands : 0) + blocks * bitpool) + 7) / 8;

    return ret;
}

void rsi_bt_app_a2dp_pause()
{
    int32_t status = 0;
    status         = rsi_bt_a2dp_suspend(bt_remote_dev_addr);
    if (status != RSI_SUCCESS) {
        LOG_EVENT("\nrsi_bt_app_a2dp_pause- bt_str_conn_bd_addr: %s, status err: 0x%x\n", bt_str_conn_bd_addr, status);
    } else {
        app_state &= ~(1 << A2DP_STREAM_START);
        rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_MORE_DATA_REQ);
    }
}

void rsi_bt_app_a2dp_resume()
{
    int32_t status = 0;
    status = rsi_bt_a2dp_start((uint8_t *)bt_remote_dev_addr);
    if (status != RSI_SUCCESS) {
        LOG_EVENT("\nrsi_bt_app_a2dp_resume: bt_str_conn_bd_addr: %s, status err: 0x%x\n", bt_str_conn_bd_addr, status);
    } else {
        /*
            * 0x00 Active Mode.
            * 0x01 Hold Mode.
            * 0x02 Sniff Mode. */
        if (sniff_mode == 0x02) {
            rsi_bt_sniff_exit_mode(bt_remote_dev_addr);
        }
        app_state |= (1 << A2DP_STREAM_START);
        rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_MORE_DATA_REQ);
    }
}

static void bt_task(void* arg)
{
    int32_t status = 0;
    int32_t temp_event_map = 0;
    uint8_t i               = 0;
    uint32_t cap[3] = { 0 };
    uint8_t ix;
    notify_val_t notify = { 0 };
    uint8_t atts[5] = { 1 };
    uint8_t vals[5] = { 0, 1 };

    while (1) {
        // checking for received events
        temp_event_map = rsi_bt_app_get_event();
        if (temp_event_map == RSI_FAILURE) {
            // if events are not received loop will be continued.
            rsi_semaphore_wait(&bt_thread_sem, 0);
            continue;
        }

        // if any event is received, it will be served.
        switch (temp_event_map) {
            case RSI_APP_EVENT_CONNECTED:
                //! remote device connected event
                LOG_EVENT("\nRSI_APP_EVENT_CONNECTED \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_CONNECTED);
                app_state |= (1 << CONNECTED);
                break;
            case RSI_APP_EVENT_UNBOND:
                //! unbound event
                LOG_EVENT("\nRSI_APP_EVENT_UNBOND \n");
																	 
																
                rsi_bt_app_clear_event(RSI_APP_EVENT_UNBOND);
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_MORE_DATA_REQ);
                rsi_bt_app_set_event(RSI_APP_EVENT_DISCONNECTED);   
                app_state = 0;
                break;
                // remote device disconnected event
            case RSI_APP_EVENT_PINCODE_REQ:
                //! Pin code request event
                LOG_EVENT("\nRSI_APP_EVENT_PINCODE_REQ \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_PINCODE_REQ);                
                print_status(rsi_bt_pincode_request_reply((uint8_t *)bt_remote_dev_addr,(uint8_t *)&pin_code, 1));
                break;
            case RSI_APP_EVENT_LINKKEY_REQ:
                //! Link_key_request_event
                LOG_EVENT("\nRSI_APP_EVENT_LINKKEY_REQ \n");             
                rsi_bt_app_clear_event(RSI_APP_EVENT_LINKKEY_REQ);
                if ((linkkey_bt[0] == 0) && (linkkey_bt[15] == 0)) {
                    LOG_PRINT("\nRSI_APP_EVENT_LINKKEY_REQ negative reply\n");
                    //! sending the linkkey request negative reply
                    rsi_bt_linkkey_request_reply((uint8_t *)bt_remote_dev_addr, NULL, 0);
                } else {
                    LOG_PRINT("\nRSI_APP_EVENT_LINKKEY_REQ positive reply\n");
                    //! sending the linkkey request positive reply
                    rsi_bt_linkkey_request_reply((uint8_t *)bt_remote_dev_addr, linkkey_bt, 1);
                }
                break;
            case RSI_APP_EVENT_LINKKEY_SAVE:
                //! Link_key_save_event
                LOG_EVENT("\nRSI_APP_EVENT_LINKKEY_SAVE \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_LINKKEY_SAVE);
                break;
            case RSI_APP_EVENT_REMOTE_NAME_RESP:
                //! Remote_name_req_event
                LOG_EVENT("\nRSI_APP_EVENT_REMOTE_NAME_RESP \n");
                //LOG_PRINT("\nRemote device name %s\n" bt_remote_device_name.remote_device_name);
                rsi_bt_app_clear_event(RSI_APP_EVENT_REMOTE_NAME_RESP);
                break;
            case RSI_APP_EVENT_REMOTE_NAME_CANCEL_RESP:
                //!Remote_name_req_cancel_event
                LOG_EVENT("\nRSI_APP_EVENT_REMOTE_NAME_CANCEL_RESP \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_REMOTE_NAME_CANCEL_RESP);
                break;
            case RSI_APP_EVENT_INQ_COMPLT:
                //!RSI_APP_EVENT_INQ_COMPLT
                LOG_EVENT("\nRSI_APP_EVENT_INQ_COMPLT \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_INQ_COMPLT);
                break;
            case RSI_APP_EVENT_INQ_RESP:
                //!Inquiry_resp_event
                rsi_bt_app_clear_event(RSI_APP_EVENT_INQ_RESP);  
		        LOG_EVENT("RSI_APP_EVENT_INQ_RESP- Inquiry_type = %d, COD = %x%x%x, RSSI : %d, len: %d, name: %s",bt_rsi_bt_inquiry_response.inquiry_type,bt_rsi_bt_inquiry_response.cod[2],bt_rsi_bt_inquiry_response.cod[1],bt_rsi_bt_inquiry_response.cod[0],bt_rsi_bt_inquiry_response.rssi,bt_rsi_bt_inquiry_response.name_length,bt_rsi_bt_inquiry_response.remote_device_name);              
                LOG_EVENT("\nRSI_APP_EVENT_INQ_RESP- Remote_device_addr-");
                for (i = 0; i < 6; i++) 
                {
                	LOG_EVENT("%02X", bt_rsi_bt_inquiry_response.dev_addr[5-i]);
                	if(i<5)
                	{
                		LOG_EVENT(":");
                	}
                	if(i==5)
                	{
                		LOG_EVENT("\n");
                	}
                }                
                break;
            case RSI_APP_EVENT_AUTH_COMPLT:
                //! Auth_complete
                LOG_EVENT("\nRSI_APP_EVENT_AUTH_COMPLT \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_AUTH_COMPLT);
                app_state |= (1 << AUTHENTICATED);
                if(current_bt_role == BT_MASTER_ROLE && current_profile == BT_SPP){
                    //! send bt spp connect only in Master mode
                    LOG_PRINT("\nSending rsi_bt_spp_connect\n");
                    print_status(rsi_bt_spp_connect(bt_remote_dev_addr));
                }
                if(current_bt_role == BT_MASTER_ROLE && (current_profile == BT_A2DP_SRC || current_profile == BT_A2DP_AVRCP_SRC)){
                    //! send bt A2DP connect only in Master mode
                    LOG_PRINT("\nSending rsi_bt_a2dp_connect\n");
                    print_status(rsi_bt_a2dp_connect(bt_remote_dev_addr));
                }
                break;
            case RSI_APP_EVENT_QUERY_SERVICES:
                //! Query_services_complete
                LOG_EVENT("\nRSI_APP_EVENT_QUERY_SERVICES \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_QUERY_SERVICES);
                break;
            case RSI_APP_EVENT_DISCONNECTED:
                //! Disconnected_event.
                LOG_EVENT("\nRSI_APP_EVENT_DISCONNECTED \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_DISCONNECTED);
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_MORE_DATA_REQ);
                app_state        = 0;
                rem_mtu_size     = DEFAULT_MTU_SIZE;
                break;
            case RSI_APP_EVENT_A2DP_CONN:
                //! a2dp connected event
                //! clear the a2dp connected event.
                LOG_EVENT("\nRSI_APP_EVENT_A2DP_CONN \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_CONN);
                break;
            case RSI_APP_EVENT_A2DP_DISCONN:
                //! a2dp disconnected event
                //! clear the a2dp disconnected event.
                LOG_EVENT("\nRSI_APP_EVENT_A2DP_DISCONN \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_DISCONN);
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_MORE_DATA_REQ);
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_SBC_ENCODE);
                reset_audio_params();
                break;
            case RSI_APP_EVENT_A2DP_OPEN:
                //! a2dp open event
                //! clear the a2dp open event.
                LOG_EVENT("\nRSI_APP_EVENT_A2DP_OPEN \n");
                rsi_bt_app_clear_event (RSI_APP_EVENT_A2DP_OPEN);
                /* Get Config Command */
                LOG_PRINT("\nSending rsi_bt_a2dp_get_config\n");
                rsi_bt_a2dp_get_config(bt_remote_dev_addr, &sbc_resp_cap);
                LOG_PRINT("\nOLD_CONFIG: ChannelMode=%d | Freq=%d | ",
                        sbc_resp_cap.sbc_cap.ChannelMode,
                        sbc_resp_cap.sbc_cap.Freq);
                LOG_PRINT("AllocMethod=%d | SubBands=%d | ", sbc_resp_cap.sbc_cap.AllocMethod, sbc_resp_cap.sbc_cap.SubBands);
                LOG_PRINT("MinBitPool=%d | MaxBitPool=%d | ", sbc_resp_cap.sbc_cap.MinBitPool, sbc_resp_cap.sbc_cap.MaxBitPool);
                LOG_PRINT("BlockLength=%d\n", sbc_resp_cap.sbc_cap.BlockLength);
                memcpy(&set_sbc_cap, &sbc_resp_cap.sbc_cap, sizeof(set_sbc_cap));
                /* Use Macros from rsi_sbc_codec.h */
                set_sbc_cap.Freq        = SBC_SAMPLING_FREQ_44100;
                set_sbc_cap.ChannelMode = SBC_CHANNEL_MODE_JOINT_STEREO;
                set_sbc_cap.AllocMethod = SBC_ALLOCATION_LOUDNESS;
                set_sbc_cap.SubBands    = SBC_SUBBANDS_8;
                set_sbc_cap.BlockLength = SBC_BLOCK_LENGTH_16;
                set_sbc_cap.MaxBitPool  = 53;

                rsi_delay_ms(500);
                LOG_PRINT("\nSending rsi_bt_a2dp_set_config\n");
                status = rsi_bt_a2dp_set_config(bt_remote_dev_addr, &set_sbc_cap, NULL);
                print_status(status);
                if (status == RSI_APP_ERR_A2DP_SBC_SAME_CODEC_PARAMS) {
                    if (!(app_state & (1 << A2DP_STREAM_START))) {
                        rsi_delay_ms(1000);
                        LOG_PRINT("\nSending rsi_bt_a2dp_start\n");
                        print_status(rsi_bt_a2dp_start(bt_remote_dev_addr));
                    }
                }
                break;
            case RSI_APP_EVENT_A2DP_CONFIGURE:
                // //! a2dp configure event
                // //! clear the a2dp configure event.
                LOG_EVENT("\nRSI_APP_EVENT_A2DP_CONFIGURE \n");
                rsi_bt_app_clear_event (RSI_APP_EVENT_A2DP_CONFIGURE);
                break;
            case RSI_APP_EVENT_A2DP_START:
                //! a2dp start event
                //! clear the a2dp start event.
                LOG_EVENT("\nRSI_APP_EVENT_A2DP_START \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_START);
                if(current_bt_role == BT_MASTER_ROLE && current_profile == BT_A2DP_AVRCP_SRC){
                    if (!(app_state & (1 << AVRCP_CONNECTED))) {
                        LOG_PRINT("\nSending rsi_bt_avrcp_conn\n");
                        status = rsi_bt_avrcp_conn(bt_remote_dev_addr);
                        if (status != RSI_SUCCESS) {
                            LOG_PRINT("\navrcp conn resp status 0x%04x\n", status);
                        }
                        print_status(status);
                        rsi_delay_ms(500);
                    }
                }
                /* Get Config Command */
                LOG_PRINT("\nSending rsi_bt_a2dp_get_config\n");
                print_status(rsi_bt_a2dp_get_config(bt_remote_dev_addr, &sbc_resp_cap));
                LOG_PRINT("\nNEW_CONFIG: ChannelMode=%d | Freq=%d | ",
                        sbc_resp_cap.sbc_cap.ChannelMode,
                        sbc_resp_cap.sbc_cap.Freq);
                LOG_PRINT("AllocMethod=%d | SubBands=%d | ", sbc_resp_cap.sbc_cap.AllocMethod, sbc_resp_cap.sbc_cap.SubBands);
                LOG_PRINT("MinBitPool=%d | MaxBitPool=%d | ", sbc_resp_cap.sbc_cap.MinBitPool, sbc_resp_cap.sbc_cap.MaxBitPool);
                LOG_PRINT("BlockLength=%d\n", sbc_resp_cap.sbc_cap.BlockLength);
                /* ReInit SBC */
                memcpy(&set_sbc_cap, &sbc_resp_cap.sbc_cap, sizeof(rsi_bt_a2dp_sbc_codec_cap_t));
                LOG_PRINT("\nSending rsi_bt_cmd_sbc_reinit\n");
                rsi_bt_cmd_sbc_reinit((void *)&set_sbc_cap);
                /* Get Number of Channels */
                if (set_sbc_cap.ChannelMode == SBC_CHANNEL_MODE_MONO)
                no_of_channels = 1;
                else
                no_of_channels = 2;

                /* Get Number of Blocks */
                if (set_sbc_cap.BlockLength == SBC_BLOCK_LENGTH_4)
                no_of_blocks = 4;
                else if (set_sbc_cap.BlockLength == SBC_BLOCK_LENGTH_8)
                no_of_blocks = 8;
                else if (set_sbc_cap.BlockLength == SBC_BLOCK_LENGTH_12)
                no_of_blocks = 12;
                else if (set_sbc_cap.BlockLength == SBC_BLOCK_LENGTH_16)
                no_of_blocks = 16;

                /* Get Number of Subbands */
                if (set_sbc_cap.SubBands == SBC_SUBBANDS_4)
                no_of_subbands = 4;
                else
                no_of_subbands = 8;

                /* Calculate PCM bytes to read according to SBC codec config */
                frame_size          = calculate_sbc_frame_size((rsi_bt_a2dp_sbc_codec_cap_t *)&(set_sbc_cap));
                no_of_sbc_frames    = (rem_mtu_size - PKT_HEADER_AND_CRC - RTP_HEADER) / frame_size;
                bytes_to_read       = no_of_sbc_frames * (no_of_blocks * no_of_subbands * no_of_channels * 2);
                LOG_PRINT("\nFrame_size=%d | no_of_sbc_frames=%d | no_of_blocks=%d | no_of_subbands=%d | no_of_channels=%d",
                        frame_size, no_of_sbc_frames, no_of_blocks, no_of_subbands, no_of_channels);
                first_buff_overflow = 1;
                //! clear the a2dp start event.
                
                // The reference example has the following lines here. 
                // But we will call the encode manually using bt_a2dp_start_sbc_streaming manually 
                // rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_SBC_ENCODE);
                // rsi_delay_ms(500);
                // LOG_PRINT("\nA2DP Send Audio\n");
                LOG_PRINT("\nSending reset_audio_params\n");
                reset_audio_params();
                break;
            case RSI_APP_EVENT_A2DP_SUSPEND:
                //! a2dp suspend event
                //! clear the a2dp suspend event.
                LOG_EVENT("\nRSI_APP_EVENT_A2DP_SUSPEND \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_SUSPEND);
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_MORE_DATA_REQ);
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_SBC_ENCODE);
                break;
            case RSI_APP_EVENT_A2DP_RECONFIG:
                //! a2dp reconfig event
                LOG_EVENT("\nRSI_APP_EVENT_A2DP_RECONFIG \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_RECONFIG);
                if (!(app_state & (1 << A2DP_STREAM_START))) {
                    rsi_delay_ms(1000);
                    LOG_PRINT("\nSending rsi_bt_a2dp_start\n");
                    print_status(rsi_bt_a2dp_start(bt_remote_dev_addr));
                }
            break;
            case RSI_APP_EVENT_A2DP_SBC_ENCODE:
                LOG_PRINT("\nRSI_APP_EVENT_A2DP_SBC_ENCODE \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_SBC_ENCODE);
                status = rsi_bt_a2dp_start_sbc_encoding();
                LOG_PRINT(status);
                break;
            case RSI_APP_EVENT_A2DP_MORE_DATA_REQ:
                //! a2dp more data event
                LOG_PRINT("\nRSI_APP_EVENT_A2DP_MORE_DATA_REQ \n");
                if (!(app_state & (1 << CONNECTED)) && !(app_state & (1 << A2DP_CONNECTED))) {
                    rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_SBC_ENCODE);
                    rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_MORE_DATA_REQ);
                    break;
                }
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_MORE_DATA_REQ);

                LOG_PRINT("\nSending rsi_bt_app_send_sbc_data\n");
                status = rsi_bt_app_send_sbc_data();
                LOG_PRINT(status);

                rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_SBC_ENCODE);

                if (status == RSI_SUCCESS) {
                    rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_MORE_DATA_REQ);
                } else if (status == RSI_APP_ERR_A2DP_SBC_BUFF_UNDERFLOW) {
                    underflow = 1;
                } else if (status == RSI_APP_ERR_HW_BUFFER_OVERFLOW) {
                    overflow_count++;
                //Do Nothing
                } else if (status == RSI_APP_ERR_HW_BUFFER_OVERFLOW_TIMEOUT) {
                    LOG_PRINT("\n Buffer Overflow Timeout: 0x%x \n", status);
                    rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_MORE_DATA_REQ);
                } else if (status == RSI_APP_ERR_A2DP_INVALID_SOCKET) {
                    LOG_PRINT("\n Invalid Socket Error: 0x%x\n", status);
                    /*This invalid socket error comes when there is no l2cap cfg response from remote device for stream socket.
                    i.e, A2DP stream socket conn is not completed although A2DP Conn socket is completed.*/
                    LOG_PRINT("\n Initiating profile level reconn: \n");
                    status = rsi_bt_a2dp_disconnect(bt_remote_dev_addr);
                    if (status != RSI_SUCCESS) {
                        LOG_PRINT("\n A2DP Disconn Failed: %x\n", status);
                    }
                    app_state &= ~(1 << A2DP_STREAM_START);
                    break;
                } else {
                    first_buff_overflow = 1;
                    LOG_PRINT("\n send SBC command status: 0x%x \n", status);
                }
                break;
            case RSI_APP_EVENT_A2DP_ABORT:
                //! a2dp abort event
                //! clear the a2dp abort event.
                LOG_EVENT("\nRSI_APP_EVENT_A2DP_ABORT \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_ABORT);
                break;
            case RSI_APP_EVENT_A2DP_CLOSE:
                //! a2dp close event
                //! clear the a2dp close event.
                LOG_EVENT("\nRSI_APP_EVENT_A2DP_CLOSE \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_CLOSE);
                break;
            case RSI_APP_EVENT_A2DP_SBC_DATA:
                //! clear the a2dp close event.
                LOG_EVENT("\nRSI_APP_EVENT_A2DP_SBC_DATA \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_SBC_DATA);
                break;
            case RSI_APP_EVENT_A2DP_PCM_DATA:
                //! clear the a2dp close event.
                LOG_EVENT("\nRSI_APP_EVENT_A2DP_PCM_DATA \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_A2DP_PCM_DATA);
                break;
            case RSI_APP_EVENT_AVRCP_PAUSE:
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_PAUSE);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_PAUSE\n");
                if ((app_reg_events != 0) && (app_event_id[0] == 1)) {
                    notify.player_status = 0;
                    //rsi_bt_avrcp_notify(remote_dev_addr, 1, &notify);
                    app_event_id[0] = 0;
                    app_reg_events--;
                }
                rsi_bt_app_a2dp_pause();
                break;
            case RSI_APP_EVENT_AVRCP_CONN:
                //! avrcp conn event
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_CONN);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_CONN\n");
                /* Register AVRCP volume event notification, when AVRCP connected */
                if (app_state & (1 << AVRCP_CONNECTED)) {
                    status = rsi_bt_avrcp_reg_notification(bt_remote_dev_addr, AVRCP_EVENT_VOLUME_CHANGED, &abs_vol);
                    if (status != RSI_SUCCESS) {
                        LOG_EVENT("AVRCP Register Notification: status: 0x%x\n", status);
                    }
                    uint8_t abs_vol_per = (abs_vol * 100) / 0x7f;
                    LOG_EVENT("Absolute Volume: %d% (0x%x)\n", abs_vol_per, abs_vol);
                }
                rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_GET_REM_CAP);
                break;
            case RSI_APP_EVENT_AVRCP_DISCONN:
                //! avrcp disconn event
                //! clear the avrcp disconn event.
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_DISCONN);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_DISCONN\n");
                break;
            case RSI_APP_EVENT_AVRCP_PLAY:
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_PLAY);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_PLAY\n");
                if ((app_reg_events != 0) && (app_event_id[0] == 1)) {
                    notify.player_status = 1;
                    //rsi_bt_avrcp_notify(remote_dev_addr, 1, &notify);
                    app_event_id[0] = 0;
                    app_reg_events--;
                }
                rsi_bt_app_a2dp_resume();
                break;
            case RSI_APP_EVENT_AVRCP_GET_CAP:
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_GET_CAP);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_GET_CAP\n");
                break;
            case RSI_APP_EVENT_AVRCP_GET_ATTS:                
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_GET_ATTS);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_GET_ATTS\n");
                rsi_bt_avrcp_att_list_resp(bt_remote_dev_addr, 1, atts);
                break;
            case RSI_APP_EVENT_AVRCP_GET_ATT_VALS:
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_GET_ATT_VALS);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_GET_ATT_VALS\n");
                rsi_bt_avrcp_att_val_list_resp(bt_remote_dev_addr, 2, vals);
                break;
            case RSI_APP_EVENT_AVRCP_CUR_ATT_VALS:
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_CUR_ATT_VALS);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_CUR_ATT_VALS\n");
                break;
            case RSI_APP_EVENT_AVRCP_SET_ATT_VALS:
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_SET_ATT_VALS);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_SET_ATT_VALS\n");
                rsi_bt_avrcp_set_cur_att_val_resp(bt_remote_dev_addr, 0);
                break;
            case RSI_APP_EVENT_AVRCP_ATT_TEXT:
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_ATT_TEXT);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_ATT_TEXT\n");
                break;
            case RSI_APP_EVENT_AVRCP_ATT_VALS_TEXT:
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_ATT_VALS_TEXT);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_ATT_VALS_TEXT\n");
                break;
            case RSI_APP_EVENT_AVRCP_SONG_ATTS:
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_SONG_ATTS);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_SONG_ATTS\n");
                for (ix = 0; ix < app_song_atts.nbr_atts; ix++) {
                    attr_list[ix].id = (uint8_t)(app_song_atts.ele_atts[ix]);
                    switch (app_song_atts.ele_atts[ix]) {
                        case BT_AVRCP_MEDIA_ATTR_ID_MEDIA_TITLE:
                            break;
                        case BT_AVRCP_MEDIA_ATTR_ID_ARTIST_NAME:
                            attr_list[ix].attr_len = strlen(SAMPLE_ARTIST_NAME);
                            memcpy(attr_list[ix].attr_val, SAMPLE_ARTIST_NAME, attr_list[ix].attr_len);
                            break;
                        case BT_AVRCP_MEDIA_ATTR_ID_ALBUM_NAME:
                            attr_list[ix].attr_len = strlen(SAMPLE_ALBUM_NAME);
                            memcpy(attr_list[ix].attr_val, SAMPLE_ALBUM_NAME, attr_list[ix].attr_len);
                            break;
                        case BT_AVRCP_MEDIA_ATTR_ID_TRACK_NUM:
                            // rsi_itoa((uint32_t)app_song_list_idx, (uint8_t *)attr_list[ix].attr_val);
                            // attr_list[ix].attr_len = strlen((const char *)attr_list[ix].attr_val);
                            break;
                        case BT_AVRCP_MEDIA_ATTR_ID_NUM_OF_TRACK:
                            rsi_itoa(SONG_LIST_MAX_COUNT, attr_list[ix].attr_val);
                            attr_list[ix].attr_len = strlen((const char *)attr_list[ix].attr_val);
                            break;
                        case BT_AVRCP_MEDIA_ATTR_ID_GENRE:
                            attr_list[ix].attr_len = strlen((const char *)SAMPLE_GENRE);
                            memcpy(attr_list[ix].attr_val, SAMPLE_GENRE, strlen(SAMPLE_GENRE));
                            break;
                        case BT_AVRCP_MEDIA_ATTR_ID_PLAYING_TIME_MS:
                            // rsi_itoa(((file_size / PCM_DATA_LEN_PER_MS) * 1000), (uint8_t *)attr_list[ix].attr_val);
                            // attr_list[ix].attr_len = strlen((const char *)attr_list[ix].attr_val);
                            break;
                        default:{

                        }
                    }
                }
                rsi_bt_avrcp_ele_att_resp(bt_remote_dev_addr, app_song_atts.nbr_atts, attr_list);
                break;   
            case RSI_APP_EVENT_AVRCP_PLAY_STATUS:
                //TODO : Most of this is not making sense and commented. Needs review  
                // uint32_t pos, size;
                // uint8_t play_status;
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_PLAY_STATUS \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_PLAY_STATUS);
                // pos         = f_tell(&g_fileObject_sd);
                // size        = file_size;
                // play_status = bt_rsi_app_async_event_map & BIT(RSI_APP_EVENT_A2DP_CONFIGURE);
                // rsi_bt_avrcp_play_status_resp(bt_remote_dev_addr,
                                            // play_status,
                                            //((size / PCM_DATA_LEN_PER_MS) * 1000), //I don't understand this correctly
                                            //((pos / PCM_DATA_LEN_PER_MS) * 1000));
                break;
            case RSI_APP_EVENT_AVRCP_REG_EVENT:
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_REG_EVENT);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_REG_EVENT\n");
                if (app_event_id[app_reg_events - 1] == AVRCP_EVENT_TRACK_CHANGED) {
                    uint8_t event_data[8] = { 0 };
                    rsi_bt_avrcp_reg_notify_resp(bt_remote_dev_addr, AVRCP_EVENT_TRACK_CHANGED, sizeof(event_data), event_data);
                }
                break;
            case RSI_APP_EVENT_AVRCP_SET_ABS_VOL:
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_SET_ABS_VOL);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_SET_ABS_VOL\n");
                break;
            case RSI_APP_EVENT_AVRCP_NOTIFY:
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_NOTIFY);
                LOG_PRINT("\nRSI_APP_EVENT_AVRCP_NOTIFY\n");
                status = rsi_bt_avrcp_reg_notification(bt_remote_dev_addr, avrcp_notify.notify_val.eventid, &abs_vol);
                if (status != RSI_SUCCESS) {
                    LOG_PRINT("Avrcp reg notification cmd status: 0x%x\n", status);
                    break;
                }
                //LOG_PRINT ("notify event id: %d \n", avrcp_notify.notify_val.eventid);
                switch (avrcp_notify.notify_val.eventid) {
                    case AVRCP_EVENT_VOLUME_CHANGED: {
                        uint8_t abs_vol_per;
                        uint8_t abs_vol = avrcp_notify.notify_val.notify_val.abs_vol;
                        abs_vol_per     = (abs_vol * 100) / 0x7f;
                        LOG_PRINT("Absolute Volume: %d% (0x%x)\n", abs_vol_per, abs_vol);
                    } break;
                }
                break;
            case RSI_APP_EVENT_AVRCP_NEXT:
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_NEXT\n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_NEXT);
                pcm_offset = 0;
                reset_audio_params();
                break;
            case RSI_APP_EVENT_AVRCP_PREVIOUS:
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_PREVIOUS\n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_PREVIOUS);
                pcm_offset = 0;
                reset_audio_params();
                break;
            case RSI_APP_EVENT_AVRCP_VOL_UP:
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_VOL_UP);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_VOL_UP\n");
                break;
            case RSI_APP_EVENT_AVRCP_VOL_DOWN:
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_VOL_DOWN);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_VOL_DOWN\n");
                break;
            case RSI_APP_EVENT_AVRCP_GET_REM_CAP:
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_GET_REM_CAP);
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_GET_REM_CAP\n");
                status = rsi_bt_avrcp_get_capabilities(bt_remote_dev_addr, app_cap_type, (rsi_bt_rsp_avrcp_get_capabilities_t *)cap);
                if (status != RSI_SUCCESS) {
                    LOG_EVENT("\nAVRCP get_capabilities: status 0x%x\n", status);
                }
                LOG_EVENT("\nAVRCP get capabilities resp status 0x%x: cap[0]:%d cap[1]:%d cap[2]:%d\n",
                        status,
                        cap[0],
                        cap[1],
                        cap[2]);

                if (app_state & (1 << AVRCP_CONNECTED)) {
                    status = rsi_bt_avrcp_reg_notification(bt_remote_dev_addr, AVRCP_EVENT_VOLUME_CHANGED, &abs_vol);
                    if (status != RSI_SUCCESS) {
                        LOG_EVENT("AVRCP Register Notification: status: 0x%x\n", status);
                    }
                    uint8_t abs_vol_per = (abs_vol * 100) / 0x7f;
                    LOG_EVENT("Absolute Volume: %d% (0x%x)\n", abs_vol_per, abs_vol);
                }
                rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_GET_REM_VER);
                break;
            case RSI_APP_EVENT_AVRCP_GET_REM_VER:
                LOG_EVENT("\nRSI_APP_EVENT_AVRCP_GET_REM_VER\n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_AVRCP_GET_REM_VER);
                status = rsi_bt_avrcp_get_remote_version(bt_remote_dev_addr, (rsi_bt_rsp_avrcp_remote_version_t *)&avrcp_version);
                if (status != RSI_SUCCESS) {
                    LOG_EVENT("\nAVRCP get_remote_version: status 0x%x\n", status);
                }
                LOG_EVENT("\nAVRCP remote version: %d.%d\n", ((avrcp_version >> 8) & 0xFF), ((avrcp_version) && 0xFF));
                break;
            case RSI_APP_EVENT_SPP_CONN:
                //! spp connected event
                LOG_EVENT("\nRSI_APP_EVENT_SPP_CONN \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_SPP_CONN);
                break;
            case RSI_APP_EVENT_SPP_DISCONN:
                //! spp disconnected event
                LOG_EVENT("\nRSI_APP_EVENT_SPP_DISCONN \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_SPP_DISCONN);
                break;
            case RSI_APP_EVENT_SPP_RX:
                //! spp receive event
                LOG_EVENT("\nRSI_APP_EVENT_SPP_RX \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_SPP_RX);
                LOG_PRINT("\nSending rsi_bt_spp_transfer\n");
                print_status(rsi_bt_spp_transfer(bt_remote_dev_addr, bt_data, bt_data_len));
                break;
            case RSI_APP_EVENT_PASSKEY_DISPLAY:
                //! spp receive event
                LOG_EVENT("\nRSI_APP_EVENT_PASSKEY_DISPLAY \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_PASSKEY_DISPLAY);
                break;
            case RSI_APP_EVENT_CONFIRM_REQUEST:
                //! spp receive event
                LOG_EVENT("\nRSI_APP_EVENT_CONFIRM_REQUEST \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_CONFIRM_REQUEST);
                LOG_PRINT("\nSending rsi_bt_accept_ssp_confirm\n");
                print_status(rsi_bt_accept_ssp_confirm((int8_t *)bt_remote_dev_addr));
                break;
            case RSI_APP_EVENT_PASSKEY_REQUEST:
                //! spp receive event
                LOG_EVENT("\nRSI_APP_EVENT_PASSKEY_REQUEST \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_PASSKEY_REQUEST);
                break;
            case RSI_APP_EVENT_SSP_COMPLETE:
                //! spp receive event
                LOG_EVENT("\nRSI_APP_EVENT_SSP_COMPLETE \n");
                rsi_bt_app_clear_event(RSI_APP_EVENT_SSP_COMPLETE);
                break;
            case RSI_APP_EVENT_MODE_CHANGED:
                //! spp receive event
                LOG_EVENT("\nRSI_APP_EVENT_MODE_CHANGED \n");                
                rsi_bt_app_clear_event(RSI_APP_EVENT_MODE_CHANGED);
                break;
            case RSI_APP_EVENT_SNIFF_SUBRATING:
                //! spp receive event
                rsi_bt_app_clear_event(RSI_APP_EVENT_SNIFF_SUBRATING);
                LOG_EVENT("\nRSI_APP_EVENT_SNIFF_SUBRATING \n");
                break;
            case RSI_APP_EVENT_ROLE_CHANGE:
                            //! role change event
                rsi_bt_app_clear_event(RSI_APP_EVENT_ROLE_CHANGE);
                LOG_EVENT("\nRSI_APP_EVENT_ROLE_CHANGE \n");
                break;
            case RSI_APP_EVENT_SEARCH_SERVICE:
            	rsi_bt_app_clear_event(RSI_APP_EVENT_ROLE_CHANGE);
            	LOG_EVENT("\nRSI_APP_EVENT_SEARCH_SERVICE \n");
            	break;
            default: {
            }
        }
    }
}

/*********** END OF HELPER FUNCTIONS *******************/

/*********** BEGIN OF HANDLERS *******************/
void init_bt_command()
{
    if (bt_task_handle != NULL) {
        // already initialized
        print_status(RSI_ERROR_NONE);
        return;
    }
    int32_t status = intialize_bt_stack(STACK_BT_MODE);

    if (status == RSI_SUCCESS) {   
           
        status = rsi_switch_proto(1, NULL);
        if(status != RSI_SUCCESS){
            print_status(status);
            return;
        }

        //set default role to master
        current_bt_role = BT_MASTER_ROLE;

        //set profile to default
        current_profile = BT_DEFAULT;

        rsi_task_create((rsi_task_function_t)bt_task, 
                        (uint8_t *)"bt_task",
                        RSI_BT_TASK_STACK_SIZE,
                        NULL,
                        RSI_BT_TASK_PRIORITY,
                        &bt_task_handle);
        //! BT Classic register GAP callbacks:
        rsi_bt_gap_register_callbacks(rsi_bt_on_role_change_event, //role_change
                                rsi_bt_on_conn_status_event,
                                rsi_bt_on_unbond_status_event,
                                rsi_bt_on_disconn_event,
                                rsi_bt_on_inq_resp_event,
                                rsi_bt_on_remote_name_resp_event,
                                rsi_bt_on_passkey_display_event, //passkey_display
                                rsi_bt_on_remote_name_cancel_resp_event,
                                rsi_bt_on_confirm_request_event, //confirm req
                                rsi_bt_on_pincode_req_event,
                                rsi_bt_on_passkey_request_event, //passkey request
                                rsi_bt_on_inq_complete_event,
                                rsi_bt_on_auth_complete_event,
                                rsi_bt_on_linkkey_req_event,
                                rsi_bt_on_ssp_complete_event,    //ssp coplete
                                rsi_bt_on_linkkey_save_event,
                                rsi_bt_on_query_services_event,
                                NULL,
                                rsi_bt_on_mode_change_event,
                                rsi_bt_on_sniff_subrating_event, //search service
                                NULL);
        //! initialize the event map
        rsi_bt_app_init_events();
    }
    print_status(status);
}

void rsi_bt_spp_init_command(sl_cli_command_arg_t *arguments){
    (void)arguments;
    int32_t status = rsi_bt_spp_init();
    if(status == RSI_SUCCESS){
        current_profile = BT_SPP;
        //! register the SPP profile callback's
        rsi_bt_spp_register_callbacks(rsi_bt_on_spp_connect, 
                                        rsi_bt_on_spp_disconnect, 
                                        rsi_bt_on_spp_data_rx);
    }
    print_status(status);
}

int32_t rsi_bt_a2dp_init_command(sl_cli_command_arg_t *arguments){
    (void)arguments;
    int32_t status = rsi_bt_a2dp_init(&audio_codec_cap);
    if(status == RSI_SUCCESS){
        status = rsi_bt_cmd_sbc_init();
        if (status == RSI_SUCCESS) {
            current_profile = BT_A2DP_SRC;
            //! register the A2DP profile callback's
            rsi_bt_a2dp_register_callbacks(rsi_bt_on_a2dp_connect,
                                        rsi_bt_on_a2dp_disconnect,
                                        rsi_bt_on_a2dp_configure,
                                        rsi_bt_on_a2dp_open,
                                        rsi_bt_on_a2dp_start,
                                        rsi_bt_on_a2dp_suspend,
                                        rsi_bt_on_a2dp_abort, 
                                        rsi_bt_on_a2dp_close,
                                        rsi_bt_on_a2dp_encode_data,
                                        rsi_bt_on_a2dp_pcm_data,
                                        rsi_bt_on_a2dp_more_data_req,
                                        rsi_bt_on_a2dp_reconfig);
        }
    }
    print_status(status);
    return status;
}

void rsi_bt_avrcp_init_command(sl_cli_command_arg_t *arguments){
    (void)arguments;
    int32_t status = rsi_bt_avrcp_init(NULL);
    if (status == RSI_SUCCESS) {
        current_profile = BT_A2DP_AVRCP_SRC;
        //! register the AVRCP profile callback's
        rsi_bt_avrcp_register_callbacks(rsi_bt_app_on_avrcp_connect,
                                rsi_bt_app_on_avrcp_disconnect,
                                rsi_bt_app_on_avrcp_play,
                                rsi_bt_app_on_avrcp_pause,
                                NULL,
                                rsi_bt_app_on_avrcp_next,
                                rsi_bt_app_on_avrcp_previous,
                                rsi_bt_app_on_avrcp_vol_up,
                                rsi_bt_app_on_avrcp_vol_down,
                                NULL,
                                rsi_bt_on_avrcp_notify_event);

        rsi_bt_avrcp_target_register_callbacks(rsi_bt_on_avrcp_get_cap_event,
                                                rsi_bt_on_avrcp_get_app_supp_atts_event,
                                                rsi_bt_on_avrcp_get_app_suup_att_vals_event,
                                                rsi_bt_on_avrcp_get_app_cur_att_val_event,
                                                rsi_bt_on_avrcp_set_app_cur_att_val_event,
                                                rsi_bt_on_avrcp_get_app_att_text_event,
                                                rsi_bt_on_avrcp_get_app_att_vals_text_event,
                                                NULL, //rsi_bt_on_avrcp_supp_char_sets_event,
                                                NULL, //rsi_bt_on_avrcp_batt_status_event,
                                                rsi_bt_on_avrcp_get_song_atts_event,
                                                rsi_bt_on_avrcp_get_play_status_event,
                                                rsi_bt_on_avrcp_reg_notify_event,
                                                rsi_bt_on_avrcp_set_abs_vol_event,
                                                NULL, //rsi_bt_on_avrcp_set_addr_player_event,
                                                NULL, //rsi_bt_on_avrcp_get_folder_items_event,
                                                NULL  //rsi_bt_on_avrcp_get_tot_num_items_event,
                                                );
    }
    print_status(status);
}

void rsi_bt_set_master_role_command(sl_cli_command_arg_t *arguments){
    (void)arguments;
    int32_t status = rsi_bt_stop_discoverable();
    if(status == RSI_SUCCESS){
        status = rsi_bt_set_non_connectable();
    }
    if(status == RSI_SUCCESS){
        current_bt_role = BT_MASTER_ROLE;
    }
    print_status(status);
}

void rsi_bt_set_slave_role_command(sl_cli_command_arg_t *arguments){
    (void)arguments;
    int32_t status = rsi_bt_start_discoverable();
    if(status == RSI_SUCCESS){
        status = rsi_bt_set_connectable();
    }
    if(status == RSI_SUCCESS){
        current_bt_role = BT_SLAVE_ROLE;
    }
    print_status(status);
}

//! initiating power save in BLE mode
void rsi_bt_power_save_profile_command(sl_cli_command_arg_t *arguments){
    uint8_t mode = sl_cli_get_argument_uint8(arguments, 0);
    uint8_t psp_type = sl_cli_get_argument_uint8(arguments, 1);
    print_status(rsi_bt_power_save_profile(mode, psp_type));
}

//! Put device under test mode
void rsi_bt_enable_device_under_testmode_command(sl_cli_command_arg_t *arguments){
    (void)arguments;
    print_status(rsi_bt_enable_device_under_testmode());
}

void rsi_bt_set_pin_code_command(sl_cli_command_arg_t *arguments){
    char* pin = sl_cli_get_argument_string(arguments, 0);
    if(pin != "\0"){
        memcpy(pin_code, (uint8_t *)pin, RSI_MAX_PINCODE_REPLY_SIZE);
    }
    print_status(RSI_ERROR_NONE);
}

void rsi_bt_get_pin_code_command(sl_cli_command_arg_t *arguments){
    (void)arguments;
    printf("\n%s\n", (uint8_t *)&pin_code);
    print_status(RSI_ERROR_NONE);
}

//! start the ssp mode
// Simple secure pair
void rsi_bt_set_ssp_mode_command(sl_cli_command_arg_t *arguments){
    uint8_t pair_mode = sl_cli_get_argument_uint8(arguments, 0);
    uint8_t IOcapability = sl_cli_get_argument_uint8(arguments, 1);
    print_status(rsi_bt_set_ssp_mode(pair_mode, IOcapability));
}

void rsi_bt_get_local_class_of_device_command(sl_cli_command_arg_t *arguments){
    (void)arguments;
    int32_t class_of_device;
    int32_t status = rsi_bt_get_local_class_of_device(&class_of_device);
    if (status == RSI_SUCCESS) {
        printf("\n0x%x - %lu\n", class_of_device, class_of_device);
    }
    print_status(status);
}

void rsi_bt_set_local_class_of_device_command(sl_cli_command_arg_t *arguments){
    int32_t class_of_device = sl_cli_get_argument_uint32(arguments, 0);
    print_status(rsi_bt_set_local_class_of_device(class_of_device));
}

void rsi_bt_start_limited_discoverable_command(sl_cli_command_arg_t *arguments){
    int32_t time_out_ms = sl_cli_get_argument_uint32(arguments, 0);    // set to 100 in the example app;
    print_status(rsi_bt_start_limited_discoverable(time_out_ms));
}

void rsi_bt_stop_discoverable_command(sl_cli_command_arg_t *arguments){
   (void)arguments;
    print_status(rsi_bt_stop_discoverable());
}

void rsi_bt_get_discoverable_status_command(sl_cli_command_arg_t *arguments){
    (void)arguments;
    uint8_t device_state = 0;
    int32_t status = rsi_bt_get_discoverable_status(&device_state);
    if (status == RSI_SUCCESS) {
        printf("\n%d\n", device_state);
    }
    print_status(status);
}

void rsi_bt_set_non_connectable_command(sl_cli_command_arg_t *arguments){
    (void)arguments;
    print_status(rsi_bt_set_non_connectable());
}

//! Set Adaptive Frequency Hopping host channel classification
void rsi_bt_set_afh_host_channel_classification_command(sl_cli_command_arg_t *arguments){
    uint8_t enable = 1;//sl_cli_get_argument_string(arguments, 0);

    //static uint8_t channel_map[CHANNEL_MAP_LEN] = {255,255,255,255,00,00,00,00,00,15}; // Minimum 20 channels needed
    static uint8_t channel_map[CHANNEL_MAP_LEN] = {
    0xff, 0xff, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff, 0x00, 0x0f
    }; // Minimum 20 channels needed

    print_status(rsi_bt_set_afh_host_channel_classification(enable, &channel_map));
}

//! Get Adaptive Frequency Hopping host channel classification
void rsi_bt_get_afh_host_channel_classification_command(sl_cli_command_arg_t *arguments){
    (void)arguments;
    uint8_t mode = 0;

    int32_t status = rsi_bt_get_afh_host_channel_classification(&mode);
    if (status == RSI_SUCCESS) {
        printf("\n%d\n", mode);
    }
    print_status(status);
}

//! API_9 - Get connectability status
void rsi_bt_get_connectable_status_command(sl_cli_command_arg_t *arguments){
    (void)arguments;
    uint8_t device_state = 0;
    int32_t status = rsi_bt_get_connectable_status(&device_state);
    if (status == RSI_SUCCESS) {
        printf("\n%d\n", device_state);
    }
    print_status(status);
}

//! start BT inquiry
void rsi_bt_inquiry_command(sl_cli_command_arg_t *arguments){
    uint8_t inquiry_type = sl_cli_get_argument_uint8(arguments, 0);
    uint32_t inquiry_duration = sl_cli_get_argument_uint32(arguments, 1);
    uint8_t max_devices = sl_cli_get_argument_uint8(arguments, 2);

    print_status(rsi_bt_inquiry(inquiry_type, inquiry_duration, max_devices));
}

//! initiate A2DP connection with remote device
void rsi_bt_a2dp_connect_command(sl_cli_command_arg_t *arguments){
    char* remote_bd_addr = sl_cli_get_argument_string(arguments, 0);
    print_status(rsi_bt_a2dp_connect((uint8_t *)remote_bd_addr));
}


void rsi_bt_a2dp_start_sbc_streaming_command(sl_cli_command_arg_t *arguments){
    (void)arguments;
    pcm_offset=0;
    print_status(rsi_bt_a2dp_start_sbc_encoding());
}

//! API_24 - initiate SPP connection with remote device
void rsi_bt_spp_connect_command(sl_cli_command_arg_t *arguments){
    char* remote_bd_addr = sl_cli_get_argument_string(arguments, 0);
    print_status(rsi_bt_spp_connect((uint8_t *)remote_bd_addr));
}

//! API_25 - Set bt classic antenna transmit power level
//1 – BT classic 2 – BT Low Energy
void rsi_bt_set_antenna_tx_power_level_command(sl_cli_command_arg_t *arguments){
    uint8_t protocol_mode = sl_cli_get_argument_uint8(arguments, 0);
    uint8_t tx_power = sl_cli_get_argument_uint8(arguments, 1);
    print_status(rsi_bt_set_antenna_tx_power_level(protocol_mode, tx_power));
}

//! API_11 - Enable authentication
void rsi_bt_enable_authentication_command(sl_cli_command_arg_t *arguments){
    (void)arguments;
    print_status(rsi_bt_enable_authentication());
}

//! API_12 - Disable authentication
void rsi_bt_disable_authentication_command(sl_cli_command_arg_t *arguments){
    (void)arguments;
    print_status(rsi_bt_disable_authentication());
}

//! get the RSSI value with connected remote device
void rsi_bt_get_rssi_command(sl_cli_command_arg_t *arguments){
    char* remote_bond_dev_addr = sl_cli_get_argument_string(arguments, 0);

    int8_t bt_rsi_app_resp_rssi = 0;
    uint8_t device_address[6] = {0};
    rsi_ascii_dev_address_to_6bytes_rev(device_address, (int8_t*)remote_bond_dev_addr);
    int32_t status = rsi_bt_get_rssi((uint8_t *)device_address, &bt_rsi_app_resp_rssi);
    if (status == RSI_SUCCESS) {
        printf("\n%d\n", bt_rsi_app_resp_rssi);
    }
    print_status(status);
}

//! API_17 - Get remote device name request cancel
void rsi_bt_remote_name_request_cancel_command(sl_cli_command_arg_t *arguments){
    char* remote_bond_dev_addr = sl_cli_get_argument_string(arguments, 0);

    //uint8_t remote_bond_dev_addr[6] = { 0 };
    print_status(rsi_bt_remote_name_request_cancel((uint8_t *)remote_bond_dev_addr));
}

//! API_18 - Sending the pincode requet reply
void rsi_bt_pincode_request_reply_command(sl_cli_command_arg_t *arguments){
    char* remote_bond_dev_addr = sl_cli_get_argument_string(arguments, 0);
    uint8_t reply_type = sl_cli_get_argument_uint8(arguments, 1);
    char* pin = sl_cli_get_argument_string(arguments, 2);
    print_status(rsi_bt_pincode_request_reply((uint8_t *)remote_bond_dev_addr,(uint8_t *)pin, reply_type));
}

//! API_15 - Get Local device role: 0 - Master, 1 - Slave.
void rsi_bt_get_local_device_role_command(sl_cli_command_arg_t *arguments){
    char* remote_bond_dev_addr = sl_cli_get_argument_string(arguments, 0);

    uint8_t device_state    = 0;

    int32_t status = rsi_bt_get_local_device_role((uint8_t *)remote_bond_dev_addr, &device_state);
    if (status == RSI_SUCCESS) {
        printf("%d\n", device_state);
    }
    print_status(status);
}

//! API_16 - Get remote device name.
void rsi_bt_remote_name_request_async_command(sl_cli_command_arg_t *arguments){
    char* remote_bond_dev_addr = sl_cli_get_argument_string(arguments, 0);
    rsi_bt_event_remote_device_name_t bt_remote_device_name = { 0 };
    bt_remote_device_name.name_length = RSI_DEV_NAME_LEN;
    int32_t status = rsi_bt_remote_name_request_async((uint8_t *)remote_bond_dev_addr, &bt_remote_device_name);
    print_status(status);
}

//! API_20 - BT disconnect/ unbond.
void rsi_bt_disconnect_command(sl_cli_command_arg_t *arguments){
    char* remote_bond_dev_addr = sl_cli_get_argument_string(arguments, 0);
    print_status(rsi_bt_disconnect(rsi_ascii_dev_address_to_6bytes_rev(bt_remote_dev_addr, remote_bond_dev_addr)));
}

//! Sending the linkkey request negative reply
void rsi_bt_linkkey_request_reply_command(sl_cli_command_arg_t *arguments){
    char* remote_bond_dev_addr = sl_cli_get_argument_string(arguments, 0);
    uint8_t reply_type = sl_cli_get_argument_uint8(arguments, 1);
    print_status(rsi_bt_linkkey_request_reply((uint8_t *)remote_bond_dev_addr, NULL, reply_type));
}

void rsi_bt_connect_command(sl_cli_command_arg_t *arguments){
    char* remote_bond_dev_addr = sl_cli_get_argument_string(arguments, 0);
    print_status(rsi_bt_connect(rsi_ascii_dev_address_to_6bytes_rev(bt_remote_dev_addr, remote_bond_dev_addr)));
}

void rsi_bt_cancel_connect_command(sl_cli_command_arg_t *arguments){
    char* remote_bond_dev_addr = sl_cli_get_argument_string(arguments, 0);
    print_status(rsi_bt_cancel_connect((uint8_t *)remote_bond_dev_addr));
}

//! API_23 - ssp transfer.
void rsi_bt_spp_transfer_command(sl_cli_command_arg_t *arguments){
    char* remote_bond_dev_addr = sl_cli_get_argument_string(arguments, 0);
    char* data = sl_cli_get_argument_string(arguments, 1);

    uint8_t bt_data[RSI_BT_MAX_PAYLOAD_SIZE];
    uint8_t bt_data_len = 0;
    int32_t tx_ix = 0;

    strcpy((char *)bt_data,data);
    bt_data_len = strlen((char *)bt_data);
    bt_data[bt_data_len] = (tx_ix++) % 10;

    //rsi_bt_sniff_mode(remote_bond_dev_addr, 0xC0, 0xA0, 0x04, 0x02);
    print_status(rsi_bt_spp_transfer(rsi_ascii_dev_address_to_6bytes_rev(bt_remote_dev_addr, remote_bond_dev_addr), bt_data, bt_data_len));
}

void rsi_bt_get_role(sl_cli_command_arg_t *arguments){
    char* remote_bd_address = sl_cli_get_argument_string(arguments, 0);
    uint8_t remote_dev_addr[RSI_DEV_ADDR_LEN] = {0};
    uint8_t role_resp = 2;

    rsi_ascii_dev_address_to_6bytes_rev(remote_dev_addr, remote_bd_address);
    //int32_t status = rsi_bt_get_local_device_role((int8_t *)remote_dev_addr,&role_resp);



    int32_t status = rsi_bt_get_local_device_role(remote_dev_addr,&role_resp);
    printf("\ndevice role: %d\n",role_resp);
    print_status(status);
}

void rsi_bt_set_role(sl_cli_command_arg_t *arguments){
    char* remote_bd_address = sl_cli_get_argument_string(arguments, 0);
    uint8_t role_set_flag = sl_cli_get_argument_int8(arguments, 1);
    uint8_t remote_dev_addr[RSI_DEV_ADDR_LEN] = {0};
    uint8_t role_resp = 2;

    //int32_t status =rsi_bt_set_local_device_role((int8_t *)remote_dev_addr,role_set_flag,&role_resp);
    rsi_ascii_dev_address_to_6bytes_rev(remote_dev_addr, remote_bd_address);
    int32_t status =rsi_bt_set_local_device_role((int8_t *)remote_dev_addr,role_set_flag,&role_resp);
    printf("\ndevice role: %d\n",role_resp);
    print_status(status);
}

void rsi_bt_set_slave_role_connectable(sl_cli_command_arg_t *arguments){
    (void)arguments;

    int32_t status = rsi_bt_set_connectable();
    print_status(status);
}


void rsi_bt_get_services_command(sl_cli_command_arg_t *arguments){
    char* remote_bond_dev_addr = sl_cli_get_argument_string(arguments, 0);

    int32_t status = rsi_bt_get_services_async((uint8_t *)remote_bond_dev_addr, &bt_resp_query_services);
    print_status(status);
}

/*********** END OF HANDLERS *******************/

/******************* BEGIN OF CALLBACK IMPLEMENTATIONS *****************/
/*==============================================*/
/**
 * @fn         rsi_bt_app_init_events
 * @brief      initializes the event parameter.
 * @param[in]  none.
 * @return     none.
 * @section description
 * This function is used during BT initialization.
 */
static void rsi_bt_app_init_events()
{
    bt_rsi_app_async_event_map = 0;
    bt_rsi_app_async_event_map1 = 0;
    return;
}

/*==============================================*/
/**
 * @fn         rsi_bt_app_set_event
 * @brief      sets the specific event.
 * @param[in]  event_num, specific event number.
 * @return     none.
 * @section description
 * This function is used to set/raise the specific event.
 */
static void rsi_bt_app_set_event(uint32_t event_num)
{
    if (event_num <= 31) {
        bt_rsi_app_async_event_map |= BIT(event_num);
    } else {
       bt_rsi_app_async_event_map1 |= BIT(event_num-32);
    }
    rsi_semaphore_post(&bt_thread_sem);
		   
}

/*==============================================*/
/**
 * @fn         rsi_bt_app_clear_event
 * @brief      clears the specific event.
 * @param[in]  event_num, specific event number.
 * @return     none.
 * @section description
 * This function is used to clear the specific event.
 */
static void rsi_bt_app_clear_event(uint32_t event_num)
{   
    if (event_num <= 31) {
        bt_rsi_app_async_event_map &= ~BIT(event_num);
    } else {
        bt_rsi_app_async_event_map1 &= ~BIT((event_num - 32));
    }
    return;
}

/*==============================================*/
/**
 * @fn         rsi_bt_app_get_event
 * @brief      returns the first set event based on priority
 * @param[in]  none.
 * @return     int32_t
 *             > 0  = event number
 *             -1   = not received any event
 * @section description
 * This function returns the highest priority event among all the set events
 */
static int32_t rsi_bt_app_get_event(void)
{
    uint32_t ix;

    for (ix = 0; ix < 64; ix++) {
        if (ix <= 31) {
            if (bt_rsi_app_async_event_map & (1 << ix)) {
                return ix;
            }
        } else {
            if (bt_rsi_app_async_event_map1 & (1 << (ix - 32))) {
                return ix;
            }
        }
    }

    return (RSI_FAILURE);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_conn_status_event
 * @brief      invoked when connection complete event is received
 * @param[out] bond_response, connected remote device information
 * @return     none.
 * @section description
 * This callback function indicates the status of the connection.
 */
void rsi_bt_on_conn_status_event(uint16_t resp_status, rsi_bt_event_bond_t *conn_event)
{
    memcpy((int8_t *)bt_remote_dev_addr, conn_event->dev_addr, RSI_DEV_ADDR_LEN);
    if (resp_status == RSI_APP_ERR_NONE) {
        app_state |= (1 << CONNECTED);
        rsi_bt_app_set_event(RSI_APP_EVENT_CONNECTED);
    } else if (resp_status == RSI_APP_ERR_ACL_CONN_ALREADY_EXISTS) {
        app_state |= (1 << CONNECTED);
        rsi_bt_app_set_event(RSI_APP_EVENT_CONNECTED);
    } else {
        rsi_bt_app_set_event(RSI_APP_EVENT_DISCONNECTED);
    }
    LOG_EVENT("\nrsi_bt_on_conn_status_event- dev_addr: %s, resp_status: 0x%X\n",
             rsi_6byte_dev_address_to_ascii((int8_t *)bt_str_conn_bd_addr, conn_event->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_unbond_status_event
 * @brief      invoked when unbond/disconnect status event is received
 * @param[out] unbond_status, unbonding remote device information
 * @return     none.
 * @section description
 * This callback function indicates disconnection from remote device
 */
void rsi_bt_on_unbond_status_event(uint16_t resp_status, rsi_bt_event_unbond_t *unbond_status)
{
    (void)(unbond_status);
    memcpy((int8_t *)bt_remote_dev_addr, unbond_status->dev_addr, RSI_DEV_ADDR_LEN);
    rsi_bt_app_set_event(RSI_APP_EVENT_UNBOND);
    LOG_EVENT("\nrsi_bt_on_unbond_status_event- dev_addr: %s, resp_status: 0x%X\n",
            rsi_6byte_dev_address_to_ascii(bt_remote_dev_addr, unbond_status->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_pincode_req_event
 * @brief      invoked when pincode request event is received
 * @param[out] user_pincode_request, pairing remote device information
 * @return     none.
 * @section description
 * This callback function indicates the pincode request from remote device
 */
void rsi_bt_on_pincode_req_event(uint16_t resp_status, rsi_bt_event_user_pincode_request_t *user_pincode_request)
{
    memcpy((int8_t *)bt_remote_dev_addr, user_pincode_request->dev_addr, RSI_DEV_ADDR_LEN);
    rsi_bt_app_set_event(RSI_APP_EVENT_PINCODE_REQ);
    LOG_EVENT("\nrsi_bt_on_pincode_req_event- dev_addr: %s, resp_status: 0x%X\n",
            rsi_6byte_dev_address_to_ascii((int8_t *)bt_str_conn_bd_addr, user_pincode_request->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_linkkey_req_event
 * @brief      invoked when linkkey request event is received
 * @param[out] user_linkkey_req, pairing remote device information
 * @return     none.
 * @section description
 * This callback function indicates the linkkey request from remote device
 */
void rsi_bt_on_linkkey_req_event(uint16_t resp_status, rsi_bt_event_user_linkkey_request_t *user_linkkey_req)
{
    memcpy(bt_remote_dev_addr, user_linkkey_req->dev_addr, RSI_DEV_ADDR_LEN);
    rsi_bt_app_set_event(RSI_APP_EVENT_LINKKEY_REQ);
    LOG_EVENT("\nrsi_bt_on_linkkey_req_event- dev_addr: %s, resp_status: 0x%X\n",
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, user_linkkey_req->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_linkkey_save_event
 * @brief      invoked when linkkey save event is received
 * @param[out] user_linkkey_save, paired remote device information
 * @return     none.
 * @section description
 * This callback function indicates the linkkey save from local device
 */
void rsi_bt_on_linkkey_save_event(uint16_t resp_status, rsi_bt_event_user_linkkey_save_t *user_linkkey_save)
{
    memcpy(linkkey_bt, user_linkkey_save->linkKey, RSI_LINKKEY_REPLY_SIZE);
    memcpy((int8_t *)bt_remote_dev_addr, user_linkkey_save->dev_addr, RSI_DEV_ADDR_LEN);
    rsi_bt_app_set_event(RSI_APP_EVENT_LINKKEY_SAVE);
    LOG_EVENT("\nrsi_bt_on_linkkey_save_event- dev_addr:  %s, resp_status: 0x%X\n",
                 rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, user_linkkey_save->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_inq_complete_event
 * @brief      invoked when inquiry complete event is received
 * @return     none.
 * @section description
 * This callback function indicates inquiry complete.
 */
void rsi_bt_on_inq_complete_event(uint16_t resp_status)
{
  LOG_EVENT("\nrsi_bt_on_inq_complete_event- resp_status: 0x%X\n",resp_status);
  rsi_bt_app_set_event(RSI_APP_EVENT_INQ_COMPLT);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_auth_complete_event
 * @brief      invoked when authentication complete event is received
 * @param[out] auth_complete, authentication complete information
 * @return     none.
 * @section description
 * This callback function when authentication complete is recieved.
 */
void rsi_bt_on_auth_complete_event(uint16_t resp_status, rsi_bt_event_auth_complete_t *auth_complete)
{
    memcpy((int8_t *)bt_remote_dev_addr, auth_complete->dev_addr, RSI_DEV_ADDR_LEN);
    if (resp_status == 0) {
        rsi_bt_app_set_event(RSI_APP_EVENT_AUTH_COMPLT);
        app_state |= (1 << AUTHENTICATED);
    } else {
        memset(linkkey_bt, 0, RSI_LINKKEY_REPLY_SIZE);
        rsi_bt_app_set_event(RSI_APP_EVENT_DISCONNECTED);
    }
    LOG_EVENT("\nrsi_bt_on_auth_complete_event- dev_addr: %s, resp_status: 0x%X\n",
                 rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, auth_complete->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_remote_name_resp_event
 * @brief      invoked when remote device name response event is received
 * @param[out] remote_name, paired remote device name information
 * @return     none.
 * @section description
 * This callback function is called when get remote device name cmd response is recieved.
 */
void rsi_bt_on_remote_name_resp_event(uint16_t resp_status, rsi_bt_event_remote_device_name_t *remote_name)
{
    memcpy(&bt_remote_device_name, remote_name, sizeof(rsi_bt_event_remote_device_name_t));
    rsi_bt_app_set_event(RSI_APP_EVENT_REMOTE_NAME_RESP);
    LOG_EVENT("\nrsi_bt_on_remote_name_resp_event- remote_name: %s, resp_status: 0x%X\n",
                    bt_remote_device_name.remote_device_name, resp_status);
    
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_remote_name_cancel_resp_event
 * @brief      invoked when remote device name request cancel event is received
 * @param[out] user_linkkey_req, paired remote device information
 * @return     none.
 * @section description
 * This callback function indicates the linkkey save from local device
 */
void rsi_bt_on_remote_name_cancel_resp_event(uint16_t resp_status,
                                                 rsi_bt_event_remote_name_request_cancel_t *remote_name_cancel)
{
    memcpy(&bt_remote_device_name, remote_name_cancel, sizeof(rsi_bt_event_remote_name_request_cancel_t));
    rsi_bt_app_set_event(RSI_APP_EVENT_REMOTE_NAME_CANCEL_RESP);
    LOG_EVENT("\nrsi_bt_on_remote_name_cancel_resp_event- resp_status: 0x%X\n",resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_inq_resp_event
 * @brief      invoked when inquiry response is received
 * @param[out] inq_resp, inquiry response information
 * @return     none.
 * @section description
 * This callback function is called when response to do inquiry command is recieved. 
 */
void rsi_bt_on_inq_resp_event(uint16_t resp_status, rsi_bt_event_inquiry_response_t *inq_resp)
{
    memcpy(&bt_rsi_bt_inquiry_response, inq_resp, sizeof(rsi_bt_event_inquiry_response_t));
    rsi_bt_app_set_event(RSI_APP_EVENT_INQ_RESP);
    LOG_EVENT("\nrsi_bt_on_inq_resp_event- resp_status: 0x%X\n",resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_disconn_event
 * @brief      invoked when disconnect event is received
 * @param[out] resp_status, disconnect status/error
 * @param[out] bt_disconnected, disconnected remote device information
 * @return     none.
 * @section description
 * This callback function indicates the disconnected device information
 */
void rsi_bt_on_disconn_event(uint16_t resp_status, rsi_bt_event_disconnect_t *bt_disconnected)
{
    memcpy((int8_t *)bt_remote_dev_addr, bt_disconnected->dev_addr, RSI_DEV_ADDR_LEN);
    rsi_bt_app_set_event(RSI_APP_EVENT_DISCONNECTED);
    LOG_EVENT("\nrsi_bt_on_disconn_event- dev_addr: %s, resp_status: 0x%X\n",
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, bt_disconnected->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_query_services_event
 * @brief      invoked when serch services response event is received
 * @param[out] query_services, response information to get services command.
 * @return     none.
 * @section description
 * This callback function is used to get services of the remote device.
 */
void rsi_bt_on_query_services_event(uint16_t resp_status, rsi_bt_resp_query_services_t *query_services)
{
    (void)(query_services);
    memcpy(&bt_resp_query_services, query_services, sizeof(rsi_bt_resp_query_services_t));
    rsi_bt_app_set_event(RSI_APP_EVENT_QUERY_SERVICES);
    LOG_EVENT("\nrsi_bt_on_query_services_event- resp_status: 0x%X\n",resp_status);
}
/*==============================================*/
/**
 * @fn         rsi_bt_on_search_service_event
 * @brief      invoked when serch services response event is received
 * @param[out] query_services, response information to get services command.
 * @return     none.
 * @section description
 * This callback function is used to get services of the remote device.
 */

void rsi_bt_on_search_service_event (uint16_t resp_status, uint8_t *remote_dev_addr, uint8_t status)
{
	if(resp_status == 0)
			LOG_EVENT("\nrsi_bt_on_search_service_event success %0x\n",resp_status);
		else
			LOG_EVENT("\nrsi_bt_on_search_service_event failed %0x\n",resp_status);
	rsi_bt_app_set_event (RSI_APP_EVENT_SEARCH_SERVICE);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_passkey_display_event
 * @brief      invoked when passkey display event is received
 * @param[out] resp_status, event status
 * @param[out] bt_event_user_passkey_display, passkey information
 * @return     none.
 * @section description
 * This callback function indicates the passkey display event
 */

void rsi_bt_on_passkey_display_event(uint16_t resp_status, rsi_bt_event_user_passkey_display_t *bt_event_user_passkey_display)
{
    rsi_bt_app_set_event(RSI_APP_EVENT_PASSKEY_DISPLAY);
    uint8_t ix;
    // //rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, bt_event_user_passkey_display->passkey);
    // memcpy(bt_data, bt_event_user_passkey_display->passkey, 4);
    for (ix = 0; ix < 4; ix++) {
        LOG_PRINT(" 0x%02x,", bt_event_user_passkey_display->passkey[ix]);
    }
    LOG_EVENT("\nrsi_bt_on_passkey_display_event- passkey: %d, resp_status: 0x%X\n", 
                            *((uint32_t *)bt_event_user_passkey_display->passkey), resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_confirm_request_event
 * @brief      invoked when ssp confirm request event is received
 * @param[out] resp_status, event status
 * @param[out] ssp_complete, secure simple pairing requested remote device information
 * @return     none.
 * @section description
 * This callback function indicates the ssp confirm event
 */
void rsi_bt_on_confirm_request_event(uint16_t resp_status,
                               rsi_bt_event_user_confirmation_request_t *user_confirmation_request)
{
    rsi_bt_app_set_event(RSI_APP_EVENT_CONFIRM_REQUEST);
    LOG_EVENT("\nrsi_bt_on_confirm_request_event- confirmation_value: %d, resp_status: 0x%X\n", 
                        user_confirmation_request->confirmation_value, resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_passkey_request_event
 * @brief      invoked when passkey request event is received
 * @param[out] resp_status, event status
 * @param[out] user_passkey_request, passkey information
 * @return     none.
 * @section description
 * This callback function indicates the passkey request event
 */
void rsi_bt_on_passkey_request_event(uint16_t resp_status, rsi_bt_event_user_passkey_request_t *user_passkey_request)
{
    memcpy((int8_t *)bt_remote_dev_addr, user_passkey_request->dev_addr, RSI_DEV_ADDR_LEN);
    rsi_bt_app_set_event(RSI_APP_EVENT_PASSKEY_REQUEST);
    LOG_EVENT("\nrsi_bt_on_passkey_request_event- dev_addr: %s, resp_status: 0x%X\n", 
                 rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, user_passkey_request->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_ssp_complete_event
 * @brief      invoked when ssp complete event is received
 * @param[out] resp_status, event status
 * @param[out] ssp_complete, secure simple pairing information
 * @return     none.
 * @section description
 * This callback function indicates the spp status
 */
void rsi_bt_on_ssp_complete_event(uint16_t resp_status, rsi_bt_event_ssp_complete_t *ssp_complete)
{
    memcpy((int8_t *)bt_remote_dev_addr, ssp_complete->dev_addr, RSI_DEV_ADDR_LEN);
    rsi_bt_app_set_event(RSI_APP_EVENT_SSP_COMPLETE);
    LOG_EVENT("\nrsi_bt_on_ssp_complete_event- dev_addr: %s, resp_status: 0x%X\n", 
                 rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, ssp_complete->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_mode_change_event
 * @brief      invoked when mode is changed event is received
 * @param[out] mode_change, mode related information
 * @return     none.
 * @section description
 * This callback function indicates the mode change in BT device.
 */

void rsi_bt_on_mode_change_event (uint16_t resp_status, rsi_bt_event_mode_change_t  *mode_change)
{
    sniff_mode = mode_change->current_mode;
    memcpy((int8_t *)bt_remote_dev_addr, mode_change->dev_addr, RSI_DEV_ADDR_LEN);
    rsi_bt_app_set_event (RSI_APP_EVENT_MODE_CHANGED);
	LOG_EVENT("\nrsi_bt_on_mode_change_event- dev_addr: %s, resp_status: 0x%X, sniff_mode: %d\n", 
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, mode_change->dev_addr),resp_status, sniff_mode);
}
/*==============================================*/
/**
 * @fn         rsi_bt_on_sniff_subrating_event
 * @brief      invoked when mode is changed(sniff subrating) event is received
 * @param[out] mode_change, mode related information
 * @return     none.
 * @section description
 * This callback function indicates the mode change in BT device.
 */
void rsi_bt_on_sniff_subrating_event (uint16_t resp_status,rsi_bt_event_sniff_subrating_t  *mode_change)
{
	memcpy((int8_t *)bt_remote_dev_addr, mode_change->dev_addr, RSI_DEV_ADDR_LEN);
    rsi_bt_app_set_event (RSI_APP_EVENT_SNIFF_SUBRATING);
    LOG_EVENT("\nrsi_bt_on_sniff_subrating_event- dev_addr: %s, resp_status: 0x%X\n", 
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, mode_change->dev_addr),resp_status);
}


void rsi_bt_on_role_change_event(uint16_t resp_status, rsi_bt_event_role_change_t *role_change_status)
{
	if(resp_status == 0)
		LOG_EVENT("\nrsi_bt_on_role_change_event success; role:%d\n",role_change_status->role);
	else
		LOG_EVENT("\nrsi_bt_on_role_change_event failed %x\n",resp_status);
	rsi_bt_app_set_event (RSI_APP_EVENT_ROLE_CHANGE);

}
/*==============================================*/
/**
 * @fn         rsi_bt_on_spp_connect
 * @brief      invoked when spp profile connected event is received
 * @param[out] spp_connect, spp connected remote device information
 * @return     none.
 * @section description
 * This callback function indicates the spp connected remote device information
 */
void rsi_bt_on_spp_connect(uint16_t resp_status, rsi_bt_event_spp_connect_t *spp_connect)
{
    memcpy((int8_t *)bt_remote_dev_addr, spp_connect->dev_addr, RSI_DEV_ADDR_LEN);
    rsi_bt_app_set_event(RSI_APP_EVENT_SPP_CONN);
    LOG_EVENT("\nrsi_bt_on_spp_connect- dev_addr: %s, resp_status: 0x%X\n", 
                 rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, spp_connect->dev_addr),resp_status);
}


/*==============================================*/
/**
 * @fn         rsi_bt_on_spp_disconnect
 * @brief      invoked when spp profile disconnected event is received
 * @param[out] spp_disconn, spp disconnected remote device information
 * @return     none.
 * @section description
 * This callback function indicates the spp disconnected event
 */
void rsi_bt_on_spp_disconnect(uint16_t resp_status, rsi_bt_event_spp_disconnect_t *spp_disconn)
{
    memcpy((int8_t *)bt_remote_dev_addr, spp_disconn->dev_addr, RSI_DEV_ADDR_LEN);
    rsi_bt_app_set_event(RSI_APP_EVENT_SPP_DISCONN);
    LOG_EVENT("\nrsi_bt_on_spp_disconnect- dev_addr: %s, resp_status: 0x%X\n", 
                 rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, spp_disconn->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_spp_data_rx
 * @brief      invoked when spp data rx event is received
 * @param[out] spp_receive, spp data from remote device
 * @return     none.
 * @section description
 * This callback function indicates the spp data received event
 */
void rsi_bt_on_spp_data_rx(uint16_t resp_status, rsi_bt_event_spp_receive_t *spp_receive)
{
    uint16_t ix;
    bt_data_len = spp_receive->data_len;
    memcpy(bt_data, spp_receive->data, spp_receive->data_len);
    rsi_bt_app_set_event(RSI_APP_EVENT_SPP_RX);
    for (ix = 0; ix < spp_receive->data_len; ix++) {
        LOG_PRINT(" 0x%02x,", spp_receive->data[ix]);
    }
    LOG_EVENT("\nrsi_bt_on_spp_data_rx- data: %s, resp_status: 0x%X\n", spp_receive->data,resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_a2dp_connect
 * @brief      invoked when a2dp profile connected event is received
 * @param[out] a2dp_connect, a2dp connected remote device information
 * @return     none.
 * @section description
 * This callback function indicates the a2dp connected remote device information
 */
void rsi_bt_on_a2dp_connect(uint16_t resp_status, rsi_bt_event_a2dp_connect_t *a2dp_connect)
{
    if (resp_status == 0) {
        app_state |= (1 << A2DP_CONNECTED);
        memcpy((int8_t *)bt_remote_dev_addr, a2dp_connect->dev_addr, RSI_DEV_ADDR_LEN);
        rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_CONN);
    }
    LOG_EVENT("\nrsi_bt_on_a2dp_connect- dev_addr %s, resp_status: 0x%X\n", 
                rsi_6byte_dev_address_to_ascii((int8_t *)bt_str_conn_bd_addr, a2dp_connect->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_a2dp_disconnect
 * @brief      invoked when a2dp profile disconnected event is received
 * @param[out] a2dp_disconnect, a2dp disconnected remote device information
 * @return     none.
 * @section description
 * This callback function indicates the a2dp disconnected remote device information
 */
void rsi_bt_on_a2dp_disconnect(uint16_t resp_status, rsi_bt_event_a2dp_disconnect_t *a2dp_disconnect)
{
    if (resp_status == 0) {
        app_state &= ~(1 << A2DP_CONNECTED);
        memcpy((int8_t *)bt_remote_dev_addr, a2dp_disconnect->dev_addr, RSI_DEV_ADDR_LEN);
        rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_DISCONN);
    }
    LOG_EVENT("\nrsi_bt_on_a2dp_disconnect- dev_addr %s, resp_status: 0x%X\n", 
                rsi_6byte_dev_address_to_ascii((int8_t *)bt_str_conn_bd_addr, a2dp_disconnect->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_a2dp_configure
 * @brief      invoked when a2dp profile configured event is received
 * @param[out] a2dp_connect, a2dp configured remote device information
 * @return     none.
 * @section description
 * This callback function indicates the a2dp configured remote device information
 */
void rsi_bt_on_a2dp_configure(uint16_t resp_status, rsi_bt_event_a2dp_configure_t *a2dp_configure)
{
    memcpy((int8_t *)bt_remote_dev_addr, a2dp_configure->dev_addr, RSI_DEV_ADDR_LEN);
    rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_CONFIGURE);
    LOG_EVENT("\nrsi_bt_on_a2dp_configure- dev_addr %s, resp_status: 0x%X\n", 
                rsi_6byte_dev_address_to_ascii((int8_t *)bt_str_conn_bd_addr, a2dp_configure->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_a2dp_open
 * @brief      invoked when a2dp profile open event is received
 * @param[out] a2dp_open, a2dp open remote device information
 * @return     none.
 * @section description
 * This callback function indicates the a2dp open remote device information
 */
void rsi_bt_on_a2dp_open(uint16_t resp_status, rsi_bt_event_a2dp_open_t *a2dp_oen)
{   
    if (resp_status == 0) {
        app_state |= (1 << A2DP_STREAM_OPEN);
        memcpy((int8_t *)bt_remote_dev_addr, a2dp_oen->dev_addr, RSI_DEV_ADDR_LEN);
        rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_OPEN);
    }
    LOG_EVENT("\nrsi_bt_on_a2dp_open- dev_addr: %s, resp_status: 0x%X\n", 
                rsi_6byte_dev_address_to_ascii((int8_t *)bt_str_conn_bd_addr, a2dp_oen->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_a2dp_start
 * @brief      invoked when a2dp profile start event is received
 * @param[out] a2dp_start, a2dp start remote device information
 * @return     none.
 * @section description
 * This callback function indicates the a2dp start remote device information
 */
void rsi_bt_on_a2dp_start(uint16_t resp_status, rsi_bt_event_a2dp_start_t *a2dp_start)
{
    uint32_t freq = 0;
    if (resp_status == RSI_SUCCESS) {
        sample_freq = freq = a2dp_start->sample_freq;
        rem_mtu_size = (a2dp_start->rem_mtu_size > DEFAULT_MTU_SIZE) ? (a2dp_start->rem_mtu_size) : DEFAULT_MTU_SIZE;
        headset_max_mtu_size = a2dp_start->rem_mtu_size;
        rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_START);
        app_state |= (1 << A2DP_STREAM_START);
    }
    update_modified_mtu_size(rem_mtu_size);
    LOG_PRINT("\rsi_bt_on_a2dp_start- bt_str_conn_bd_addr: %s, resp status: 0x%x, Sampling_Freq: %d, MTU: %d\n", 
                        bt_str_conn_bd_addr, resp_status, freq, rem_mtu_size);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_a2dp_suspend
 * @brief      invoked when a2dp profile suspend event is received
 * @param[out] a2dp_suspend, a2dp suspend remote device information
 * @return     none.
 * @section description
 * This callback function indicates the a2dp suspend remote device information
 */
void rsi_bt_on_a2dp_suspend(uint16_t resp_status, rsi_bt_event_a2dp_suspend_t *a2dp_suspend)
{
    memcpy(bt_remote_dev_addr, a2dp_suspend->dev_addr, RSI_DEV_ADDR_LEN);
    rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_SUSPEND);
    LOG_EVENT("\nrsi_bt_on_a2dp_suspend- dev_addr %s, resp_status: 0x%X\n", 
                rsi_6byte_dev_address_to_ascii((int8_t *)bt_str_conn_bd_addr, a2dp_suspend->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_a2dp_abort
 * @brief      invoked when a2dp profile abort event is received
 * @param[out] a2dp_abort, a2dp abort remote device information
 * @return     none.
 * @section description
 * This callback function indicates the a2dp abort remote device information
 */
void rsi_bt_on_a2dp_abort(uint16_t resp_status, rsi_bt_event_a2dp_abort_t *a2dp_abort)
{
    memcpy((int8_t *)bt_remote_dev_addr, a2dp_abort->dev_addr, RSI_DEV_ADDR_LEN);
    rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_ABORT);
    LOG_EVENT("\nrsi_bt_on_a2dp_abort- dev_addr: %s, resp_status: 0x%X\n", 
            rsi_6byte_dev_address_to_ascii((int8_t *)bt_str_conn_bd_addr, a2dp_abort->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_a2dp_close
 * @brief      invoked when a2dp profile close event is received
 * @param[out] a2dp_close, a2dp close remote device information
 * @return     none.
 * @section description
 * This callback function indicates the a2dp close remote device information
 */
void rsi_bt_on_a2dp_close(uint16_t resp_status, rsi_bt_event_a2dp_close_t *a2dp_close)
{
    memcpy((int8_t *)bt_remote_dev_addr, a2dp_close->dev_addr, RSI_DEV_ADDR_LEN);
    rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_CLOSE);
    LOG_EVENT("\nrsi_bt_on_a2dp_close- dev_addr: %s, resp_status: 0x%X\n", 
            rsi_6byte_dev_address_to_ascii((int8_t *)bt_str_conn_bd_addr, a2dp_close->dev_addr),resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_a2dp_encode_data
 * @brief      invoked when a2dp profile audio encode data event is received
 * @param[out] a2dp_encode_data, a2dp audio data information
 * @return     none.
 * @section description
 * This callback function indicates the a2dp audio data recived from remote device information
 */
void rsi_bt_on_a2dp_encode_data(uint16_t resp_status, rsi_bt_event_a2dp_encode_data_t *a2dp_encode_data)
{
    rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_SBC_DATA);
    LOG_EVENT("\nrsi_bt_on_a2dp_encode_data- resp_status: 0x%X\n", resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_a2dp_pcm_data
 * @brief      invoked when a2dp profile audio encode data event is received
 * @param[out] a2dp_encode_data, a2dp audio data information
 * @return     none.
 * @section description
 * This callback function indicates the a2dp audio data recived from remote device information
 */
void rsi_bt_on_a2dp_pcm_data(uint16_t resp_status, rsi_bt_event_a2dp_pcm_data_t *a2dp_pcm_data)
{
    rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_PCM_DATA);
    LOG_EVENT("\nrsi_bt_on_a2dp_pcm_data- resp_status: 0x%X\n", resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_a2dp_more_data_req
 * @brief      invoked when a2dp profile configured event is received
 * @param[out] a2dp_connect, a2dp configured remote device information
 * @return     none.
 * @section description
 * This callback function indicates the a2dp configured remote device information
 */
void rsi_bt_on_a2dp_more_data_req(uint16_t resp_status, rsi_bt_event_a2dp_more_data_req_t *a2dp_more_data_req)
{
  if (resp_status == RSI_SUCCESS) {
    if (app_state & (1 << A2DP_STREAM_START)) {
      memcpy((int8_t *)bt_remote_dev_addr, a2dp_more_data_req->dev_addr, RSI_DEV_ADDR_LEN);
      /* No. of SBC bytes required to receive more data request
			 * Ex1:for 2DH5 Packet (MTU=672) for Bitpool=53, 595 (5*119) is the maximum SBC bytes can be sent to RS9116
			 *     then this number will be 595*3 (Assuming RS9116 stack has 3 buffers available)
			 * Ex2:for 3DH5 Packet (MTU=1021) for Bitpool=53, 952 (8*119) is the maximum SBC bytes can be sent to RS9116
			 *     then this number will be 952*5 (Assuming RS9116 stack has 5 buffers available)
			 */
      NbrBytesReqd = a2dp_more_data_req->NbrBytesReqd;
      rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_MORE_DATA_REQ);
    }
  }
}

/**
 * @fn         rsi_bt_on_a2dp_reconfig
 * @brief      invoked when a2dp profile reconfig event is received
 * @param[out] a2dp_suspend, a2dp suspend remote device information
 * @return     none.
 * @section description
 * This callback function indicates the a2dp suspend remote device information
 */
void rsi_bt_on_a2dp_reconfig(uint16_t resp_status, rsi_bt_event_a2dp_reconfig_t *a2dp_reconfig)
{
    if (resp_status == 0) {
        rsi_bt_app_set_event(RSI_APP_EVENT_A2DP_RECONFIG);
    }
    LOG_EVENT("\nrsi_bt_on_a2dp_reconfig- bt_str_conn_bd_addr: %s, resp_status: 0x%x\n",
            bt_str_conn_bd_addr,
            a2dp_reconfig->resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_app_on_avrcp_connect
 * @brief       invoked when avrcp connected event is received
 * @param[out] avrcp_conn, remote device bdaddress
 * @return     none.
 * @section description
 * This callback function indicates the avrcp connected event
 */
void rsi_bt_app_on_avrcp_connect(uint16_t resp_status, rsi_bt_event_avrcp_connect_t *avrcp_connect)
{
  if (resp_status == 0) {
    app_state |= (1 << AVRCP_CONNECTED);
    rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_CONN);
  }
  memcpy(bt_remote_dev_addr, avrcp_connect->dev_addr, RSI_DEV_ADDR_LEN);
  LOG_EVENT("\nrsi_bt_app_on_avrcp_connect- bt_str_conn_bd_addr: %s, resp status: 0x%x\n",
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, avrcp_connect->dev_addr),
            resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_app_on_avrcp_disconnect
 * @brief       invoked when avrcp disconnected event is received
 * @param[out] avrcp_disconn, remote device bdaddress
 * @return     none.
 * @section description
 * This callback function indicates the avrcp disconnected event
 */
void rsi_bt_app_on_avrcp_disconnect(uint16_t resp_status, rsi_bt_event_avrcp_disconnect_t *avrcp_disconn)
{
  if (resp_status == 0) {
    app_state &= ~(1 << AVRCP_CONNECTED);
    rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_DISCONN);
  }
  memcpy(bt_remote_dev_addr, avrcp_disconn->dev_addr, RSI_DEV_ADDR_LEN);
  LOG_EVENT("\nrsi_bt_app_on_avrcp_disconnect- bt_str_conn_bd_addr: %s, resp status: 0x%x\n",
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, avrcp_disconn->dev_addr),
            resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_app_on_avrcp_play
 * @brief      invoked when avrcp previous event is play 
 * @param[out] avrcp play,remote device bdaddress
 * @return     none.
 * @section description
 * This callback function indicates the avrcp play event
 */
void rsi_bt_app_on_avrcp_play(uint16_t resp_status, rsi_bt_event_avrcp_play_t *avrcp_play)
{
  if (avrcp_play->status_flag == RSI_BUTTON_RELEASED) {
    rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_PLAY);
  }
  memcpy(bt_remote_dev_addr, avrcp_play->dev_addr, RSI_DEV_ADDR_LEN);
  LOG_EVENT("\nrsi_bt_app_on_avrcp_play- bt_str_conn_bd_addr: %s, resp status: 0x%x, status_flag: 0x%x\n",
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, avrcp_play->dev_addr),
            resp_status,
            avrcp_play->status_flag);
}

/*==============================================*/
/**
 * @fn         rsi_bt_app_on_avrcp_pause
 * @brief      invoked when avrcp pause event is received
 * @param[out] avrcp pause,remote device bdaddress
 * @return     none.
 * @section description
 * This callback function indicates the avrcp pause event
 */
void rsi_bt_app_on_avrcp_pause(uint16_t resp_status, rsi_bt_event_avrcp_pause_t *avrcp_pause)
{
    if (avrcp_pause->status_flag == RSI_BUTTON_RELEASED) {
        rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_PAUSE);
    }
    memcpy(bt_remote_dev_addr, avrcp_pause->dev_addr, RSI_DEV_ADDR_LEN);
    LOG_EVENT("\nrsi_bt_app_on_avrcp_pause- bt_str_conn_bd_addr: %s, resp status: 0x%x, status_flag 0x%x\n",
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, avrcp_pause->dev_addr),
            resp_status,
            avrcp_pause->status_flag);
}

/*==============================================*/
/**
 * @fn         rsi_bt_app_on_avrcp_stop
 * @brief      invoked when avrcp stop event is received
 * @param[out] avrcp stop,remote device bdaddress
 * @return     none.
 * @section description
 * This callback function indicates the avrcp stop event
 */
void rsi_bt_app_on_avrcp_stop(uint16_t resp_status, rsi_bt_event_avrcp_stop_t *avrcp_stop)
{
  //rsi_bt_app_set_event (RSI_APP_EVENT_AVRCP_STOP);
  memcpy(bt_remote_dev_addr, avrcp_stop->dev_addr, RSI_DEV_ADDR_LEN);
  LOG_EVENT("\nrsi_bt_app_on_avrcp_stop- bt_str_conn_bd_addr: %s, resp status: 0x%x\n",
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, avrcp_stop->dev_addr),
            resp_status);

  return;
}

/*==============================================*/
/**
 * @fn         rsi_bt_app_on_avrcp_next
 * @brief      invoked when avrcp next event is received
 * @param[out] avrcp pause,remote device bdaddress
 * @return     none.
 * @section description
 * This callback function indicates the avrcp next event
 */
void rsi_bt_app_on_avrcp_next(uint16_t resp_status, rsi_bt_event_avrcp_next_t *avrcp_next)
{
  if (avrcp_next->status_flag == RSI_BUTTON_RELEASED) {
    rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_NEXT);
  }
  memcpy(bt_remote_dev_addr, avrcp_next->dev_addr, RSI_DEV_ADDR_LEN);
  LOG_EVENT("\nrsi_bt_app_on_avrcp_next- bt_str_conn_bd_addr: %s, resp status: 0x%x, status_flag 0x%x\n",
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, avrcp_next->dev_addr),
            resp_status,
            avrcp_next->status_flag);
}

/*==============================================*/
/**
 * @fn         rsi_bt_app_on_avrcp_previous
 * @brief      invoked when avrcp previous event is received
 * @param[out] avrcp pause,remote device bdaddress
 * @return     none.
 * @section description
 * This callback function indicates the avrcp previous event
 */
void rsi_bt_app_on_avrcp_previous(uint16_t resp_status, rsi_bt_event_avrcp_previous_t *avrcp_prev)
{
  if (avrcp_prev->status_flag == RSI_BUTTON_RELEASED) {
    rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_PREVIOUS);
  }
  memcpy(bt_remote_dev_addr, avrcp_prev->dev_addr, RSI_DEV_ADDR_LEN);
  LOG_EVENT("\nrsi_bt_app_on_avrcp_previous- bt_str_conn_bd_addr: %s, resp status: 0x%x, status_flag 0x%x\n",
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, avrcp_prev->dev_addr),
            resp_status,
            avrcp_prev->status_flag);
}

/*==============================================*/
/**
 * @fn         rsi_bt_app_on_avrcp_vol_up
 * @brief      invoked when avrcp volume up event is received
 * @param[out] avrcp volume up,remote device bdaddress
 * @return     none.
 * @section description
 * This callback function indicates the avrcp volume up event
 */
void rsi_bt_app_on_avrcp_vol_up(uint16_t resp_status, rsi_bt_event_avrcp_vol_up_t *avrcp_vol_up)
{
  if (avrcp_vol_up->status_flag == RSI_BUTTON_RELEASED) {
    rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_VOL_UP);
  }
  memcpy(bt_remote_dev_addr, avrcp_vol_up->dev_addr, RSI_DEV_ADDR_LEN);
  LOG_EVENT("\nrsi_bt_app_on_avrcp_vol_up- bt_str_conn_bd_addr: %s, resp status: 0x%x, status_flag 0x%x\n",
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, avrcp_vol_up->dev_addr),
            resp_status,
            avrcp_vol_up->status_flag);
}

/*==============================================*/
/**
 * @fn         rsi_bt_app_on_avrcp_vol_down
 * @brief      invoked when avrcp volume down event is received
 * @param[out] avrcp volume down,remote device bdaddress
 * @return     none.
 * @section description
 * This callback function indicates the avrcp volume down event
 */
void rsi_bt_app_on_avrcp_vol_down(uint16_t resp_status, rsi_bt_event_avrcp_vol_down_t *avrcp_vol_down)
{
  if (avrcp_vol_down->status_flag == RSI_BUTTON_RELEASED) {
    rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_VOL_DOWN);
  }
  memcpy(bt_remote_dev_addr, avrcp_vol_down->dev_addr, RSI_DEV_ADDR_LEN);
  LOG_EVENT("\nrsi_bt_app_on_avrcp_vol_down- bt_str_conn_bd_addr: %s, resp status: 0x%x, status_flag 0x%x\n",
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, avrcp_vol_down->dev_addr),
            resp_status,
            avrcp_vol_down->status_flag);
}


/*==============================================*/
/**
 * @fn         rsi_bt_on_avrcp_notify_event
 * @brief      invoked when avrcp notification event is received 
 * @param[out] avrcp p_notify, player notication event related info
 * @return     none.
 * @section description
 * This callback function indicates the avrcp notification event
 */
void rsi_bt_on_avrcp_notify_event(uint16_t resp_status, rsi_bt_event_avrcp_notify_t *p_notify)
{
  rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_NOTIFY);
  memcpy(&avrcp_notify, p_notify, sizeof(rsi_bt_event_avrcp_notify_t));
  memcpy(bt_remote_dev_addr, p_notify->dev_addr, RSI_DEV_ADDR_LEN);
  LOG_PRINT("\nrsi_bt_on_avrcp_notify_event- bt_str_conn_bd_addr: %s, resp status: 0x%x\n",
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, p_notify->dev_addr),
            resp_status);
}

/*==============================================*/
/**
 * @fn         rsi_bt_on_avrcp_get_cap_event
 * @brief      invoked when AVRCP get capabilities event is received
 * @param[out] resp_status, event status
 * @param[out] ssp_complete, secure simple pairing requested remote device information
 * @return     none.
 * @section description
 * This callback function indicates the ssp confirm event
 */

void rsi_bt_on_avrcp_get_cap_event(uint8_t *bd_addr, uint8_t cap_type)
{
  app_cap_type = cap_type;
  rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_GET_CAP);
  memcpy(bt_remote_dev_addr, bd_addr, RSI_DEV_ADDR_LEN);
  LOG_EVENT("\nrsi_bt_on_avrcp_get_cap_event- bt_str_conn_bd_addr: %s, capability ID: %d\n",
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, bd_addr),
            cap_type);

  return;
}

void rsi_bt_on_avrcp_get_app_supp_atts_event(uint8_t *bd_addr)
{
  rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_GET_ATTS);
  LOG_EVENT("\nrsi_bt_on_avrcp_get_app_supp_atts_event\n");
  return;
}

void rsi_bt_on_avrcp_get_app_suup_att_vals_event(uint8_t *bd_addr, uint8_t att_id)
{
  app_att_id = att_id;
  rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_GET_ATT_VALS);
  LOG_EVENT("\nrsi_bt_on_avrcp_get_app_suup_att_vals_event- att_id: %d\n", att_id);
  return;
}

void rsi_bt_on_avrcp_get_app_cur_att_val_event(rsi_bt_event_avrcp_get_cur_att_val_t *p_att_list)
{
  uint8_t ix;
  memcpy(&app_att_list, p_att_list, sizeof(rsi_bt_event_avrcp_get_cur_att_val_t));
  rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_CUR_ATT_VALS);
  LOG_EVENT("\nrsi_bt_on_avrcp_get_app_cur_att_val_event: nbr_atts: %d, atts: ", p_att_list->nbr_atts);
  for (ix = 0; ix < p_att_list->nbr_atts; ix++) {
    LOG_EVENT("%d, ", p_att_list->atts);
  }
  LOG_EVENT("\n");
  return;
}

void rsi_bt_on_avrcp_set_app_cur_att_val_event(rsi_bt_event_avrcp_set_att_val_t *p_att_list)
{
  uint8_t ix;
  rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_SET_ATT_VALS);
  LOG_EVENT("\nrsi_bt_on_avrcp_set_app_cur_att_val_event- nbr_atts:%d\n", p_att_list->nbr_atts);
  for (ix = 0; ix < p_att_list->nbr_atts; ix++) {
    LOG_EVENT("attid: %d - attvalue: %d \n", p_att_list->att_list[ix].attid, p_att_list->att_list[ix].attvalue);
  }
  LOG_EVENT("\n");
  return;
}

void rsi_bt_on_avrcp_get_app_att_text_event(rsi_bt_event_avrcp_get_cur_att_val_t *p_att_text_list)
{
  uint8_t ix;

  memcpy(&app_att_text_list, p_att_text_list, sizeof(rsi_bt_event_avrcp_get_cur_att_val_t));
  rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_ATT_TEXT);
  LOG_EVENT("\nrsi_bt_on_avrcp_get_app_att_text_event- nbr_atts: %d, atts: ", p_att_text_list->nbr_atts);
  for (ix = 0; ix < p_att_text_list->nbr_atts; ix++) {
    LOG_EVENT("%d, ", p_att_text_list->atts[ix]);
  }
  LOG_EVENT("\n");
  return;
}

void rsi_bt_on_avrcp_get_app_att_vals_text_event(rsi_bt_event_avrcp_vals_text_req_t *p_vals_list)
{
  uint8_t ix;

  memcpy(&app_vals_list, p_vals_list, sizeof(rsi_bt_event_avrcp_vals_text_req_t));
  rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_ATT_VALS_TEXT);
  LOG_EVENT("\nrsi_bt_on_avrcp_get_app_att_vals_text_event- att_id: %d, nbr_vals:%d, vals:",
            p_vals_list->att_id,
            p_vals_list->nbr_vals);
  for (ix = 0; ix < p_vals_list->nbr_vals; ix++) {
    LOG_EVENT("%d, ", p_vals_list->vals);
  }
  LOG_EVENT("\n");
  return;
}

void rsi_bt_on_avrcp_get_song_atts_event(rsi_bt_event_avrcp_ele_att_t *p_song_atts)
{
  uint8_t ix;

  memcpy(&app_song_atts, p_song_atts, sizeof(rsi_bt_event_avrcp_ele_att_t));
  rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_SONG_ATTS);

  if (p_song_atts->nbr_atts == 0) {
    /* all attribute information shall be returned */
    app_song_atts.nbr_atts = BT_AVRCP_MEDIA_ATTR_ID_MAX_COUNT;
    for (ix = BT_AVRCP_MEDIA_ATTR_ID_MEDIA_TITLE; ix <= BT_AVRCP_MEDIA_ATTR_ID_PLAYING_TIME_MS; ix++)
      app_song_atts.ele_atts[ix - 1] = ix;
  }
  LOG_EVENT("\nrsi_bt_on_avrcp_get_song_atts_event\n");
  LOG_EVENT("No. of attrs: %d, attr list:", p_song_atts->nbr_atts);
  for (ix = 0; ix < p_song_atts->nbr_atts; ix++) {
    LOG_EVENT("%d, ", p_song_atts->ele_atts[ix]);
  }
  LOG_EVENT("\n");

  return;
}

void rsi_bt_on_avrcp_get_play_status_event(uint8_t *bd_addr)
{
  rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_PLAY_STATUS);
  memcpy(bt_remote_dev_addr, bd_addr, RSI_DEV_ADDR_LEN);
  LOG_EVENT("\nrsi_bt_on_avrcp_get_play_status_event- bt_str_conn_bd_addr: %s\n", rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, bd_addr));

  return;
}

uint8_t app_event_id[5];
uint8_t app_reg_events;
void rsi_bt_on_avrcp_reg_notify_event(uint8_t *bd_addr, uint8_t event_id)
{
  app_event_id[app_reg_events++] = event_id;
  rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_REG_EVENT);
  memcpy(bt_remote_dev_addr, bd_addr, RSI_DEV_ADDR_LEN);
  LOG_EVENT("\nrsi_bt_on_avrcp_reg_notify_event- bt_str_conn_bd_addr: %s, event ID: %d\n",
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, bd_addr),
            event_id);

  return;
}

void rsi_bt_on_avrcp_set_abs_vol_event(rsi_bt_event_avrcp_set_abs_vol_t *p_abs_vol)
{
  uint8_t abs_vol_per;
  rsi_bt_app_set_event(RSI_APP_EVENT_AVRCP_SET_ABS_VOL);
  memcpy(bt_remote_dev_addr, p_abs_vol->dev_addr, RSI_DEV_ADDR_LEN);
  abs_vol = p_abs_vol->abs_vol;
  /* The value 0x0 corresponds to 0%.
   * The value 0x7F corresponds to 100%. */
  abs_vol_per = (abs_vol * 100) / 0x7f;

  LOG_EVENT("\nrsi_bt_on_avrcp_set_abs_vol_event- bt_str_conn_bd_addr: %s, Vol: %d%\n",
            rsi_6byte_dev_address_to_ascii(bt_str_conn_bd_addr, p_abs_vol->dev_addr),
            abs_vol_per);

  return;
}
/******************* END OF CALLBACK IMPLEMENTATIONS *****************/

void rsi_bt_sniff_mode_command(sl_cli_command_arg_t *arguments){

    char* remote_dev_addr = sl_cli_get_argument_string(arguments, 0);
    uint16_t sniff_max_intv = sl_cli_get_argument_uint16(arguments, 1);
    uint16_t sniff_min_intv = sl_cli_get_argument_uint16(arguments, 2);
    uint16_t sniff_attempt = sl_cli_get_argument_uint16(arguments, 3);
    uint16_t sniff_tout = sl_cli_get_argument_uint16(arguments, 4);

    uint8_t dev_addr[6];
	rsi_ascii_dev_address_to_6bytes_rev(dev_addr, (int8_t*)remote_dev_addr);
    print_status(rsi_bt_sniff_mode(dev_addr, sniff_max_intv, sniff_min_intv, sniff_attempt, sniff_tout));
}

void rsi_bt_sniff_exit_mode_command(sl_cli_command_arg_t *arguments){

    char* remote_dev_addr = sl_cli_get_argument_string(arguments, 0);
    uint8_t dev_addr[6];
	rsi_ascii_dev_address_to_6bytes_rev(dev_addr, (int8_t*)remote_dev_addr);
    print_status(rsi_bt_sniff_exit_mode(dev_addr));
}

void bt_reject_ssp_confirm_command(sl_cli_command_arg_t* arguments)
{
    char* remote_dev_addr = sl_cli_get_argument_string(arguments, 0);
    uint8_t device_address[6];
	rsi_ascii_dev_address_to_6bytes_rev(device_address, (int8_t*)remote_dev_addr);
    print_status(rsi_bt_reject_ssp_confirm(device_address));
}

void bt_spp_disconnect_command(sl_cli_command_arg_t* arguments)
{
    char* remote_dev_addr = sl_cli_get_argument_string(arguments, 0);
    uint8_t device_address[6];
	rsi_ascii_dev_address_to_6bytes_rev(device_address, (int8_t*)remote_dev_addr);
    print_status(rsi_bt_spp_disconnect(device_address));
}

void bt_clear_linkkey_command()
{
    memset(linkkey_bt,'\0',sizeof(linkkey_bt));
    print_status(RSI_ERROR_NONE);
}
