import time
import pytest
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI


def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Enable the wlan and bt power save mode in dut after the connection
        3. Initiates ble in DUT 
        4. Connect to the remote device/connect to the dut

    Author: Jyothi Nagireddy
"""



class BleScan(ThreadBase):
    def __init__(self, wifi_dut, ble_clients=None, bt_client_address=None, ble_scan_interval=None, ble_scan_window=None, filter_type=None
                 ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_clients = ble_clients
        self.bt_client_address = bt_client_address
        self.ble_scan_interval = ble_scan_interval
        self.ble_scan_window = ble_scan_window
        self.filter_type = filter_type

    def run(self):
        logger().info(f" \n\n******************* START SCANNING FROM DUT ***********************\n\n ")
        dut_scan_results = self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.bt_client_address,
                                                                       ble_scan_interval=self.ble_scan_interval,
                                                                       ble_scan_window=self.ble_scan_window, timeout=60)
        logger().info(f"dut_scan_results: {dut_scan_results}")
        time.sleep(60)
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()

        enable_wifi_ps = self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps = self.wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'

        events = self.wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            # if event.event_type == RS9116AsyncEventType.Adv_Report:
                whitelist_data = self.wifi_dut.interfaces.wifi.parse_and_get_whitelist_data(event.event_data)
                assert whitelist_data == "AUTOMATION", "whitelist data not found"
                logger().info(f"\n\n***********character conversion of advertising data*****************\n\n")
                logger().info(f"\n\n***********found advertising data: {whitelist_data}****************\n\n")
                break
    def ble_adv(self):
        logger().info(" **** START ADVERTISEMENT FROM DUT **** ")
        self.wifi_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_filter_type=self.filter_type)
        # enable wlan and bt power save in dut
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        enable_wifi_ps = self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps = self.wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'

        # scan and connect from whitelisted remote device
        ble_white_list_address = self.ble_clients.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.bt_dut_address)
        assert ble_white_list_address, "FAILED TO INITIATE BLE IN REMOTE DEVICE 1"
        time.sleep(5)
        self.ble_clients.interfaces.bluetooth.stop_scanning()
        found_devices = self.ble_clients.interfaces.bluetooth.get_devices()
        logger().info(f" FOUND_DEVICES :*********{found_devices}*****************")
        flag = self.wifi_dut.interfaces.bluetooth.ble_address in found_devices
        assert flag, "DUT ISN'T LISTED IN SCAN RESULTS"
        if flag:
            logger().info("REMOTE DEVICE 1 IS VISIBLE IN SCAN RESULTS")
        logger().info("....CONNECT TO DUT AND MAC ADDRESS....")
        connect_state = self.ble_clients.interfaces.bluetooth.pair_and_connect(self.bt_dut_address, timeout=120)
        logger().info(f"THE STATE IS: {connect_state}")
        assert connect_state, "UNABLE TO CONNECT TO THE GIVEN ADDRESS"
        time.sleep(10)

    def check_device_state(self):
        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
        return state_int




pytestmark = [
  pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0  | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    },
)
  ]
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_whitelist_with_adv_data_index5_C19949(wifi_dut, ble_client, sl_collections, ble_clients):
    try:
        logger().info(f"\n\n**************Start ble on DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None

        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=5, compare_data_length=10,
                                                            data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I', 'O',
                                                                       'N'])

        logger().info(f"\n\n************Start advertise on advertise******************\n\n")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_whitelist_with_hci_tool(
            bt_dut_address=bt_dut_address,
            hci_whitelist_adv_data="0x1F "  # Number of bytes that follow in the advertisement(payload length)
                                   "0x00 0x00 0x00 0x00 0x00 "  # prepend 00s at start, based on whitelist data index(5 here)
                                   "0x41, 0x55, 0x54, 0x4F, 0x4D, 0x41 "  # whitelist data
                                   "0x54, 0x49, 0x4F, 0x4E, 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00",
            # append 00s at end, based on length of payload
            hci_adv_params="0x20 0x00 "  # Advertising_Interval_Min
                           "0x20 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy

        )
        assert bt_client_address is not None
        time.sleep(10)

        blescan_obj = BleScan(wifi_dut, ble_clients, ble_scan_interval=256, ble_scan_window=80)
        blescan_obj.start()
        blescan_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_whitelist_with_adv_data_index10_C19951(wifi_dut, ble_client, sl_collections):
    try:
        logger().info(f"\n\n**************Start ble on DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=10, compare_data_length=10,
                                                            data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I', 'O',
                                                                       'N'])

        logger().info(f"\n\n************Start advertise on ble client******************\n\n")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_whitelist_with_hci_tool(
            bt_dut_address=bt_dut_address,
            hci_whitelist_adv_data="0x1F "  # Number of bytes that follow in the advertisement(payload length)
                                   "0x00 0x00 0x00 0x00 0x00 "  # prepend 00s at start, based on whitelist data index(10th here)
                                   "0x00, 0x00, 0x00, 0x00, 0x00, 0x41 "  # whitelist data
                                   "0x55, 0x54, 0x4F, 0x4D, 0x41 0x54 0x49 0x4F 0x4E 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00",
            # append 00s at end, based on length of payload
            hci_adv_params="0x20 0x00 "  # Advertising_Interval_Min
                           "0x20 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy

        )
        assert bt_client_address is not None
        time.sleep(10)

        blescan_obj = BleScan(wifi_dut, ble_scan_interval=256, ble_scan_window=80)
        blescan_obj.start()
        blescan_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_whitelist_with_adv_data_index20_C19953(wifi_dut, ble_client, sl_collections):
    try:
        logger().info(f"\n\n**************Start ble on DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=20, compare_data_length=10,
                                                            data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I', 'O',
                                                                       'N'])

        logger().info(f"\n\n************Start advertise on ble client******************\n\n")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_whitelist_with_hci_tool(
            bt_dut_address=bt_dut_address,
            hci_whitelist_adv_data="0x1F "  # Number of bytes that follow in the advertisement(payload length)
                                   "0x00 0x00 0x00 0x00 0x00 "  # prepend 00s at start, based on whitelist data index(20th here)
                                   "0x00, 0x00, 0x00, 0x00, 0x00, 0x00 "  # whitelist data
                                   "0x00, 0x00, 0x00, 0x00, 0x00 0x00 0x00 0x00 0x00 0x41 0x55 0x54 0x4F 0x4D 0x41 0x54 0x49 0x4F 0x4E 0x00",
            # append 00s at end, based on length of payload
            hci_adv_params="0x20 0x00 "  # Advertising_Interval_Min
                           "0x20 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy

        )
        assert bt_client_address is not None
        time.sleep(10)

        blescan_obj = BleScan(wifi_dut, ble_scan_interval=256, ble_scan_window=80)
        blescan_obj.start()
        blescan_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_whitelist_with_adv_data_index25_C19954(wifi_dut, ble_client, sl_collections):
    try:
        logger().info(f"\n\n**************Start DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None

        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=0, data_compare_index=5, compare_data_length=10,
                                                            data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I', 'O',
                                                                       'N'])

        logger().info(f"\n\n************Start advertise on ble client******************\n\n")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_whitelist_with_hci_tool(
            bt_dut_address=bt_dut_address,
            hci_whitelist_adv_data="0x1F "  # Number of bytes that follow in the advertisement(payload length)
                                   "0x00 0x00 0x00 0x00 0x00 "  # prepend 00s at start, based on whitelist data index(5 here)
                                   "0x41, 0x55, 0x54, 0x4F, 0x4D, 0x41 "  # whitelist data
                                   "0x54, 0x49, 0x4F, 0x4E, 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00",
            # append 00s at end, based on length of payload
            hci_adv_params="0x20 0x00 "  # Advertising_Interval_Min
                           "0x20 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy

        )
        assert bt_client_address is not None
        time.sleep(10)

        blescan_obj = BleScan(wifi_dut, bt_client_address=bt_client_address, ble_scan_interval=256, ble_scan_window=80)
        blescan_obj.start()
        blescan_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_whitelist_adv_data_index15_2Advertisers_C19952(wifi_dut, ble_client, ble_clients, sl_collections):
    assert len(ble_clients) >= 2
    ble_client1 = ble_clients[1]
    ble_client2 = ble_clients[0]
    try:
        logger().info(f"\n\n**************Start DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=15, compare_data_length=10,
                                                            data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I', 'O',
                                                                       'N'])
        logger().info(f"\n\n************Start advertise on ble client1******************\n\n")
        bt_client_address1 = ble_client1.interfaces.bluetooth.start_smp_adv_whitelist_with_hci_tool(
            bt_dut_address=bt_dut_address,
            hci_whitelist_adv_data="0x1F "  # Number of bytes that follow in the advertisement(payload length)
                                   "0x00 0x00 0x00 0x00 0x00 "  # prepend 00s at start, based on whitelist data index(15 here)
                                   "0x00, 0x00, 0x00, 0x00, 0x00, 0x00 "  # whitelist data
                                   "0x00, 0x00, 0x00, 0x00, 0x41 0x55 0x54 0x4F 0x4D 0x41 0x54 0x49 0x4F 0x4E 0x00 0x00 0x00 0x00 0x00 0x00",
            # append 00s at end, based on length of payload
            hci_adv_params="0x20 0x00 "  # Advertising_Interval_Min
                           "0x20 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy

        )
        logger().info(f"\n\n************Start advertise on ble client2******************\n\n")
        bt_client_address2 = ble_client2.interfaces.bluetooth.start_smp_adv_whitelist_with_hci_tool(
            bt_dut_address=bt_dut_address,
            hci_whitelist_adv_data="0x1F "  # Number of bytes that follow in the advertisement(payload length)
                                   "0x00 0x00 0x00 0x00 0x00 "  # prepend 00s at start, based on whitelist data index(5 here)
                                   "0x00, 0x00, 0x00, 0x00, 0x00, 0x00 "  # whitelist data
                                   "0x00, 0x00, 0x00, 0x00, 0x41 0x55 0x54 0x4F 0x4D 0x41 0x54 0x49 0x4F 0x4E 0x00 0x00 0x00 0x00 0x00 0x00",
            # append 00s at end, based on length of payload
            hci_adv_params="0x20 0x00 "  # Advertising_Interval_Min
                           "0x20 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy

        )
        blescan_obj = BleScan(wifi_dut, ble_scan_interval=256, ble_scan_window=80)
        blescan_obj.start()
        blescan_obj.wait_for_exit()
        blescan_obj = BleScan(wifi_dut, ble_scan_interval=256, ble_scan_window=80)
        blescan_obj.start()
        blescan_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_aggressive_interval_whitelist_adv_data_index5_C19956(wifi_dut, ble_client, ble_clients, sl_collections):
    try:
        logger().info(f"\n\n**************Start DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=5, compare_data_length=10,
                                                            data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I', 'O',
                                                                       'N'])

        logger().info(f"\n\n************Start ble client******************\n\n")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_whitelist_with_hci_tool(
            bt_dut_address=bt_dut_address,
            hci_whitelist_adv_data="0x1F "  # Number of bytes that follow in the advertisement(payload length)
                                   "0x00 0x00 0x00 0x00 0x00 "  # prepend 00s at start, based on whitelist data index(5 here)
                                   "0x41, 0x55, 0x54, 0x4F, 0x4D, 0x41 "  # whitelist data
                                   "0x54, 0x49, 0x4F, 0x4E, 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00",
            # append 00s at end, based on length of payload
            hci_adv_params="0x20 0x00 "  # Advertising_Interval_Min
                           "0x20 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy

        )
        blescan_obj = BleScan(wifi_dut, ble_scan_interval=160, ble_scan_window=80)
        blescan_obj.start()
        blescan_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_aggressive_interval_whitelist_adv_data_2advertisers_index5_C19957(wifi_dut, ble_client, ble_clients, sl_collections):
    assert len(ble_clients) >= 2
    ble_client1 = ble_clients[1]
    ble_client2 = ble_clients[0]
    try:
        logger().info(f"\n\n**************Start DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=5, compare_data_length=10,
                                                            data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I', 'O',
                                                                       'N'])
        logger().info(f"\n\n************Start ble client******************\n\n")
        bt_client_address1 = ble_client1.interfaces.bluetooth.start_smp_adv_whitelist_with_hci_tool(
            bt_dut_address=bt_dut_address,
            hci_whitelist_adv_data="0x1F "  # Number of bytes that follow in the advertisement(payload length)
                                   "0x00 0x00 0x00 0x00 0x00 "  # prepend 00s at start, based on whitelist data index(5 here)
                                   "0x41, 0x55, 0x54, 0x4F, 0x4D, 0x41 "  # whitelist data
                                   "0x54, 0x49, 0x4F, 0x4E, 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00",
            # append 00s at end, based on length of payload
            hci_adv_params="0x20 0x00 "  # Advertising_Interval_Min
                           "0x20 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy

        )
        bt_client_address2 = ble_client2.interfaces.bluetooth.start_smp_adv_whitelist_with_hci_tool(
            bt_dut_address=bt_dut_address,
            hci_whitelist_adv_data="0x1F "  # Number of bytes that follow in the advertisement(payload length)
                                   "0x00 0x00 0x00 0x00 0x00 "  # prepend 00s at start, based on whitelist data index(5 here)
                                   "0x41, 0x55, 0x54, 0x4F, 0x4D, 0x41 "  # whitelist data
                                   "0x54, 0x49, 0x4F, 0x4E, 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00",
            # append 00s at end, based on length of payload
            hci_adv_params="0x20 0x00 "  # Advertising_Interval_Min
                           "0x20 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy

        )
        logger().info(f"bt_client_address1: {bt_client_address1}")
        logger().info(f"bt_client_address2: {bt_client_address2}")

        blescan_obj = BleScan(wifi_dut, ble_clients, ble_scan_interval=960, ble_scan_window=640)
        blescan_obj.start()
        blescan_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_dut_master_white_list_remote_device_c19846(wifi_dut, ble_client, rs_helper_ble, sl_collections):
    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_wifi_dut_master_remote_device_directed_connectable.logs_{int(time.time())}"):
        try:
            ble_client.interfaces.bluetooth.close()
            logger().info(f"Start ble DUT and client")
            wifi_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert wifi_dut_address, f"Unable to get wifi_dut_address"
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=wifi_dut_address)
            assert ble_client_address, f"Unable to get ble_client_address"
            time.sleep(5)
            try:
                logger().info(f"****** ADDING WHITELIST BEFORE SCANNING")
                wifi_dut.interfaces.wifi.ble_add_white_list(ble_client_address)
                logger().info(f"Start scanning and connect to ble client")
                wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, ble_scan_filter_type=1,
                                                           timeout=120)
                logger().info("stop scanning")
                wifi_dut.interfaces.bluetooth.ble_stop_scanning()
                time.sleep(5)
                enable_wifi_ps =wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                assert enable_wifi_ps == 0, 'failed to enable wlan power save'
                enable_bt_ps = wifi_dut.interfaces.wifi.enable_bt_power_save(
                    psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                    psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
                assert enable_bt_ps == 0, 'failed to enable bt power save'
                logger().info(f"DUT initiating BLE connection with ble_client device")
                rs_helper_ble.ble_connect_DUT_as_master(wifi_dut=wifi_dut, ble_remote=ble_client,
                                                        wifi_dut_address=wifi_dut_address,
                                                        ble_remote_address=ble_client_address, smp_flag=True)
                logger().info("******** BLE master connection successful ********")

            except Exception as e:
                logger().info("*************** Exception block for stop advertising and stop scanning")
                ble_client.interfaces.bluetooth.stop_advertising()
                wifi_dut.interfaces.wifi.ble_stop_scanning()
                raise e
            ble_obj = BleScan(wifi_dut)
            ble_obj.check_device_state()
            wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
            ble_client.interfaces.bluetooth.stop_advertising()

        except Exception as error:
            sl_collections.exception_handling(wifi_dut, error)

        
    


