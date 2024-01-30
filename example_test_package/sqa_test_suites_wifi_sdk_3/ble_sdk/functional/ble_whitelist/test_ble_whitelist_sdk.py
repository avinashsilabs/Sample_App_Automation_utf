import time
import pytest
import re
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
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
    def __init__(self, wifi_dut, ble_clients=None, ble_dut_address=None, ble_scan_interval=None, ble_scan_window=None,
                 index_compare=None, testcase=None
                 ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_clients = ble_clients
        self.ble_dut_address = ble_dut_address
        self.ble_scan_interval = ble_scan_interval
        self.ble_scan_window = ble_scan_window
        self.index_compare = index_compare
        self.testcase = testcase

    def run(self):
        logger().info(f" \n\n******************* START SCANNING FROM DUT ***********************\n\n ")
        dut_scan_results = self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.ble_dut_address,
                                                                            ble_scan_interval=self.ble_scan_interval,
                                                                            ble_scan_window=self.ble_scan_window,
                                                                            timeout=60)
        logger().info(f"dut_scan_results: {dut_scan_results}")
        time.sleep(60)
        enable_wifi_ps = self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps = self.wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'

        self.wifi_dut.interfaces.wifi.ble_stop_scanning()

    def whitelist_check(self):
        index = ""
        events = self.wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                    adv_data1 = re.split('adv_data:', event.event_data)
                    adv_data_list1 = (adv_data1[1]).split('-')
                    adv_data_list = adv_data_list1[:-1]
                    whitelist_string = ""
                    for data in adv_data_list:
                        if data != '0':
                            data1 = int(data, base=10)
                            ascii_value = chr(data1)
                            whitelist_string = whitelist_string + ascii_value
                    for i in range(len(adv_data_list)):
                        d = chr(int(adv_data_list[i]))
                        if d.isalpha():
                            index = i
                            logger().info(f"*********index found in scan results : {index} ***************")
                            break
                    if self.testcase == "C19954":
                        assert whitelist_string == "GANGA", "whitelist data not found"
                        logger().info(f" Whitelist advertising data is matching..found whitelist data : {whitelist_string}")
                    else:
                        assert whitelist_string == "AUTOMATION", "whitelist data not found"
                        logger().info(f" Whitelist advertising data is matching..found whitelist data : {whitelist_string}")
                    assert index == self.index_compare, "index is not matched"
                    logger().info(f"index is matching")
                    break

    def ble_adv(self, filter_type=None):
        logger().info(" **** START ADVERTISEMENT FROM DUT **** ")
        self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_filter_type=filter_type)
        logger().info(f"enable wlan and bt power save in dut")
        enable_wifi_ps = self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps = self.wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'
        ble_white_list_address = self.ble_clients.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=self.ble_dut_address)
        assert ble_white_list_address, "FAILED TO INITIATE BLE IN REMOTE DEVICE 1"
        time.sleep(5)
        self.ble_clients.interfaces.bluetooth.stop_scanning()
        found_devices = self.ble_clients.interfaces.bluetooth.get_devices()
        logger().info(f" FOUND_DEVICES :*********{found_devices}*****************")
        flag = self.wifi_dut.interfaces.wifi.ble_address in found_devices
        assert flag, "DUT ISN'T LISTED IN SCAN RESULTS"
        if flag:
            logger().info("REMOTE DEVICE 1 IS VISIBLE IN SCAN RESULTS")
        logger().info("....CONNECT TO DUT AND MAC ADDRESS....")
        connect_state = self.ble_clients.interfaces.bluetooth.connect(self.ble_dut_address)
        logger().info(f"THE STATE IS: {connect_state}")
        assert connect_state, "UNABLE TO CONNECT TO THE GIVEN ADDRESS"
        time.sleep(60)

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
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
]


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_whitelist_with_adv_data_index5_C19949(wifi_dut, ble_client, sl_collections, ble_clients):
    try:
        logger().info(f"\n\n**************Start ble on DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        index = 5
        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=index, compare_data_length=10,
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
        blescan_obj = BleScan(wifi_dut, ble_clients, ble_scan_interval=256, ble_scan_window=80, index_compare=index)
        blescan_obj.start()
        blescan_obj.wait_for_exit()
        blescan_obj.whitelist_check()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_whitelist_with_adv_data_index10_C19951(wifi_dut, ble_client, sl_collections):
    try:
        logger().info(f"\n\n**************Start ble on DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        index = 10
        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=index, compare_data_length=10,
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
        blescan_obj = BleScan(wifi_dut, ble_scan_interval=256, ble_scan_window=80, index_compare=index)
        blescan_obj.start()
        blescan_obj.wait_for_exit()
        blescan_obj.whitelist_check()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_whitelist_with_adv_data_index20_C19953(wifi_dut, ble_client, sl_collections):
    try:
        index = 20
        logger().info(f"\n\n**************Start ble on DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=index, compare_data_length=10,
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

        blescan_obj = BleScan(wifi_dut, ble_scan_interval=256, ble_scan_window=80, index_compare=index)
        blescan_obj.start()
        blescan_obj.wait_for_exit()
        blescan_obj.whitelist_check()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_whitelist_with_adv_data_index25_C19954(wifi_dut, ble_client, sl_collections, ble_clients):
    try:
        logger().info(f"\n\n**************Start ble on DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=25, compare_data_length=5,
                                                            data_list=['G', 'A', 'N', 'G', 'A'])

        logger().info(f"\n\n************Start advertise on ble client******************\n\n")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_whitelist_with_hci_tool(
            bt_dut_address=bt_dut_address,
            hci_whitelist_adv_data="0x1F "  # Number of bytes that follow in the advertisement(payload length)
                                   "0x00 0x00 0x00 0x00 0x00 "  # prepend 00s at start, based on whitelist data index(25th here)
                                   "0x00, 0x00, 0x00, 0x00, 0x00, 0x00 "  # whitelist data
                                   "0x00, 0x00, 0x00, 0x00, 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x47 0x41 0x4E 0x47 0x41 0x00",
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
        blescan_obj = BleScan(wifi_dut, ble_clients, ble_scan_interval=256, ble_scan_window=80, index_compare=25,
                              testcase="C19954")
        logger().info(f" \n\n******************* START SCANNING FROM DUT ***********************\n\n ")
        dut_scan_results = wifi_dut.interfaces.wifi.ble_start_scanning(ble_scan_interval=256, ble_scan_window=80,
                                                                       timeout=60)
        time.sleep(60)
        logger().info(f"dut_scan_results: {dut_scan_results}")
        enable_wifi_ps = wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps = wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        blescan_obj.whitelist_check()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_disable_ble_whitelist_with_adv_data_C19950(wifi_dut, ble_client, sl_collections):
    try:
        index = 18
        logger().info(f"\n\n**************Start DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None

        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=0, data_compare_index=18, compare_data_length=10,
                                                            data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I', 'O',
                                                                       'N'])

        logger().info(f"\n\n************Start advertise on ble client******************\n\n")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_whitelist_with_hci_tool(
            bt_dut_address=bt_dut_address,
            hci_whitelist_adv_data="0x1F "  # Number of bytes that follow in the advertisement(payload length)
                                   "0x00 0x00 0x00 0x00 0x00 "  # prepend 00s at start, based on whitelist data index(18th here)
                                   "0x00, 0x00, 0x00, 0x00, 0x00, 0x00 "  # whitelist data
                                   "0x00, 0x00, 0x00, 0x00, 0x00 0x00 0x00 0x41 0x55 0x54 0x4F 0x4D 0x41 0x54 0x49 0x4F 0x4E 0x00 0x00 0x00",
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

        blescan_obj = BleScan(wifi_dut, ble_dut_address=bt_client_address, ble_scan_interval=256, ble_scan_window=80,
                              index_compare=index)
        blescan_obj.start()
        blescan_obj.wait_for_exit()
        blescan_obj.whitelist_check()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_whitelist_adv_data_index15_2Advertisers_C19952(wifi_dut, ble_client, ble_clients, sl_collections):
    assert len(ble_clients) >= 2
    ble_client1 = ble_clients[1]
    ble_client2 = ble_clients[0]
    scan_result = ""
    try:
        index = 15
        logger().info(f"\n\n**************Start DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=index, compare_data_length=10,
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
        assert bt_client_address1 is not None
        time.sleep(5)
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
        assert bt_client_address2 is not None
        time.sleep(10)
        blescan_obj = BleScan(wifi_dut, ble_scan_interval=256, ble_scan_window=80, index_compare=index)
        blescan_obj.start()
        blescan_obj.wait_for_exit()
        blescan_obj.whitelist_check()
        events = wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                    logger().info(f" event data : {event.event_data}")
                    scan_result = event.event_data
        logger().info("verifying client addr1, is available in scan list...")
        assert str(bt_client_address1) in str(scan_result), "failed to find client bt addr in scan list...."
        logger().info(f"found BT client address : {bt_client_address1}")
        logger().info("verifying client addr2, is available in scan list...")
        assert str(bt_client_address2) in str(scan_result), "failed to find client bt addr in scan list...."
        logger().info(f"found BT client address : {bt_client_address2}")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_aggressive_interval_whitelist_adv_data_index5_C19956(wifi_dut, ble_client, ble_clients,
                                                                           sl_collections):
    try:
        index = 5
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
        assert bt_client_address is not None
        time.sleep(10)
        blescan_obj = BleScan(wifi_dut, ble_scan_interval=160, ble_scan_window=80, index_compare=index)
        blescan_obj.start()
        blescan_obj.wait_for_exit()
        blescan_obj.whitelist_check()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_aggressive_interval_whitelist_adv_data_2advertisers_index5_C19957(wifi_dut, ble_client, ble_clients,
                                                                                    sl_collections):
    assert len(ble_clients) >= 2
    ble_client1 = ble_clients[1]
    ble_client2 = ble_clients[0]
    scan_result = ""
    try:
        index = 5
        logger().info(f"\n\n**************Start DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=index, compare_data_length=10,
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
        assert bt_client_address1 is not None
        time.sleep(5)
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
        assert bt_client_address2 is not None
        time.sleep(10)
        logger().info(f"bt_client_address1: {bt_client_address1}")
        logger().info(f"bt_client_address2: {bt_client_address2}")

        blescan_obj = BleScan(wifi_dut, ble_clients, ble_scan_interval=960, ble_scan_window=640, index_compare=index)
        blescan_obj.start()
        blescan_obj.wait_for_exit()
        events = wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                    logger().info(f" event data : {event.event_data}")
                    scan_result = event.event_data
        logger().info("verifying client addr1, is available in scan list...")
        assert str(bt_client_address1) in str(scan_result), "failed to find client bt addr in scan list...."
        logger().info(f"found BT client address : {bt_client_address1}")
        logger().info("verifying client addr2, is available in scan list...")
        assert str(bt_client_address2) in str(scan_result), "failed to find client bt addr in scan list...."
        logger().info(f"found BT client address : {bt_client_address2}")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.skip("testagent issue")
def test_wifi_dut_master_white_list_remote_device_c19846(wifi_dut, ble_client, rs_helper_ble, sl_collections):
    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_wifi_dut_master_remote_device_directed_connectable.logs_{int(time.time())}"):
        try:
            ble_client.interfaces.bluetooth.close()
            logger().info(f"Start ble DUT and client")
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert ble_dut_address, f"Unable to get ble_dut_address"
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
            assert ble_client_address, f"Unable to get ble_client_address"
            time.sleep(5)
            try:
                logger().info(f"****** ADDING WHITELIST BEFORE SCANNING")
                wifi_dut.interfaces.wifi.ble_add_white_list(ble_client_address)
                logger().info(f"Start scanning and connect to ble client")
                wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address,
                                                            ble_scan_filter_type=1,
                                                            timeout=120)
                logger().info("stop scanning")
                wifi_dut.interfaces.bluetooth.ble_stop_scanning()
                time.sleep(5)
                enable_wifi_ps = wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                assert enable_wifi_ps == 0, 'failed to enable wlan power save'
                enable_bt_ps = wifi_dut.interfaces.wifi.enable_bt_power_save(
                    psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                    psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
                assert enable_bt_ps == 0, 'failed to enable bt power save'
                logger().info(f"DUT initiating BLE connection with ble_client device")
                rs_helper_ble.ble_connect_DUT_as_master(wifi_dut=wifi_dut, ble_remote=ble_client,
                                                        ble_dut_address=ble_dut_address,
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



@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_sdk_ble_advertising_with_whitelist_filter_policy_0x01_C19841(wifi_dut, ble_clients, sl_collections):
    try:
        assert len(ble_clients) >= 2, f"MINIMUM 2 RASPI DEVICES NEEDED"
        ble_client1 = ble_clients[0]
        ble_client2 = ble_clients[1]
        logger().info("INITIATING BLE SERVICE IN DUT")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start(set_smp=0)
        assert bt_dut_address, "FAILED TO INITIATE BLE IN DUT"

        logger().info(" **** SETTING LOCAL NAME **** ")
        device_name = "AUTOMATION432"
        wifi_dut.interfaces.wifi.bt_set_local_name(device_name)
        returned_name = wifi_dut.interfaces.wifi.bt_get_local_name()
        assert device_name == returned_name, "THE SET DEVICE NAME DIDN'T MATCH RETURNED DEVICE NAME"
        ble_white_list_address = ble_client1.interfaces.bluetooth.get_ble_address()
        wifi_dut.interfaces.wifi.ble_set_scan_response_data()
        # add the remote device 1 to whitelist and start advertising from DUT
        logger().info(" **** ADDING REMOTE DEVICE 1 TO WHITELIST **** ")
        wifi_dut.interfaces.wifi.ble_add_white_list(ble_white_list_address)
        ble_obj = BleScan(wifi_dut=wifi_dut, ble_clients=ble_client1, ble_dut_address=bt_dut_address)
        ble_obj.ble_adv(filter_type=1)
        state_int = ble_obj.check_device_state()
        if (state_int > 0):
            logger().info("DISCONNECTING THE BT HOST....")
            wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_white_list_address)
            assert "UNABLE TO DISCONNECT SINCE THE CONNECTION NEVER EXISTED"
        ble_client1.interfaces.bluetooth.close()
        time.sleep(10)
        # start advertisement from dut again
        logger().info("STARTING BLE ADVERTISEMENT IN DUT AGAIN.....")
        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_filter_type=1)
        time.sleep(10)
        logger().info("....SCANNING FOR NON WHITE LISTED DEVICES....")
        ble_non_white_list_address = ble_client2.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert ble_non_white_list_address, "FAILED TO INITIATE BLE IN DUT"
        time.sleep(5)
        ble_client2.interfaces.bluetooth.stop_scanning()
        found_devices = ble_client2.interfaces.bluetooth.get_devices()
        logger().info(f"SCAN RESULTS FROM REMOTE DEVICE 2:*********{found_devices}*****************")
        assert wifi_dut.interfaces.wifi.ble_address in found_devices, "DUT ISN'T LISTED IN SCAN RESULTS"
        logger().info("FOUND DUT BD ADDRESS IN SCAN RESULTS")
        logger().info("....CONNECT TO DUT WITH MAC ADDRESS....")
        ble_client2.interfaces.bluetooth.connect(bt_dut_address)
        time.sleep(60)
        status = ble_client2.interfaces.bluetooth.get_connection_status(bt_dut_address)
        logger().info(f"Connection status in remote device '{ble_client2}' is:{status}")
        assert status, f"Remote device '{ble_client2}' is not connected to DUT"
        if (status > 0):
            logger().info("DISCONNECTING THE BT HOST....")
            wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_non_white_list_address)
            assert "UNABLE TO DISCONNECT SINCE THE CONNECTION NEVER EXISTED"
        ble_client2.interfaces.bluetooth.close()
        time.sleep(10)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_sdk_ble_slave_connection_with_whitelist_filter_policy_0x00_C19843(wifi_dut, ble_clients, sl_collections):
    try:
        assert len(ble_clients) >= 2, f"MINIMUM 2 RASPI DEVICES NEEDED"
        ble_client1 = ble_clients[0]
        ble_client2 = ble_clients[1]
        logger().info("INITIATING BLE SERVICE IN DUT")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address, "FAILED TO INITIATE BLE IN DUT"

        logger().info(" **** SETTING LOCAL NAME **** ")
        device_name = "AUTOMATION432"
        wifi_dut.interfaces.wifi.bt_set_local_name(device_name)
        returned_name = wifi_dut.interfaces.wifi.bt_get_local_name()
        assert device_name == returned_name, "THE SET DEVICE NAME DIDN'T MATCH RETURNED DEVICE NAME"
        ble_white_list_address = ble_client1.interfaces.bluetooth.get_ble_address()
        wifi_dut.interfaces.wifi.ble_set_scan_response_data()
        # add the remote device 1 to whitelist and start advertising from DUT
        logger().info(" **** ADDING REMOTE DEVICE 1 TO WHITELIST **** ")
        wifi_dut.interfaces.wifi.ble_add_white_list(ble_white_list_address)
        ble_obj = BleScan(wifi_dut=wifi_dut, ble_clients=ble_client1, ble_dut_address=bt_dut_address)
        ble_obj.ble_adv(filter_type=0)
        state_int = ble_obj.check_device_state()
        if (state_int > 0):
            logger().info("DISCONNECTING THE BT HOST....")
            wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_white_list_address)
            assert "UNABLE TO DISCONNECT SINCE THE CONNECTION NEVER EXISTED"
        ble_client1.interfaces.bluetooth.close()
        time.sleep(10)
        # start advertisement from dut again
        logger().info("STARTING BLE ADVERTISEMENT IN DUT AGAIN.....")
        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_filter_type=0)
        time.sleep(10)
        logger().info("....SCANNING FOR NON WHITE LISTED DEVICES....")
        ble_non_white_list_address = ble_client2.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert ble_non_white_list_address, "FAILED TO INITIATE BLE IN DUT"
        time.sleep(5)
        ble_client2.interfaces.bluetooth.stop_scanning()
        found_devices = ble_client2.interfaces.bluetooth.get_devices()
        logger().info(f"SCAN RESULTS FROM REMOTE DEVICE 2:*********{found_devices}*****************")
        assert wifi_dut.interfaces.wifi.ble_address in found_devices, "DUT ISN'T LISTED IN SCAN RESULTS"
        logger().info("FOUND DUT BD ADDRESS IN SCAN RESULTS")
        logger().info("....CONNECT TO DUT WITH MAC ADDRESS....")
        ble_client2.interfaces.bluetooth.connect(bt_dut_address)
        time.sleep(60)
        status = ble_client2.interfaces.bluetooth.get_connection_status(bt_dut_address)
        logger().info(f"Connection status in remote device '{ble_client2}' is:{status}")
        assert status, f"Remote device '{ble_client2}' is not connected to DUT"
        if (status > 0):
            logger().info("DISCONNECTING THE BT HOST....")
            wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_non_white_list_address)
            assert "UNABLE TO DISCONNECT SINCE THE CONNECTION NEVER EXISTED"
        ble_client2.interfaces.bluetooth.close()
        time.sleep(10)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        logger().info(" **** ADDING clearing WHITELIST on dut **** ")
        wifi_dut.interfaces.wifi.ble_clear_white_list()

@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_sdk_ble_slave_connection_with_whitelist_filter_policy_0x02_C19842(wifi_dut, ble_clients, sl_collections):
    try:
        assert len(ble_clients) >= 2, f"MINIMUM 2 RASPI DEVICES NEEDED"
        ble_client1 = ble_clients[0]
        ble_client2 = ble_clients[1]
        logger().info("INITIATING BLE SERVICE IN DUT")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address, "FAILED TO INITIATE BLE IN DUT"

        logger().info(" **** SETTING LOCAL NAME **** ")
        device_name = "AUTOMATION432"
        wifi_dut.interfaces.wifi.bt_set_local_name(device_name)
        returned_name = wifi_dut.interfaces.wifi.bt_get_local_name()
        assert device_name == returned_name, "THE SET DEVICE NAME DIDN'T MATCH RETURNED DEVICE NAME"
        ble_white_list_address = ble_client1.interfaces.bluetooth.get_ble_address()
        wifi_dut.interfaces.wifi.ble_set_scan_response_data()
        # add the remote device 1 to whitelist and start advertising from DUT
        logger().info(" **** ADDING REMOTE DEVICE 1 TO WHITELIST **** ")
        wifi_dut.interfaces.wifi.ble_add_white_list(ble_white_list_address)
        ble_obj = BleScan(wifi_dut=wifi_dut, ble_clients=ble_client1, ble_dut_address=bt_dut_address)
        ble_obj.ble_adv(filter_type=2)
        state_int = ble_obj.check_device_state()
        if (state_int > 0):
            logger().info("DISCONNECTING THE BT HOST....")
            wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_white_list_address)
            assert "UNABLE TO DISCONNECT SINCE THE CONNECTION NEVER EXISTED"
        ble_client1.interfaces.bluetooth.close()
        time.sleep(10)
        # start advertisement from dut again
        logger().info("STARTING BLE ADVERTISEMENT IN DUT AGAIN.....")
        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_filter_type=2)
        time.sleep(10)
        logger().info("....SCANNING FOR NON WHITE LISTED DEVICES....")
        ble_non_white_list_address = ble_client2.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert ble_non_white_list_address, "FAILED TO INITIATE BLE IN DUT"
        time.sleep(5)
        ble_client2.interfaces.bluetooth.stop_scanning()
        found_devices = ble_client2.interfaces.bluetooth.get_devices()
        logger().info(f"SCAN RESULTS FROM REMOTE DEVICE 2:*********{found_devices}*****************")
        assert wifi_dut.interfaces.wifi.ble_address in found_devices, "DUT ISN'T LISTED IN SCAN RESULTS"
        logger().info("FOUND DUT BD ADDRESS IN SCAN RESULTS")
        for count in range(0, 4):
            try:
                logger().info("....CONNECT TO DUT WITH MAC ADDRESS....")
                ble_client2.interfaces.bluetooth.connect(bt_dut_address)
            except Exception:
                logger().info(f"\n\n **** ble connection Failed....retrying for the {count + 1} iteration ****\n\n")
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        ble_client2.interfaces.bluetooth.close()
        time.sleep(10)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
def test_ble_dut_slave_2_white_list_rd_1_non_white_list_rd_c19844(ble_dut, ble_clients, sl_collections):
    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_ble_dut_master_remote_device_directed_connectable.logs_{int(time.time())}"):
        remote_le_devices = 3
        assert len(ble_clients) >= remote_le_devices, "This test case requires 3 Raspberry pi devices"

        logger().info(f"Start ble DUT and client")
        ble_dut_address = ble_dut.interfaces.wifi.ble_start()
        time.sleep(1)

        ble_client1_address = ble_clients[0].interfaces.bluetooth.get_ble_address()
        ble_client2_address = ble_clients[1].interfaces.bluetooth.get_ble_address()
        logger().info(f"ble_client1_address: {ble_client1_address} \nble_client2_address:{ble_client2_address}")

        logger().info(f"Setting local name for 9117")
        ble_dut.interfaces.bluetooth.bt_set_local_name("RSI_SCAN_DATA_RS")

        time.sleep(2)
        logger().info(f"Adding {ble_clients[0].name} to WHITELIST")
        ble_dut.interfaces.wifi.ble_add_white_list(ble_client1_address)
        time.sleep(1)
        logger().info(f"****** Adding {ble_clients[1].name} to WHITELIST")
        ble_dut.interfaces.wifi.ble_add_white_list(ble_client2_address)

        for ble_client in ble_clients:
            logger().info(f"ble_client device: {(ble_clients.index(ble_client) + 1)}")
            logger().info("Set DUT in advertise mode")
            ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_filter_type=2)
            time.sleep(2)

            logger().info("Start smp scan from the remote device")
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
            assert ble_client_address, "failed to initiate scan in remote device"

            time.sleep(5)
            logger().info("stop scanning....")
            ble_client.interfaces.bluetooth.stop_scanning()

            logger().info("Check the dut is listed...")
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            assert ble_dut.interfaces.bluetooth.ble_address in found_devices

            if ble_clients.index(ble_client) == 0:
                logger().info("Enabling Wlan and BLE power save")
                enable_wifi_ps = ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                assert enable_wifi_ps == 0, 'failed to enable wlan power save'
                enable_bt_ps = ble_dut.interfaces.wifi.enable_bt_power_save(
                    psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                    psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
                assert enable_bt_ps == 0, 'failed to enable wlan power save'

            logger().info(f"f**********{ble_clients.index(ble_client)}")

            if ble_clients.index(ble_client) < 2:

                logger().info("Connect to the dut with mac address..")
                connect_state = ble_client.interfaces.bluetooth.connect(ble_dut_address)

                if remote_le_devices != (ble_clients.index(ble_client) + 1):
                    assert connect_state, "unable to connect to the given address"
                    time.sleep(30)
                else:
                    assert not connect_state, f"{ble_client.name} is connected to DUT"
                    logger().info(f"Failed to connect with remote device {ble_client.name} "
                                  f"as it is not added in DUT whitelist")

                    logger().info("Stop DUT advertising")
                    ble_dut.interfaces.bluetooth.ble_stop_advertising()
                    break
                time.sleep(60)
                logger().info("checking if the connection exists to disconnect")
                state = ble_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "The device is in disconnected state"

                logger().info("Disconnect DUT from BLE remote device")
                ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
                ble_client.interfaces.bluetooth.close()

            else:
                for count in range(0, 2):
                    try:
                        logger().info("....CONNECT TO DUT WITH MAC ADDRESS....")
                        ble_client.interfaces.bluetooth.connect(ble_dut_address)
                    except Exception:
                        logger().info(
                            f"\n\n **** ble connection Failed....retrying for the {count + 1} iteration ****\n\n")
