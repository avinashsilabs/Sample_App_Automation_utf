import time
import pytest
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, \
    RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap
from utf_wiseconnect.devices.rs911x import RS9116PowerSaveModes, RS9116PowerSaveProcedureTypes, RS9116AsyncEventType


def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Initiates ble in DUT 
        3. Connect to the remote device
        4. configure the dut with the scan interval and scan window params
        5. Validate the whitelist data in adv report 

    Author: Jyothi Nagireddy
"""


pytestmark = [
   pytest.mark.config(
    "wifi_dut",
     wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
        RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
         },
                     )
]

class BleScan(ThreadBase):
    def __init__(self, wifi_dut, bt_client_address=None, ble_scan_interval=None, ble_scan_window=None
                 ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client_address = bt_client_address
        self.ble_scan_interval = ble_scan_interval
        self.ble_scan_window = ble_scan_window

    def run(self):
        logger().info(f" \n\n******************* START SCANNING FROM DUT ***********************\n\n ")
        dut_scan_results = self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.bt_client_address,
                                                                       ble_scan_interval=self.ble_scan_interval,
                                                                       ble_scan_window=self.ble_scan_window, timeout=60)
        logger().info(f"dut_scan_results: {dut_scan_results}")
        time.sleep(60)
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()

        enable_wifips = self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                 RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifips, f" unable to enable the wifips"
        enable_btps = self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                  RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_btps, f"unable to enable the btps"

        events = self.wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == RS9116AsyncEventType.Adv_Report:
                whitelist_data = self.wifi_dut.interfaces.wifi.parse_and_get_whitelist_data(event.event_data)
                assert whitelist_data == "AUTOMATION", "whitelist data not found"
                logger().info(f"\n\n***********character conversion of advertising data*****************\n\n")
                logger().info(f"\n\n***********found advertising data: {whitelist_data}****************\n\n")
                break


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_whitelist_with_adv_data_index5_C19949(wifi_dut, ble_client):
    try:
        logger().info(f"\n\n**************Start ble on DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None

        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=5, compare_data_length=10,
                                                            data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I', 'O', 'N'])

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

        blescan_obj = BleScan(wifi_dut, ble_scan_interval=256, ble_scan_window=80)
        blescan_obj.start()
        blescan_obj.wait_for_exit()
    finally:
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_whitelist_with_adv_data_index10_C19951(wifi_dut, ble_client):
    try:
        logger().info(f"\n\n**************Start ble on DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=10, compare_data_length=10,
                                                            data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I', 'O', 'N'])

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
    finally:
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_whitelist_with_adv_data_index20_C19953(wifi_dut, ble_client):
    try:
        logger().info(f"\n\n**************Start ble on DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=20, compare_data_length=10,
                                                            data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I', 'O', 'N'])

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
    finally:
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_whitelist_with_adv_data_index25_C19954(wifi_dut, ble_client):
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

        logger().info(f" \n\n******************* START SCANNING FROM DUT ***********************\n\n ")
        dut_scan_results = wifi_dut.interfaces.wifi.ble_start_scanning(ble_scan_interval=256, ble_scan_window=80,
                                                                       timeout=60)
        logger().info("Scan for 60 sec")
        time.sleep(60)
        logger().info(f"dut_scan_results: {dut_scan_results}")
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        enable_wifips = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifips, f" unable to enable the wifips"
        enable_btps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_btps, f"unable to enable the btps"
        events = wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == RS9116AsyncEventType.Adv_Report:
                whitelist_data = wifi_dut.interfaces.wifi.parse_and_get_whitelist_data(event.event_data)
                assert whitelist_data == "GANGA", "whitelist data not found"
                logger().info(f"\n\n***********character conversion of advertising data*****************\n\n")
                logger().info(f"found advertising data: {whitelist_data}")
                break
    finally:
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_diable_ble_whitelist_with_adv_data_C19950(wifi_dut, ble_client):
    try:
        logger().info(f"\n\n**************Start DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None

        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=0, data_compare_index=5, compare_data_length=10,
                                                            data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I', 'O', 'N'])

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
    finally:
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_whitelist_adv_data_index15_2Advertisers_C19952(wifi_dut, ble_client, ble_clients):
    assert len(ble_clients) >= 2
    ble_client1 = ble_clients[1]
    ble_client2 = ble_clients[0]
    try:
        logger().info(f"\n\n**************Start DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=15, compare_data_length=10,
                                                            data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I', 'O', 'N'])
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
            bt_dut_address= bt_dut_address,
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

    finally:
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        time.sleep(5)

@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_aggressive_interval_whitelist_adv_data_index5_C19956(wifi_dut, ble_client, ble_clients):
    try:
        logger().info(f"\n\n**************Start DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=5, compare_data_length=10,
                                                            data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I', 'O', 'N'])

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
    finally:
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_aggressive_interval_whitelist_adv_data_2advertisers_index5_C19957(wifi_dut, ble_client, ble_clients):
    assert len(ble_clients) >= 2
    ble_client1 = ble_clients[1]
    ble_client2 = ble_clients[0]
    try:
        logger().info(f"\n\n**************Start DUT**************\n\n")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=5, compare_data_length=10,
                                                            data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I', 'O', 'N'])
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

        blescan_obj = BleScan(wifi_dut, ble_scan_interval=960, ble_scan_window=640)
        blescan_obj.start()
        blescan_obj.wait_for_exit()

    finally:
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        time.sleep(5)

@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_enable_and_disable_whitelist_for_100_iterations_c19955(wifi_dut, ble_clients):
        assert len(ble_clients) >= 2, f"minimum 2 Raspi devices needed"
        ble_client1 = ble_clients[1]
        ble_client2 = ble_clients[0]
        try:
            for i in range(0, 100):
                logger().info(f"\n\n**************Start DUT**************\n\n")
                bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
                assert bt_dut_address is not None
                wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=5,
                                                                    compare_data_length=10,
                                                                    data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I',
                                                                               'O',
                                                                               'N'])
                ble_client1.interfaces.bluetooth.close()
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
                time.sleep(5)
                ble_client2.interfaces.bluetooth.close()
                bt_client_address2 = ble_client2.interfaces.bluetooth.start_smp_adv_whitelist_with_hci_tool(
                    bt_dut_address=bt_dut_address,
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
                time.sleep(5)
                wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=5,
                                                                    compare_data_length=10,
                                                                    data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I',
                                                                               'O',
                                                                               'N'])
                logger().info(f" \n\n******************* START SCANNING FROM DUT ***********************\n\n ")
                dut_scan_results1 = wifi_dut.interfaces.wifi.ble_start_scanning(timeout=30)
                logger().info(f"dut_scan_results: {dut_scan_results1}")
                time.sleep(60)

                enable_btps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                     RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_btps, f"unable to enable the btps"

                enable_wifips = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                    RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_wifips, f" unable to enable the wifips"

                time.sleep(2)
                wifi_dut.interfaces.wifi.bt_power_save(0, 0)
                wifi_dut.interfaces.wifi.power_save(0, 0)
                wifi_dut.interfaces.wifi.ble_stop_scanning()
                logger().info(f"******************************************")
                wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=0, data_compare_index=5,
                                                                    compare_data_length=10,
                                                                    data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I',
                                                                               'O',
                                                                               'N'])
                logger().info(f" \n\n******************* START SCANNING FROM DUT ***********************\n\n ")
                dut_scan_results2 = wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address2, timeout=30)
                logger().info(f"dut_scan_results: {dut_scan_results2}")
                time.sleep(60)
                wifi_dut.interfaces.wifi.ble_stop_scanning(timeout=10)

                events = wifi_dut.interfaces.wifi.get_async_events()
                for event in events:
                    if event.event_type == RS9116AsyncEventType.Adv_Report:
                        whitelist_data = wifi_dut.interfaces.wifi.parse_and_get_whitelist_data(event.event_data)
                        assert whitelist_data == "AUTOMATION", "whitelist data not found"
                        logger().info(f"\n\n***********character conversion of advertising data*****************\n\n")
                        logger().info(f"\n\n***********found advertising data: {whitelist_data}****************\n\n")
                        break
                logger().info("verifying client ble addr1, is available in scan list...")
                if str(bt_client_address1) in str(
                        dut_scan_results1):
                    logger().info(f"found bt addr1 in scan list")
                else:
                    logger().info(f" \n\n******************* START SCANNING FROM DUT ***********************\n\n ")
                    dut_scan_results1 = wifi_dut.interfaces.wifi.ble_start_scanning(timeout=30)
                    time.sleep(120)
                    assert str(bt_client_address1) in str(
                        dut_scan_results1), "failed to find client bt addr1 in scan list...."
                    wifi_dut.interfaces.wifi.ble_stop_scanning(timeout=10)

                if str(bt_client_address2) in str(
                    dut_scan_results2):
                    logger().info(f"found bt addr2 in scan list")
                else:
                    logger().info(f" \n\n******************* START SCANNING FROM DUT ***********************\n\n ")
                    dut_scan_results2 = wifi_dut.interfaces.wifi.ble_start_scanning(timeout=30)
                    time.sleep(120)
                    assert str(bt_client_address2) in str(
                         dut_scan_results2), "failed to find client bt addr2 in scan list...."
                    wifi_dut.interfaces.wifi.ble_stop_scanning(timeout=10)

                logger().info(f"\n\n************iteration: {i + 1}*****************\n\n")

        except Exception as e:
            logger().info(f"\n******Testcase failed with : {e}******")
            raise e

        finally:
            ble_client1.interfaces.bluetooth.close()
            ble_client2.interfaces.bluetooth.close()
            time.sleep(5)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', "ble_stop_adv"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
def test_verify_ble_advertising_with_whitelist_filter_policy_0x01_C19841(ble_dut, ble_clients):
    assert len(ble_clients) >= 2, f"MINIMUM 2 RASPI DEVICES NEEDED"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]
    logger().info("INITIATING BLE SERVICE IN DUT")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "FAILED TO INITIATE BLE IN DUT"

    # set local name to device and fetch the remote device addresses
    logger().info(" **** SETTING LOCAL NAME **** ")
    device_name = "REDPINE432"
    ble_dut.interfaces.bluetooth.bt_set_local_name(device_name)
    returned_name = ble_dut.interfaces.bluetooth.bt_get_local_name()
    assert device_name == returned_name, "THE SET DEVICE NAME DIDN'T MATCH RETURNED DEVICE NAME"
    ble_white_list_address = ble_client1.interfaces.bluetooth.get_ble_address()
    ble_dut.interfaces.bluetooth.ble_set_scan_response_data()

    # add the remote device 1 to whitelist and start advertising from DUT
    logger().info(" **** ADDING REMOTE DEVICE 1 TO WHITELIST **** ")
    ble_dut.interfaces.bluetooth.ble_add_white_list(ble_white_list_address)
    logger().info(" **** START ADVERTISEMENT FROM DUT **** ")
    ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_filter_type=1)

    # enable wlan and bt power save in dut
    logger().info(f" **** ENABLING WLAN AND BT POWER SAVE **** ")
    enable_wifi_ps = ble_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, 'FAILED TO ENABLE WLAN POWER SAVE'
    enable_bt_ps = ble_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, 'FAILED TO ENABLE BT POWER SAVE'

    # scan and connect from whitelisted remote device
    ble_white_list_address = ble_client1.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert ble_white_list_address, "FAILED TO INITIATE BLE IN REMOTE DEVICE 1"
    time.sleep(5)
    ble_client1.interfaces.bluetooth.stop_scanning()
    found_devices = ble_client1.interfaces.bluetooth.get_devices()
    logger().info(f" FOUND_DEVICES :*********{found_devices}*****************")
    flag = ble_dut.interfaces.bluetooth.ble_address in found_devices
    assert flag, "DUT ISN'T LISTED IN SCAN RESULTS"
    if flag:
        logger().info("REMOTE DEVICE 1 IS VISIBLE IN SCAN RESULTS")
    logger().info("....CONNECT TO DUT AND MAC ADDRESS....")
    connect_state = ble_client1.interfaces.bluetooth.pair_and_connect(bt_dut_address, timeout=120)
    logger().info(f"THE STATE IS: {connect_state}")
    assert connect_state, "UNABLE TO CONNECT TO THE GIVEN ADDRESS"
    time.sleep(10)

    ble_dut.interfaces.bluetooth.ble_advertising = False

    # checking if the connection exists to disconnect
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("DISCONNECTING THE BT HOST....")
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=ble_white_list_address)
        assert "UNABLE TO DISCONNECT SINCE THE CONNECTION NEVER EXISTED"
    ble_client1.interfaces.bluetooth.close()
    time.sleep(10)

    # start advertisement from dut again
    logger().info("STARTING BLE ADVERTISEMENT IN DUT AGAIN.....")
    ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_filter_type=1)
    time.sleep(10)
    logger().info("....SCANNING FOR NON WHITE LISTED DEVICES....")
    ble_non_white_list_address = ble_client2.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert ble_non_white_list_address, "FAILED TO INITIATE BLE IN DUT"
    time.sleep(5)
    ble_client2.interfaces.bluetooth.stop_scanning()

    found_devices = ble_client2.interfaces.bluetooth.get_devices()
    logger().info(f"SCAN RESULTS FROM REMOTE DEVICE 2:*********{found_devices}*****************")
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices, "DUT ISN'T LISTED IN SCAN RESULTS"
    logger().info("FOUND DUT BD ADDRESS IN SCAN RESULTS")

    logger().info("....CONNECT TO DUT WITH MAC ADDRESS....")
    connect_state = ble_client2.interfaces.bluetooth.pair_and_connect(bt_dut_address, timeout=120)
    if not connect_state:
        logger().info("THE CONNECTION CAN'T BE ESTABLISHED")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', "ble_stop_adv"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
def test_verify_ble_slave_connection_with_whitelist_filter_policy_0x02_C19842(ble_dut, ble_clients):
 with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_ble_dut_master_remote_device_directed_connectable.logs_{int(time.time())}"):
    assert len(ble_clients) >= 2, f"MINIMUM 2 RASPI DEVICES NEEDED"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]
    logger().info("INITIATING BLE SERVICE IN DUT")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "FAILED TO INITIATE BLE IN DUT"

    #set local name to device and fetch the remote device addresses
    logger().info(" **** SETTING LOCAL NAME TO DUT **** ")
    device_name = "REDPINE432"
    ble_dut.interfaces.bluetooth.bt_set_local_name(device_name)
    returned_name = ble_dut.interfaces.bluetooth.bt_get_local_name()
    assert device_name == returned_name, "THE SET DEVICE NAME DIDN'T MATCH THE RETURNED NAME"
    ble_dut.interfaces.bluetooth.ble_set_scan_response_data()
    ble_white_list_address = ble_client1.interfaces.bluetooth.get_ble_address()
    logger().info(f"ble_white_list_address: {ble_white_list_address}")

    #add remote device 1 to whitelist and start advertising from DUT
    logger().info(" **** ADDING REMOTE DEVICE 1 TO WHITELIST **** ")
    status = ble_dut.interfaces.bluetooth.ble_add_white_list(ble_white_list_address)
    assert status, "REMOTE DEVICE CAN'T BE ADDED TO WHITELIST"
    logger().info(" **** START ADVERTISEMENT FROM DUT **** ")
    ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_filter_type=2)

    #enable wlan and bt power save in dut
    logger().info(" **** ENABLING WLAN AND BT POWER SAVE **** ")
    enable_wifi_ps = ble_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, 'FAILED TO ENABLE WLAN POWER SAVE'
    enable_bt_ps = ble_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, 'FAILED TO ENABLE BT POWER SAVE'

    #scan and connect from whitelisted remote device
    ble_white_list_address = ble_client1.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert ble_white_list_address, "FAILED TO INITIATE BLE IN REMOTE DEVICE 1"
    time.sleep(5)
    ble_client1.interfaces.bluetooth.stop_scanning()
    found_devices = ble_client1.interfaces.bluetooth.get_devices()
    logger().info(f" FOUND_DEVICES :*********{found_devices}*****************")
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices, "DUT ISN'T LISTED IN SCAN RESULTS"
    logger().info("....CONNECT TO DUT AND MAC ADDRESS....")
    connect_state = ble_client1.interfaces.bluetooth.pair_and_connect(bt_dut_address)
    assert connect_state, "UNABLE TO CONNECT TO GIVEN DUT ADDRESS"
    time.sleep(20)

    # checking if the connection exists to disconnect
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("DISCONNECTING THE DUT FROM REMOTE DEVICE....")
        ble_client1.interfaces.bluetooth.disconnect(bt_dut_address)
        assert "UNABLE TO DISCONNECT SINCE THE CONNECTION NEVER EXISTED"
    ble_client1.interfaces.bluetooth.close()
    time.sleep(10)


    #start advertisement from dut again
    logger().info("....STARTING BLE ADVERTISEMENT IN DUT AGAIN.....")
    ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_filter_type=2)
    time.sleep(10)
    logger().info(" SCANNING AND CONNECTING TO REMOTE DEVICE 2 ")
    ble_non_white_list_address = ble_client2.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert ble_non_white_list_address, "FAILED TO INITIATE BLE IN DUT"
    logger().info(f"ble_non_white_list_address: {ble_non_white_list_address}")

    time.sleep(5)
    ble_client2.interfaces.bluetooth.stop_scanning()

    found_devices = ble_client2.interfaces.bluetooth.get_devices()
    logger().info(f"SCAN RESULTS FROM REMOTE DEVICE 2:*********{found_devices}*****************")
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices, "DUT ISN'T LISTED IN SCAN RESULTS"

    logger().info("....CONNECT TO DUT WITH MAC ADDRESS....")
    connect_state = ble_client2.interfaces.bluetooth.pair_and_connect(bt_dut_address)
    if not connect_state:
        logger().info("THE CONNECTION CAN'T BE ESTABLISHED WITH NON WHITELISTED DEVICE")
    ble_dut.interfaces.bluetooth.ble_stop_advertising()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', "ble_stop_adv"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
def test_verify_ble_slave_connection_with_whitelist_filter_policy_0x00_C19843(ble_dut, ble_clients):
    #start ble service in dut
    assert len(ble_clients) >= 2, f"MINIMUM 2 RASPI DEVICES NEEDED"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]
    logger().info("INITIATING BLE SERVICE IN DUT")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "FAILED TO INITIATE BLE IN DUT"

    #set local name to device and fetch the remote device addresses
    logger().info(" **** SETTING LOCAL NAME TO DUT **** ")
    device_name = "REDPINE432"
    ble_dut.interfaces.bluetooth.bt_set_local_name(device_name)
    returned_name = ble_dut.interfaces.bluetooth.bt_get_local_name()
    assert device_name == returned_name, "THE SET DEVICE NAME DIDN'T MATCH THE RETURNED NAME"
    ble_dut.interfaces.bluetooth.ble_set_scan_response_data()
    ble_white_list_address = ble_client1.interfaces.bluetooth.get_ble_address()
    logger().info(f"ble_white_list_address: {ble_white_list_address}")

    #add remote device 1 to whitelist and start advertising from DUT
    logger().info(" **** ADDING REMOTE DEVICE 1 TO WHITELIST **** ")
    status = ble_dut.interfaces.bluetooth.ble_add_white_list(ble_white_list_address)
    assert status, "UNABLE TO ADD REMOTE DEVICE 1 TO WHITELIST"
    logger().info(" **** START ADVERTISEMENT FROM DUT **** ")
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    #enable wlan and bt power save in dut
    logger().info(" **** ENABLING WLAN AND BT POWER SAVE **** ")
    enable_wifi_ps = ble_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, 'FAILED TO ENABLE WLAN POWER SAVE'
    enable_bt_ps = ble_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, 'FAILED TO ENABLE BT POWER SAVE'

    #scan and connect from whitelisted remote device
    ble_white_list_address = ble_client1.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert ble_white_list_address, "FAILED TO INITIATE BLE IN REMOTE DEVICE 1"
    time.sleep(5)
    ble_client1.interfaces.bluetooth.stop_scanning()
    found_devices = ble_client1.interfaces.bluetooth.get_devices()
    logger().info(f" FOUND_DEVICES :*********{found_devices}***************** ")
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices, "DUT ISN'T LISTED IN SCAN RESULTS"
    logger().info("....CONNECT TO DUT AND MAC ADDRESS....")
    connect_state = ble_client1.interfaces.bluetooth.pair_and_connect(bt_dut_address)
    assert connect_state, "CONNECTION TO DUT FAILED"
    if connect_state:
        logger().info("....CONNECTION WITH DUT IS SUCCESSFUL....")
    time.sleep(10)

    # checking if the connection exists to disconnect from remote device 1
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("DISCONNECTING THE DUT FROM REMOTE DEVICE....")
        ble_client1.interfaces.bluetooth.disconnect(bt_dut_address)
        assert "UNABLE TO DISCONNECT SINCE THE CONNECTION NEVER EXISTED"
    ble_client1.interfaces.bluetooth.close()
    time.sleep(10)

    #start advertisement from dut after disconnection from remote device 2
    logger().info("....STARTING BLE ADVERTISEMENT FROM DUT AGAIN.....")
    ble_dut.interfaces.bluetooth.ble_start_advertising()
    time.sleep(10)
    logger().info(" CONNECTION INITIATED WITH NON WHITELISTED ADDRESS ")
    ble_non_white_list_address = ble_client2.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert ble_non_white_list_address, "FAILED TO INITIATE BLE IN REMOTE DEVICE 2"
    logger().info(f"ble_non_white_list_address: {ble_non_white_list_address}")

    time.sleep(5)
    ble_client2.interfaces.bluetooth.stop_scanning()

    found_devices = ble_client2.interfaces.bluetooth.get_devices()
    logger().info(f"SCAN RESULTS FROM REMOTE DEVICE 2:*********{found_devices}*****************")
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices, "DUT ISN'T LISTED IN SCAN RESULTS"

    logger().info("....CONNECT TO DUT WITH MAC ADDRESS....")
    connect_state = ble_client2.interfaces.bluetooth.pair_and_connect(bt_dut_address)
    assert connect_state, "UNABLE TO CONNECT TO GIVEN ADDRESS"
    if connect_state:
        logger().info("....CONNECTION WITH REMOTE DEVICE 2 IS SUCCESSFUL....")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', "ble_stop_adv"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
def test_ble_dut_slave_2_white_list_rd_1_non_white_list_rd_c19844(ble_dut, ble_clients):
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

        if ble_dut.interfaces.wifi.board_type == "rs9117":
            logger().info(f"Setting local name for 9117")
            ble_dut.interfaces.bluetooth.bt_set_local_name("RSI_SCAN_DATA_RS")
        else:
            logger().info(f"Setting local name for 9116")
            ble_dut.interfaces.bluetooth.bt_set_local_name("RSI_SCAN_RESP_DATA")

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
                enable_wifi_ps = ble_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                    RS9116PowerSaveProcedureTypes.FastPowerSave)
                enable_bt_ps = ble_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                     RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_wifi_ps, 'failed to enable wlan power save'
                assert enable_bt_ps, 'failed to enable bt power save'

            logger().info("Connect to the dut with mac address..")
            connect_state = ble_client.interfaces.bluetooth.pair_and_connect(ble_dut_address)

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

            logger().info("checking if the connection exists to disconnect")
            state = ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "The device is in disconnected state"

            logger().info("Disconnect DUT from BLE remote device")
            ble_client.interfaces.bluetooth.disconnect(ble_dut_address)

            assert "unable to disconnect since the connection never existed"
            ble_client.interfaces.bluetooth.close()
            time.sleep(2)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_verify_dut_ble_scanning_with_whitelist_device_C19845(ble_clients, ble_dut):
 with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_ble_dut_master_remote_device_directed_connectable.logs_{int(time.time())}"):
    #start ble service in dut
    assert len(ble_clients) >= 2, f"MINIMUM 2 RASPI DEVICES NEEDED"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]
    logger().info("INITIATING BLE SERVICE IN DUT")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "FAILED TO INITIATE BLE IN DUT"

    #fetch the ble addresses of remote devices and add remote device 1 to whitelist
    logger().info("FETCHING THE BLE ADDRESS OF REMOTE DEVICE 1")
    ble_white_list_address = ble_client1.interfaces.bluetooth.get_ble_address()
    logger().info(f"ble_white_list_address: {ble_white_list_address}")

    try:
        logger().info(" **** ADDING REMOTE DEVICE 1 TO WHITELIST **** ")
        ble_dut.interfaces.bluetooth.ble_add_white_list(ble_white_list_address)
        #start advertisement from remote device 1 and 2
        logger().info(" **** START ADVERTISING FROM REMOTE DEVICE 1 **** ")
        ble_white_list_address = ble_client1.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert ble_white_list_address, "UNABLE TO GET BLE CLIENT 1 ADDRESS"
        time.sleep(3)
        logger().info(" **** START ADVERTISING FROM REMOTE DEVICE 2 **** ")
        ble_non_white_list_address = ble_client2.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert ble_non_white_list_address, "UNABLE TO GET BLE CLIENT 2 ADDRESS"
        logger().info(f"ble_non_white_list_address: {ble_non_white_list_address}")
        time.sleep(3)

        #start scanning from dut and enable powersave in dut
        logger().info(f" **** START SCANNING FROM DUT **** ")
        for retry_count in range(3):
            logger().info(f"....SCANNING FOR THE {retry_count+1} ITERATION....")
            try:
                scan_results = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_white_list_address, ble_scan_filter_type=1, timeout=30)
                time.sleep(5)
                if 'RSI_APP_EVENT_ADV_REPORT' in str(scan_results):
                    break
            except Exception as e:
                ble_dut.interfaces.bluetooth.ble_stop_scanning()
                if retry_count==2:
                    raise e
        time.sleep(10)
        logger().info(f" **** ENABLING WLAN AND BT POWER SAVE **** ")
        ## Enables the wlan power save in DUT
        enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, 'FAILED TO ENABLE WLAN POWER SAVE'
        ## Enables the bt power save in DUT
        enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, 'FAILED TO ENABLE BT POWER SAVE'

        logger().info(f" SCAN RESULTS: '{scan_results}")
        assert scan_results, "NO BT DEVICE FOUND"

        status = str(ble_white_list_address) in str(scan_results)
        assert status, "WHITE LISTED ADDRESS NOT PRESENT IN DUT SCAN RESULTS"
        logger().info("WHITE LISTED DEVICE BD ADDRESS PRESENT IN SCAN RESULTS")
        status = str(ble_non_white_list_address) not in str(scan_results)
        assert status, "NON WHITE LISTED ADDRESS PRESENT IN DUT SCAN RESULTS"
        logger().info("NON WHITE LISTED DEVICE BD ADDRESS ISN'T PRESENT IN SCAN RESULTS")
    finally:
        logger().info("STOPPING BLE SCANNING")
        ble_dut.interfaces.bluetooth.ble_stop_scanning()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_master_white_list_remote_device_c19846(ble_dut, ble_client, rs_helper_ble):
    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_ble_dut_master_remote_device_directed_connectable.logs_{int(time.time())}"):
        ble_client.interfaces.bluetooth.close()
        logger().info(f"Start ble DUT and client")
        ble_dut_address = ble_dut.interfaces.wifi.ble_start()
        assert ble_dut_address, f"Unable to get ble_dut_address"
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
        assert ble_client_address, f"Unable to get ble_client_address"
        time.sleep(5)
        try:
            logger().info(f"****** ADDING WHITELIST BEFORE SCANNING")
            ble_dut.interfaces.wifi.ble_add_white_list(ble_client_address)
            logger().info(f"Start scanning and connect to ble client")
            ble_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, ble_scan_filter_type=1,
                                                       timeout=120)
            logger().info("stop scanning")
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(5)
            logger().info("Enabling Wlan and BLE power save")
            enable_wifi_ps = ble_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
            enable_bt_ps = ble_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                 RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_wifi_ps, 'failed to enable wlan power save'
            assert enable_bt_ps, 'failed to enable bt power save'

            logger().info(f"DUT initiating BLE connection with ble_client device")
            rs_helper_ble.ble_connect_DUT_as_master(ble_dut=ble_dut, ble_remote=ble_client,
                                                    ble_dut_address=ble_dut_address,
                                                    ble_remote_address=ble_client_address, smp_flag=True)
            logger().info("******** BLE master connection successful ********")

        except Exception as e:
            logger().info("*************** Exception block for stop advertising and stop scanning")
            ble_client.interfaces.bluetooth.stop_advertising()
            ble_dut.interfaces.wifi.ble_stop_scanning()
            raise e

        logger().info("Check connection status of BLE")
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
        logger().info("DUT is not disconnected from BLE")

        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
        ble_client.interfaces.bluetooth.stop_advertising()