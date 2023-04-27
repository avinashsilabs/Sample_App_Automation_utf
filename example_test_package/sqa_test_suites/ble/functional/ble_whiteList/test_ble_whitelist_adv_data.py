import time
import pytest
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
