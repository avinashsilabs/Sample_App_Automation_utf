import pytest
from example_test_package.conftest import rs_helper_ble
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, \
    RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap, RS9116PowerSaveProcedureTypes, \
        RS9116BTFeatureBitMap
from utf.utils.logger import get_logger
from utf.interfaces.wifi import WlanError

from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryService
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryLevelCharacteristic
import time, os
import threading
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch

def logger():
    return get_logger(__name__)
"""
    * setup requirement:
        1. DUT(RS9116) ac1 board with EFR
        2. REF(RS9116) ac1 board with EFR
    Author: 
        NandanBaban.Patil@silabs.com
"""
# Mark all tests in this module with 'framework_integration_test'
pytestmark = [
    pytest.mark.framework_integration_test,
    # pytest.mark.dut("rs9116_sapi"),
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass | RS9116TCPIPFeatureBitMap.DHCPv4Client,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
            "bt_feature" : RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
            "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        },
    ),
]


 #######################  LE Ext Adv - BLE Advertising Extension  ####################

def test_EXT_ADV_pkt_and_aux_ptr_C193693(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention packets for undirected connecable adv type and aux pointer
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, test_case_id="C193693",
                                    adv_handle=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    wifi_sniffer=wifi_sniffer, ble_sniffer=ble_sniffer, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_lowest_highest_adv_handle_C193694(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention with lowest and highest adv_handle
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.advertising_address=={ble_dut_address}) && (btle.extended_advertising_header.mode == 0x0)"
    logger().info(f"\n\n ** Verifying AE with lowest handle ie. 0x00 **\n\n")
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, test_case_id="C193694",
                                    adv_handle=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, test_in_progress=True,
                                    wifi_sniffer=wifi_sniffer, ble_sniffer=ble_sniffer, packet_filter1={packet_filter1:"Positive"})
    
    logger().info(f"\n\n ** Verifying AE with highest handle ie. 0xef **\n\n")
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, test_case_id="C193694", 
                                    adv_handle=239, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    wifi_sniffer=wifi_sniffer, ble_sniffer=ble_sniffer, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_adv_on_channel_37_38_39_C193695(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention with adv channels on 37,38 and 39
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"nordic_ble.channel <= 37 and nordic_ble.channel <=39 and btle.advertising_address == {ble_dut_address}"
    packet_filter2 = f"nordic_ble.channel < 37 and btle.advertising_address == {ble_dut_address}"
    logger().info(f"\n\n ** Verifying AE with lowest handle ie. 0x00 **\n\n")
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, test_case_id="C193695",
                                    adv_handle=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    wifi_sniffer=wifi_sniffer, ble_sniffer=ble_sniffer, packet_filter1={packet_filter1:"Positive"}, 
                                    packet_filter2={packet_filter2:"Negative"})

def test_verify_AE_ADV_for_infinite_time_C163696(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention for infinite time with duration paramerter 0x0000
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    adv_handle=0, duration=0)
    
def test_verify_AE_ADV_for_2560ms_C163697(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention for 2560ms and verify even RSI_APP_EVENT_EXT_ADV_TERMINATED
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    adv_handle=0, duration=256, adv_async_required=1)

def test_verify_AE_ADV_for_200_max_event_C163698(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention for max AE events 200 and verify even RSI_APP_EVENT_EXT_ADV_TERMINATED
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    max_ae_events=200, adv_async_required=1)
    
def test_verify_AE_ADV_with_randomm_address_C163701(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention with random address
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"btle.advertising_address == {random_address}"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, own_address_type=1, ble_dut_address=random_address, bt_sniffer=bt_sniffer,
                                      test_case_id="C163701",
                                      random_address=random_address, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                      packet_filter1={packet_filter1:"Positive"}
                                    )
    
#     #######################  LE Ext Adv - Non connectable Non Scannable undirected adv ####################
    
# @pytest.mark.skip ('getting data len 0 even after configuring it with 1')
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163702(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M 
                         with adb data of 1bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, test_case_id="C163702",
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=1,  ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, adv_data="AE_PERIPHERAL_DATA")
    
def test_verify_AE_non_conn_non_scan_ADV_C163703(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M 
                         with adv data of 0 bytes and max ae events: 0x32 ie.50
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"((nordic_ble.phy == 0) && (btle.advertising_address == {ble_dut_address})) && (btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, ble_dut_address=ble_dut_address , bt_sniffer=bt_sniffer, adv_type=0, pri_adv_phy=1, test_case_id="C163703",
                                      sec_adv_phy=1, data_len=0, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    adv_data="AE_PERIPHERAL_DATA", max_ae_events=50, adv_async_required=1, 
                                    packet_filter1={packet_filter1:"Positive"})
    
def test_verify_AE_non_conn_non_scan_ADV_C163704(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M 
                         with adv data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(nordic_ble.phy == 0) && (btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, test_case_id="C163704",
                                    data_len=31, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"}, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@")
    
def test_verify_AE_non_conn_non_scan_ADV_C163705(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M 
                         with adv data length of 200 bytes and Adv duration is 5 sec: 0x1F4
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=200, test_case_id="C163705",
                                    adv_data="AE_PERIPHERAL_DATA", duration=500, adv_async_required=1, 
                                    )
    
def test_verify_AE_non_conn_non_scan_ADV_C163706(ble_dut, bt_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY LE Coded
                         with adv data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, pri_adv_phy=3, sec_adv_phy=3,
                                    data_len=31, test_case_id="C163706",
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@")
    
def test_verify_AE_non_conn_non_scan_ADV_C163707(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY LE Coded 
                         with adv data of 0 bytes and max ae events: 0x32 ie.50
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=0, test_case_id="C163707",
                                    adv_data="AE_PERIPHERAL_DATA", max_ae_events=50, adv_async_required=1)
    
def test_verify_AE_non_conn_non_scan_ADV_C163708(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M 
                         with adv data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address,
                                      pri_adv_phy=3, sec_adv_phy=3, data_len=1, test_case_id="C163708", adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@")
    
def test_verify_AE_non_conn_non_scan_ADV_C163709(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY LE Coded
                         with adv data length of 200 bytes and Adv duration is 5 sec: 0x1F4
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=200, test_case_id="C163709",
                                    adv_data="AE_PERIPHERAL_DATA", duration=500, adv_async_required=1)
    
def test_verify_AE_non_conn_non_scan_ADV_C163710(ble_dut, rs_helper_ble, bt_sniffer, ble_sniffer, wifi_sniffer):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M, 2M 
                         with adv data of 1 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address, 
                                      bt_sniffer=bt_sniffer, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"},
                                      pri_adv_phy=1, sec_adv_phy=2, data_len=1, test_case_id="C163710", adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@")


def test_verify_AE_non_conn_non_scan_ADV_C163711(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri PHY is 1M and sec PHY is 2M 
                         with adv data of 0 bytes and max ae events: 0x32 ie.50
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, data_len=0, test_case_id="C163711",
                                    adv_data="AE_PERIPHERAL_DATA", max_ae_events=50, adv_async_required=1)
    
def test_verify_AE_non_conn_non_scan_ADV_C163712(ble_dut, rs_helper_ble, bt_sniffer, ble_sniffer, wifi_sniffer):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M, 2M 
                         with adv data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address, 
                                      bt_sniffer=bt_sniffer, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"},
                                      pri_adv_phy=1, sec_adv_phy=2, data_len=31, test_case_id="C163712", adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@")

def test_verify_AE_non_conn_non_scan_ADV_C163713(ble_dut, rs_helper_ble, bt_sniffer, ble_sniffer, wifi_sniffer):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M, 2M 
                         with adv data of 474 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address,
                                      bt_sniffer=bt_sniffer, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"},
                                      pri_adv_phy=1, sec_adv_phy=2, data_len=474, test_case_id="C163713", adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@")


def test_verify_AE_non_conn_non_scan_ADV_C163714(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri PHY is 1M and sec PHY is 2M
                         with adv data length of 200 bytes and Adv duration is 5 sec: 0x1F4
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, data_len=200, test_case_id="C163714",
                                    adv_data="AE_PERIPHERAL_DATA", duration=500, adv_async_required=1)
    
    
# #Scannable Non Connectable Undirected Adv with scan_response_data on DUT and primary phy is 1M, sec phy is 1M#

def test_verify_AE_Scannable_non_conn_ADV_C163715(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv - Scannable Non Connectable Undirected Adv 
    Test case          : This test case will verify Scannable Non Connectable Undirected Adv with pri PHY is 1M and sec PHY is 1M
                         with adv data of 31 bytes and scan_data is 1 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"((btle.extended_advertising_header.mode == 0x2) && (nordic_ble.phy == 0)) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, scan_resp_len=1, test_case_id="C163715",
                                    adv_data="AE_PERIPHERAL_DATA_DATA", scan_req_notify_enable=0,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_AE_Scannable_non_conn_ADV_C163716(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv - Scannable Non Connectable Undirected Adv 
    Test case          : This test case will verify Scannable Non Connectable Undirected Adv with pri PHY is 1M and sec PHY is 1M
                         with adv data of 31 bytes and scan_data is 31 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"((btle.extended_advertising_header.mode == 0x2) && (nordic_ble.phy == 0)) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, test_case_id="C163716",
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", scan_req_notify_enable=0,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})

def test_verify_AE_Scannable_non_conn_ADV_C163717(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv - Scannable Non Connectable Undirected Adv 
    Test case          : This test case will verify Scannable Non Connectable Undirected Adv with pri PHY is 1M and sec PHY is 1M
                         with adv data of 200 bytes and scan_data is 200 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"((btle.extended_advertising_header.mode == 0x2) && (nordic_ble.phy == 0)) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=200, test_case_id="C163717",
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", scan_req_notify_enable=0, 
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})
    
pytest.mark.skip ('scan_req_notify event is not receiving')
def test_verify_AE_Scannable_non_conn_ADV_C163718(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv - Scannable Non Connectable Undirected Adv 
    Test case          : This test case will verify Scannable Non Connectable Undirected Adv with pri PHY is 1M and sec PHY is 1M
                         with adv data of 200 bytes and scan_data is 200 byte,  scan_req_notify_enable = 1
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"((btle.extended_advertising_header.mode == 0x2) && (nordic_ble.phy == 0)) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=200, test_case_id="C163718",
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"},
                                    scan_req_notify_enable=1)
    
#Scannable undirected adv with scan_response_data on DUT and primary phy is LE Coded Phy, sec phy is LE Coded Phy.

def test_verify_AE_Scannable_undirected_ADV_C163719(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv - Scannable undirected adv 
    Test case          : This test case will verify Scannable undirected Adv with pri PHY and sec PHY is LE Coded
                         with adv data of 31 bytes and scan_data is 1 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut,  adv_type=2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=31, scan_resp_len = 1, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", test_case_id="C163719",
                                    scan_req_notify_enable=0)
 
def test_verify_AE_Scannable_undirected_ADV_C163720(ble_dut, bt_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable undirected adv 
    Test case          : This test case will verify Scannable undirected Adv with pri PHY and sec PHY is LE Coded
                         with adv data of 31 bytes and scan_data is 31 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=31,
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", test_case_id="C163720",
                                    scan_req_notify_enable=0)
    
def test_verify_AE_Scannable_undirected_ADV_C163721(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv - Scannable undirected adv 
    Test case          : This test case will verify Scannable undirected Adv with pri PHY and sec PHY is LE Coded
                         with adv data of 474 bytes and scan_data is 1 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut,  adv_type=2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=474, scan_resp_len = 1, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", test_case_id="C163721",
                                    scan_req_notify_enable=0)
 
def test_verify_AE_Scannable_undirected_ADV_C163722(ble_dut, bt_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable undirected adv 
    Test case          : This test case will verify Scannable undirected Adv with pri PHY and sec PHY is LE Coded
                         with adv data of 31 bytes and scan_data is 474 byte,  scan_req_notify_enable = 1
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=474,
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", test_case_id="C163722",
                                    scan_req_notify_enable=1)

# #Scannable directed adv with scan_response_data on DUT and primary phy is LE Coded Phy, sec phy is LE Coded Phy

def test_verify_AE_Scannable_directed_ADV_C163723(ble_dut, bt_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable directed adv 
    Test case          : This test case will verify Scannable directed Adv with pri PHY and sec PHY is LE Coded
                         with adv data of 31 bytes and scan_data is 1 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=5, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=1, scan_resp_len = 1, bt_sniffer=bt_sniffer,
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", test_case_id="C163723", whitelist=True,
                                    scan_req_notify_enable=0)
    
def test_verify_AE_Scannable_directed_ADV_C163724(ble_dut, bt_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable directed adv 
    Test case          : This test case will verify Scannable directed Adv with pri PHY and sec PHY is LE Coded
                         with adv data of 31 bytes and scan_data is 31 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=5, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=31, scan_resp_len = 1, bt_sniffer=bt_sniffer,
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", test_case_id="C163723", whitelist=True,
                                    scan_req_notify_enable=0)
    
def test_verify_AE_Scannable_directed_ADV_C163725(ble_dut, bt_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable directed adv 
    Test case          : This test case will verify Scannable undirected Adv with pri PHY and sec PHY is LE Coded
                         with adv data of 31 bytes and scan_data is 474 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=5, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=474, scan_resp_len = 1, bt_sniffer=bt_sniffer,
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", test_case_id="C163723", whitelist=True,
                                    scan_req_notify_enable=0)
    
# LE Ext Adv with filter policy enabled during LE Ext Adv 

def test_verify_AE_Scannable_filter_policy_C163811(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv with filter policy enabled during LE Ext Adv 
    Test case          : This test case will verify Scannable Adv with filter policy 1
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x2) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, test_case_id="C163811",
                                    data_len=31, adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", whitelist=1, adv_filter_policy=1,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"}
                                    )
    
def test_verify_AE_Scannable_filter_policy_C163812(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv with filter policy enabled during LE Ext Adv 
    Test case          : This test case will verify Connectable Adv with filter policy 2
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, test_case_id="C163812",
                                    data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", whitelist=1, adv_filter_policy=2,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_AE_Scannable_filter_policy_C163813(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
    """
    Test case category : LE Ext Adv with filter policy enabled during LE Ext Adv 
    Test case          : This test case will verify Scannable Adv with filter policy 3 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, test_case_id="C163813",
                                    data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", whitelist=1, adv_filter_policy=3,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})
    
#Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M 

def test_verify_AE_Secondary_adv_with_max_skip_1_C163814(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 1 and adv_type=0 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"nordic_ble.phy == 0 && (btle.extended_advertising_header.mode == 0x0) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, 
                                    min_interval=320, max_interval=352, sec_adv_max_skip=1, data_len=31, test_case_id="C163814",
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHE", pri_adv_phy=1, sec_adv_phy=2,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Secondary_adv_with_max_skip_15_C163815(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 1 and adv_type=0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"nordic_ble.phy == 0 && (btle.extended_advertising_header.mode == 0x0) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=15, data_len=31, test_case_id="C163815",
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", pri_adv_phy=1, sec_adv_phy=2,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_AE_Secondary_adv_with_max_skip_255_C163816(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 255 and adv_type=0 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"nordic_ble.phy == 0 && (btle.extended_advertising_header.mode == 0x0) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=255, data_len=31, test_case_id="C163816",
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", pri_adv_phy=1, sec_adv_phy=2,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})


def test_verify_AE_Secondary_adv_with_max_skip_08_adv_1_C163817(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 8 and adv_type=1 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"nordic_ble.phy == 0 && (btle.extended_advertising_header.mode == 0x1) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=8, data_len=31, test_case_id="C163817",
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", pri_adv_phy=1, sec_adv_phy=2,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})

def test_verify_AE_Secondary_adv_with_max_skip_08_adv_4_C163818(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 8 and adv_type=4 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"nordic_ble.phy == 0 && (btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=4, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=8, data_len=31, test_case_id="C163818",
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", pri_adv_phy=1, sec_adv_phy=2,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})

def test_verify_AE_Secondary_adv_with_max_skip_08_adv_5_C163819(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 8 and adv_type=5 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"nordic_ble.phy == 0 && (btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=5, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=8, data_len=31, test_case_id="C163819",
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", pri_adv_phy=1, sec_adv_phy=2,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})

#Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M'

def test_verify_AE_2ADV_sets_C163820(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M 
    Test case          : This test case will verify 2 adv sets with pri phy 1m and sec phy 2m, adv type 0 and 1
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    pri_adv_phy=1, sec_adv_phy=2, test_case_id="C163820",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, 
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163821(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M 
    Test case          : This test case will verify 2 adv sets with pri phy 1m and sec phy 2m, adv type 1 and 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    pri_adv_phy=1, sec_adv_phy=2, test_case_id="C163821",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, 
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163822(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M 
    Test case          : This test case will verify 2 adv sets with pri phy 1m and sec phy 2m, adv type 0 and 5
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, test_case_id="C163822",
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163823(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M 
    Test case          : This test case will verify 2 adv sets with pri phy 1m and sec phy 2m, adv type 0 and 2
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x2)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, 
                                    pri_adv_phy=1, sec_adv_phy=2, test_case_id="C163823",
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163824(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M 
    Test case          : This test case will verify 2 adv sets with pri phy 1m and sec phy 2m, adv type 0 and 4 with data len 200
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=4, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=200, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, test_case_id="C163824",
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163825(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M 
    Test case          : This test case will verify 2 adv sets with pri phy 1m and sec phy 2m, adv type 0 and 1 with data len 200 and 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, 
                                    pri_adv_phy=1, sec_adv_phy=2, test_case_id="C163825",
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})


def test_verify_AE_2ADV_sets_C163826(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M 
    Test case          : This test case will verify 2 adv sets with pri phy 1m and sec phy 2m, adv type 0 and 1 with data len 474 and 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, test_case_id="C163826",
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
### Extended Advertising, two Sets, Single PHY, LE primary phy is LE Coded PHY and sec phy is LE Coded

def test_verify_AE_2ADV_sets_C163827(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy and sec phy is LE Coded  
    Test case          : This test case will verify 2 adv sets with pri phy and sec phy is LE Coded, adv type 0 and 1 with data len 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, pri_adv_phy=3, sec_adv_phy=3)
    
def test_verify_AE_2ADV_sets_C163828(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy and sec phy is LE Coded  
    Test case          : This test case will verify 2 adv sets with pri phy and sec phy is LE Coded, adv type 1 and 0 with data len 0 and 191
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, pri_adv_phy=3, sec_adv_phy=3)
    
def test_verify_AE_2ADV_sets_C163829(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy and sec phy is LE Coded  
    Test case          : This test case will verify 2 adv sets with pri phy and sec phy is LE Coded, adv type 0 and 5 with data len 191 and 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, pri_adv_phy=3, sec_adv_phy=3)
    
def test_verify_AE_2ADV_sets_C163830(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy and sec phy is LE Coded  
    Test case          : This test case will verify 2 adv sets with pri phy and sec phy is LE Coded, adv type 0 and 2 with data len 191
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, pri_adv_phy=3, sec_adv_phy=3)
    
def test_verify_AE_2ADV_sets_C163831(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy and sec phy is LE Coded  
    Test case          : This test case will verify 2 adv sets with pri phy and sec phy is LE Coded, adv type 1 and 4 with data len 200
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=4, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=200, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, pri_adv_phy=3, sec_adv_phy=3)
    
def test_verify_AE_2ADV_sets_C163832(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy and sec phy is LE Coded  
    Test case          : This test case will verify 2 adv sets with pri phy and sec phy is LE Coded, adv type 0 and 1 with data len 200 and 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, pri_adv_phy=3, sec_adv_phy=3)
    
def test_verify_AE_2ADV_sets_C163833(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy and sec phy is LE Coded  
    Test case          : This test case will verify 2 adv sets with pri phy and sec phy is LE Coded, adv type 0 and 1 with data len 474 and 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=474, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, pri_adv_phy=3, sec_adv_phy=3)

#Extended Advertising, Multiple Sets, Legacy and Extended

def test_verify_AE_2ADV_sets_C163834(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Extended Advertising, Multiple Sets, Legacy and Extended
    Test case          : This test case will verify 2 adv sets with adv type 0 and 10 and data length 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.advertising_header.pdu_type == 0x2)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=16, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, test_case_id="C163834",
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163835(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Extended Advertising, Multiple Sets, Legacy and Extended
    Test case          : This test case will verify 2 adv sets with adv type 0x13 and 0 and data length 0, 191
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.advertising_header.pdu_type == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=19, adv_type_s2=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, test_case_id="C163835",
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163836(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Extended Advertising, Multiple Sets, Legacy and Extended
    Test case          : This test case will verify 2 adv sets with adv type 0 and 0x13 and data length 191, 31
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.advertising_header.pdu_type == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=19, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, test_case_id="C163836",
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163837(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Extended Advertising, Multiple Sets, Legacy and Extended
    Test case          : This test case will verify 2 adv sets with adv type 0x13 and 0x10 and data length 31
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.advertising_header.pdu_type == 0x0)"
    packet_filter2 = f"(btle.advertising_header.pdu_type == 0x2)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=19, adv_type_s2=16, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=31, data_len_s2=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, test_case_id="C163837",
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163838(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Extended Advertising, Multiple Sets, Legacy and Extended
    Test case          : This test case will verify 2 adv sets with adv type 0x13 and 0x10 and data length 31
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.advertising_header.pdu_type == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=21, adv_type_s2=4, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=200, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, test_case_id="C163838",
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163839(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Extended Advertising, Multiple Sets, Legacy and Extended
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1D and data length 200, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.advertising_header.pdu_type == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=29, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, test_case_id="C163839",
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163840(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Extended Advertising, Multiple Sets, Legacy and Extended
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x12 and data length 474, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.advertising_header.pdu_type == 0x6)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=18, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=474, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, test_case_id="C163840",
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
#Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy     
def test_verify_AE_2ADV_sets_C163841(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy 
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1 and data length 0
    Device roles       : DUT is performing Peripheral role 
    """
    rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=random_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=3, random_address=random_address, test_case_id="C163841",
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163842(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy 
    Test case          : This test case will verify 2 adv sets with adv type 0x1 and 0x0 and data length 0
    Device roles       : DUT is performing Peripheral role 
    """
    rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=0, ble_dut_address=random_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=3, random_address=random_address, test_case_id="C163842",
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163843(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy 
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x5 and data length 191, 0
    Device roles       : DUT is performing Peripheral role 
    """
    rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=random_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=3, random_address=random_address, test_case_id="C163843",
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163844(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy 
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x2 and data length 191
    Device roles       : DUT is performing Peripheral role 
    """
    rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x2)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=2, ble_dut_address=random_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=3, random_address=random_address, test_case_id="C163844",
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163845(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy 
    Test case          : This test case will verify 2 adv sets with adv type 0x1 and 0x4 and data length 200
    Device roles       : DUT is performing Peripheral role 
    """
    rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=4, ble_dut_address=random_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=3, random_address=random_address, test_case_id="C163845",
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=200, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163846(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy 
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1 and data length 200, 0
    Device roles       : DUT is performing Peripheral role 
    """
    rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=random_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=3, random_address=random_address, test_case_id="C163846",
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163847(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy 
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x5 and data length 474, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=3, random_address=random_address, test_case_id="C163847",
                                    min_interval=32, max_interval=32, data_len=474, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
#Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M

def test_verify_AE_2ADV_sets_C163848(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1 and data length 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, random_address_s2=random_address, test_case_id="C163848",
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163849(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M
    Test case          : This test case will verify 2 adv sets with adv type 0x1 and 0x0 and data length 0, 191
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, random_address_s2=random_address, test_case_id="C163849",
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163850(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x5 and data length 191, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, random_address_s2=random_address, test_case_id="C163850",
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163851(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x2 and data length 191, 191
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x2)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, random_address_s2=random_address, test_case_id="C163851",
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163852(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M
    Test case          : This test case will verify 2 adv sets with adv type 0x1 and 0x4 and data length 200, 200
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=4, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, random_address_s2=random_address, test_case_id="C163852",
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=200, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163853(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1 and data length 200, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, random_address_s2=random_address, test_case_id="C163853",
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163854(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x2 and data length 474, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, random_address_s2=random_address, test_case_id="C163854",
                                    min_interval=32, max_interval=32, data_len=474, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

#Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M

def test_verify_AE_2ADV_sets_C163855(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1 and data length 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, random_address_s2=random_address, test_case_id="C163855",
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163856(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M
    Test case          : This test case will verify 2 adv sets with adv type 0x1 and 0x0 and data length 0, 191
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, random_address_s2=random_address, test_case_id="C163856",
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163857(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x5 and data length 191, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, random_address_s2=random_address, test_case_id="C163857",
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163858(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x2 and data length 191, 191
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x2)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, random_address_s2=random_address, test_case_id="C163858",
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163859(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M
    Test case          : This test case will verify 2 adv sets with adv type 0x1 and 0x4 and data length 200, 200
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=4, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, random_address_s2=random_address, test_case_id="C163859", 
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=200, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163860(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1 and data length 200, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, random_address_s2=random_address, test_case_id="C163860",
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163861(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x2 and data length 474, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, random_address_s2=random_address, test_case_id="C163861",
                                    min_interval=32, max_interval=32, data_len=474, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
# Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =LE COded and Sec Phy LE Coded 

def test_verify_AE_2ADV_sets_C163862(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =LE COded and Sec Phy LE Coded
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1 and data length 0, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address, 
                                    pri_adv_phy=3, sec_adv_phy=3, random_address_s2=random_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1)
    
def test_verify_AE_2ADV_sets_C163863(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =LE COded and Sec Phy LE Coded
    Test case          : This test case will verify 2 adv sets with adv type 0x1 and 0x0 and data length 0, 191
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=0, ble_dut_address=ble_dut_address, 
                                    pri_adv_phy=3, sec_adv_phy=3, random_address_s2=random_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1)
    
def test_verify_AE_2ADV_sets_C163864(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =LE COded and Sec Phy LE Coded
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x5 and data length 191, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=ble_dut_address, 
                                    pri_adv_phy=3, sec_adv_phy=3, random_address_s2=random_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1)
    
def test_verify_AE_2ADV_sets_C163865(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =LE COded and Sec Phy LE Coded
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x2 and data length 191, 191
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=2, ble_dut_address=ble_dut_address, 
                                    pri_adv_phy=3, sec_adv_phy=3, random_address_s2=random_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1)
    
def test_verify_AE_2ADV_sets_C163866(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =LE COded and Sec Phy LE Coded
    Test case          : This test case will verify 2 adv sets with adv type 0x1 and 0x4 and data length 200, 200
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=4, ble_dut_address=ble_dut_address, 
                                    pri_adv_phy=3, sec_adv_phy=3, random_address_s2=random_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1)
    
def test_verify_AE_2ADV_sets_C163867(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =LE COded and Sec Phy LE Coded
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1 and data length 200, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address, 
                                    pri_adv_phy=3, sec_adv_phy=3, random_address_s2=random_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1)
    
def test_verify_AE_2ADV_sets_C163868(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =LE COded and Sec Phy LE Coded
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1 and data length 474, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address, 
                                    pri_adv_phy=3, sec_adv_phy=3, random_address_s2=random_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=474, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1)
    
# #Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected.
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163869(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 1m, addr_type public, adv_min 20ms, adv_max 28ms
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, max_ae_events=20, adv_async_required=True, test_case_id="C163869",
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163870(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 2m, addr_type public, adv_min 20ms, adv_max 28ms
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163870",
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163871(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy LE coded, sec phy Le Coded, addr_type public, adv_min 20ms, adv_max 28ms
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, max_ae_events=20, adv_async_required=True,
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5)
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163872(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 1m, addr_type random_address, adv_min 20ms, adv_max 28ms
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163872",
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163873(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 2m, addr_type random_address, adv_min 20ms, adv_max 28ms
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163873",
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163874(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy LE coded, sec phy Le coded, addr_type random_address, adv_min 20ms, adv_max 28ms
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, max_ae_events=20, adv_async_required=True,
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address)
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163875(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 1m, addr_type public, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, max_ae_events=20, adv_async_required=True, test_case_id="C163875",
                                    min_interval=80, max_interval=160, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163876(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 2m, addr_type public, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163876",
                                    min_interval=80, max_interval=160, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163877(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy LE coded, sec phy Le Coded, addr_type public, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, max_ae_events=20, adv_async_required=True,
                                    min_interval=80, max_interval=160, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5)
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163878(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 1m, addr_type random_address, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163878",
                                    min_interval=80, max_interval=160, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163879(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 2m, addr_type random_address, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163879",
                                    min_interval=32, max_interval=80, data_len=160, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163880(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy LE coded, sec phy Le coded, addr_type random_address, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, 
                                    pri_adv_phy=3, sec_adv_phy=3, max_ae_events=20, adv_async_required=True,
                                    min_interval=32, max_interval=80, data_len=160, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address)
    
#Enable - Disable Ext Adv in Loop ,adv type = non conn non scan undirected. 
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163881(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop ,adv type = non conn non scan undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 1m, addr_type public, adv_min ,0x20 adv_max 0x28
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, max_ae_events=20, adv_async_required=True, test_case_id="C163881",
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163882(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 2m, addr_type public, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163882",
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163883(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy LE coded, sec phy Le Coded, addr_type public, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, max_ae_events=20, adv_async_required=True,
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5)
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163884(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 1m, addr_type random_address, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163884",
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163885(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 2m, addr_type random_address, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163885",
                                    min_interval=32, max_interval=32, data_len=40, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=2, random_address=random_address, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163886(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy LE coded, sec phy Le coded, addr_type random_address, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, max_ae_events=20, adv_async_required=True,
                                    min_interval=32, max_interval=80, data_len=160, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address)

## Negative Test scenarios
    
def test_verify_Negative_case_C163735(ble_dut, rs_helper_ble):
    """
    Test case category : Negative Test scenarios
    Test case          : This test case will verify 0x04c error, when legacy and ext adv started together with single adv set
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=160, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id="C163736",
                                    dont_cleanup=True, test_in_progress=True)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=17, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id="C163736",
                                    error_expected= "Error code: 0x4e0c Msg: Command disallowed Command")
    

@pytest.mark.skip ("test case is not failing with invalid adv handle")
def test_verify_Negative_case_C163736(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Negative Test scenarios
    Test case          : This test case will verify invalid adv handle
    Device roles       : DUT is performing Peripheral role 
    """
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=160, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id="C163736",
                                    adv_handle=300000, packet_filter1={packet_filter1:"Positive"}, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer)
    
def test_verify_Negative_case_C163737(ble_dut, rs_helper_ble):
    """
    Test case category : Negative Test scenarios
    Test case          : This test case will verify terminated callback event with error 60, wit duration value 256ms
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    duration=256, adv_async_required=True)
    
def test_verify_Negative_case_C163738(ble_dut, rs_helper_ble):
    """
    Test case category : Negative Test scenarios
    Test case          : This test case will verify terminated callback event with error 67, with max ae events value 0x5
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    max_ae_events=5, adv_async_required=True)
    
def test_verify_Negative_case_C163739(ble_dut, rs_helper_ble):
    """
    Test case category : Negative Test scenarios
    Test case          : This test case will verify invalid adv handle error 0x4e42 for set_adv_data command
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    invalid_data_hdl=99, dont_cleanup=True, error_expected= "0x4e42")
    
def test_verify_Negative_case_C163740(ble_dut, rs_helper_ble):
    """
    Test case category : Negative Test scenarios
    Test case          : This test case will verify error 0x4e12 after setting filter_duplicates =2 and duraion/period =0 during scan enable
    Device roles       : DUT is performing Central role 
    """
    rs_helper_ble.BLE_AE().verify_ae_scan(central=ble_dut, filter_duplicates=2, error_expected="0x4e12", dont_cleanup=True)

def test_verify_Negative_case_C163741(ble_dut, rs_helper_ble):
    """
    Test case category : Negative Test scenarios
    Test case          : This test case will verify error 0x4e12 after setting duraion is greater or equal to period during scan enable
    Device roles       : DUT is performing Central role 
    """
    rs_helper_ble.BLE_AE().verify_ae_scan(central=ble_dut, duration=500, period=500, error_expected="0x4e12", dont_cleanup=True)

def test_verify_Negative_case_C163742(ble_dut, rs_helper_ble):
    """
    Test case category : Negative Test scenarios
    Test case          : This test case will verify error 0x4e12 after setting scan enable with own add type as random and not setting random add prior
    Device roles       : DUT is performing Central role 
    """
    rs_helper_ble.BLE_AE().verify_ae_scan(central=ble_dut, own_addr_type=1, error_expected="0x4e12", dont_cleanup=True)

@pytest.mark.skip ("set random address is failing")
def test_verify_Negative_case_C163743(ble_dut, rs_helper_ble):
    """
    Test case category : Negative Test scenarios
    Test case          : This test case will verify error 0x4e12 not come after setting scan enable with own add type as random and setting random add prior
    Device roles       : DUT is performing Central role 
    """
    rs_helper_ble.BLE_AE().verify_ae_scan(central=ble_dut, own_addr_type=1, random_address="AA:BB:CC:11:23:33")

@pytest.mark.skip ("Expected error is not observed")
def test_verify_Negative_case_C163744(ble_dut, rs_helper_ble):
    """
    Test case category : Negative Test scenarios
    Test case          : This test case will verify error 0x4e12 not come after setting scan enable with own add type as random and setting random add prior
    Device roles       : DUT is performing Central role 
    """
    rs_helper_ble.BLE_AE().verify_ae_scan(central=ble_dut, interval=48, window=49)