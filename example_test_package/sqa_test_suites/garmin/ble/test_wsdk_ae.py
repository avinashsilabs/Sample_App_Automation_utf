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

def test_EXT_ADV_pkt_and_aux_ptr_C193693(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention packets for undirected connecable adv type and aux pointer
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=None, adv_type=1,
                                    adv_handle=0, ble_dut_address=ble_dut_address,
                                    wifi_sniffer=wifi_sniffer, ble_sniffer=ble_sniffer, packet_filter1={packet_filter1:"Positive"})
    

def test_verify_lowest_highest_adv_handle_C193694(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention with lowest and highest adv_handle
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.advertising_address=={ble_dut_address}) && (btle.extended_advertising_header.mode == 0x0)"
    logger().info(f"\n\n ** Verifying AE with lowest handle ie. 0x00 **\n\n")
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0,
                                    adv_handle=0, ble_dut_address=ble_dut_address,
                                    wifi_sniffer=wifi_sniffer, ble_sniffer=ble_sniffer, packet_filter1={packet_filter1:"Positive"})
    
    logger().info(f"\n\n ** Verifying AE with highest handle ie. 0xef **\n\n")
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0,
                                    adv_handle=239, ble_dut_address=ble_dut_address,
                                    wifi_sniffer=wifi_sniffer, ble_sniffer=ble_sniffer, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_adv_on_channel_37_38_39_C193695(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention with adv channels on 37,38 and 39
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"nordic_ble.channel <= 37 and nordic_ble.channel <=39 and btle.advertising_address == {ble_dut_address}"
    packet_filter2 = f"nordic_ble.channel < 37 and btle.advertising_address == {ble_dut_address}"
    logger().info(f"\n\n ** Verifying AE with lowest handle ie. 0x00 **\n\n")
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0,
                                    adv_handle=0, ble_dut_address=ble_dut_address,
                                    wifi_sniffer=wifi_sniffer, ble_sniffer=ble_sniffer, packet_filter1={packet_filter1:"Positive"}, 
                                    packet_filter2={packet_filter2:"Negative"})

def test_verify_AE_ADV_for_infinite_time_C163696(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention for infinite time with duration paramerter 0x0000
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"btle.advertising_address == {ble_dut_address}"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    print_all_adv_devices=0, adv_handle=0, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    adv_time=60, duration=0, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_AE_ADV_for_2560ms_C163697(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention for 2560ms and verify even RSI_APP_EVENT_EXT_ADV_TERMINATED
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"btle.advertising_address == {ble_dut_address}"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    adv_handle=0, duration=256, adv_async_required=1, no_scan=1, 
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})

def test_verify_AE_ADV_for_200_max_event_C163698(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention for max AE events 200 and verify even RSI_APP_EVENT_EXT_ADV_TERMINATED
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"btle.advertising_address == {ble_dut_address}"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=0, ble_dut_address=ble_dut_address,
                                    max_ae_events=200, adv_async_required=1, no_scan=1,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_AE_ADV_with_randomm_address_C163701(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention with random address
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"btle.advertising_address == {random_address}"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, own_address_type=1, ble_dut_address=random_address,
                                      random_address=random_address, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                      packet_filter1={packet_filter1:"Positive"}
                                    )
    
#     #######################  LE Ext Adv - Non connectable Non Scannable undirected adv ####################
    
@pytest.mark.skip ('getting data len 0 even after configuring it with 1')
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163702(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M 
                         with adb data of 1bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"btle.advertising_address == {ble_dut_address}"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=1,  ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, adv_data="AE_PERIPHERAL_DATA")
    
def test_verify_AE_non_conn_non_scan_ADV_C163703(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M 
                         with adv data of 0 bytes and max ae events: 0x32 ie.50
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"((nordic_ble.phy == 0) && (btle.advertising_address == {ble_dut_address})) && (btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, ble_dut_address=ble_dut_address ,adv_type=0, pri_adv_phy=1, 
                                      sec_adv_phy=1, data_len=0, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    adv_data="AE_PERIPHERAL_DATA", max_ae_events=50, adv_async_required=1, 
                                    packet_filter1={packet_filter1:"Positive"})
    
pytest.mark.skip ("getting data len 0 even after configuring it with 31")
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163704(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M 
                         with adv data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"((nordic_ble.phy == 0) && (btle.advertising_address == {ble_dut_address})) && (btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address,
                                    data_len=31, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"}, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@")
    
def test_verify_AE_non_conn_non_scan_ADV_C163705(ble_dut, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M 
                         with adv data length of 200 bytes and Adv duration is 5 sec: 0x1F4
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=200, 
                                    adv_data="AE_PERIPHERAL_DATA", duration=500, adv_async_required=1, 
                                    )
    
pytest.mark.skip ("getting data len 0 even after configuring it with 1")
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163706(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY LE Coded
                         with adv data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address, pri_adv_phy=3, sec_adv_phy=3,
                                    data_len=31, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"}, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@")
    
def test_verify_AE_non_conn_non_scan_ADV_C163707(ble_dut, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY LE Coded 
                         with adv data of 0 bytes and max ae events: 0x32 ie.50
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=0, 
                                    adv_data="AE_PERIPHERAL_DATA", max_ae_events=50, adv_async_required=1)
    
pytest.mark.skip ("getting data len 0 even after configuring it with 31")
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163708(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M 
                         with adv data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address, pri_adv_phy=3, sec_adv_phy=3,
                                    data_len=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"}, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@")
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163709(ble_dut, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY LE Coded
                         with adv data length of 200 bytes and Adv duration is 5 sec: 0x1F4
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=200, 
                                    adv_data="AE_PERIPHERAL_DATA", duration=500, adv_async_required=1)
    
def test_verify_AE_non_conn_non_scan_ADV_C163711(ble_dut, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri PHY is 1M and sec PHY is 2M 
                         with adv data of 0 bytes and max ae events: 0x32 ie.50
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=2, data_len=0, 
                                    adv_data="AE_PERIPHERAL_DATA", max_ae_events=50, adv_async_required=1)
    
def test_verify_AE_non_conn_non_scan_ADV_C163714(ble_dut, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri PHY is 1M and sec PHY is 2M
                         with adv data length of 200 bytes and Adv duration is 5 sec: 0x1F4
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=2, data_len=200, 
                                    adv_data="AE_PERIPHERAL_DATA", duration=500, adv_async_required=1)
    
    
# #Scannable Non Connectable Undirected Adv with scan_response_data on DUT and primary phy is 1M, sec phy is 1M#

def test_verify_AE_Scannable_non_conn_ADV_C163715(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable Non Connectable Undirected Adv 
    Test case          : This test case will verify Scannable Non Connectable Undirected Adv with pri PHY is 1M and sec PHY is 1M
                         with adv data of 31 bytes and scan_data is 1 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"((btle.extended_advertising_header.mode == 0x2) && (nordic_ble.phy == 0)) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, scan_resp_len=1, 
                                    adv_data="AE_PERIPHERAL_DATA_DATA", scan_req_notify_enable=0,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_AE_Scannable_non_conn_ADV_C163716(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable Non Connectable Undirected Adv 
    Test case          : This test case will verify Scannable Non Connectable Undirected Adv with pri PHY is 1M and sec PHY is 1M
                         with adv data of 31 bytes and scan_data is 31 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"((btle.extended_advertising_header.mode == 0x2) && (nordic_ble.phy == 0)) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", scan_req_notify_enable=0,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})

def test_verify_AE_Scannable_non_conn_ADV_C163717(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable Non Connectable Undirected Adv 
    Test case          : This test case will verify Scannable Non Connectable Undirected Adv with pri PHY is 1M and sec PHY is 1M
                         with adv data of 200 bytes and scan_data is 200 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"((btle.extended_advertising_header.mode == 0x2) && (nordic_ble.phy == 0)) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=200, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", scan_req_notify_enable=0, 
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})
    
pytest.mark.skip ('scan_req_notify event is not receiving')
def test_verify_AE_Scannable_non_conn_ADV_C163718(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable Non Connectable Undirected Adv 
    Test case          : This test case will verify Scannable Non Connectable Undirected Adv with pri PHY is 1M and sec PHY is 1M
                         with adv data of 200 bytes and scan_data is 200 byte,  scan_req_notify_enable = 1
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"((btle.extended_advertising_header.mode == 0x2) && (nordic_ble.phy == 0)) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=200, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"},
                                    scan_req_notify_enable=1)
    
#Scannable undirected adv with scan_response_data on DUT and primary phy is LE Coded Phy, sec phy is LE Coded Phy.

@pytest.mark.skip ('No adv packets are getting captured with LE Coded')
def test_verify_AE_Scannable_undirected_ADV_C163719(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable undirected adv 
    Test case          : This test case will verify Scannable undirected Adv with pri PHY and sec PHY is LE Coded
                         with adv data of 31 bytes and scan_data is 1 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x2) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut,  adv_type=2, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=31, scan_resp_len = 1, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@",
                                    scan_req_notify_enable=0, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"},)

@pytest.mark.skip ('No adv packets are getting captured with LE Coded')   
def test_verify_AE_Scannable_undirected_ADV_C163720(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable undirected adv 
    Test case          : This test case will verify Scannable undirected Adv with pri PHY and sec PHY is LE Coded
                         with adv data of 31 bytes and scan_data is 31 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=2, ble_client=ble_client,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=31,
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@",
                                    scan_req_notify_enable=0, print_all_adv_devices=0)

# #Scannable directed adv with scan_response_data on DUT and primary phy is LE Coded Phy, sec phy is LE Coded Phy

@pytest.mark.skip ('No adv packets are getting captured with LE Coded')
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Scannable_undirected_ADV_C163723(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable undirected adv 
    Test case          : This test case will verify Scannable undirected Adv with pri PHY and sec PHY is LE Coded
                         with adv data of 31 bytes and scan_data is 1 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=6, ble_client=ble_client,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, scan_resp_len = 1, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@",
                                    scan_req_notify_enable=0, print_all_adv_devices=0)

def test_verify_AE_Scannable_filter_policy_C163811(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv with filter policy enabled during LE Ext Adv 
    Test case          : This test case will verify Scannable Adv with filter policy 1
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x2) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=2, ble_dut_address=ble_dut_address,
                                    data_len=31, adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", whitelist=1, adv_filter_policy=1,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"}
                                    )
    
def test_verify_AE_Scannable_filter_policy_C163812(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv with filter policy enabled during LE Ext Adv 
    Test case          : This test case will verify Connectable Adv with filter policy 2
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                    data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", whitelist=1, adv_filter_policy=2,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_AE_Scannable_filter_policy_C163813(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : LE Ext Adv with filter policy enabled during LE Ext Adv 
    Test case          : This test case will verify Scannable Adv with filter policy 3 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                    data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", whitelist=1, adv_filter_policy=3,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})
    
#Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M 

def test_verify_AE_Secondary_adv_with_max_skip_1_C163814(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 1 and adv_type=0 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"nordic_ble.phy == 0 && (btle.extended_advertising_header.mode == 0x0) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, 
                                    min_interval=320, max_interval=352, sec_adv_max_skip=1, data_len=31,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHE", pri_adv_phy=1, sec_adv_phy=2,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Secondary_adv_with_max_skip_15_C163815(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 1 and adv_type=0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"nordic_ble.phy == 0 && (btle.extended_advertising_header.mode == 0x0) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=15, data_len=31,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", pri_adv_phy=1, sec_adv_phy=2,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_AE_Secondary_adv_with_max_skip_255_C163816(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 255 and adv_type=0 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"nordic_ble.phy == 0 && (btle.extended_advertising_header.mode == 0x0) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=255, data_len=31,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", pri_adv_phy=1, sec_adv_phy=2,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})


def test_verify_AE_Secondary_adv_with_max_skip_08_adv_1_C163817(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 8 and adv_type=1 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"nordic_ble.phy == 0 && (btle.extended_advertising_header.mode == 0x1) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=8, data_len=31,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", pri_adv_phy=1, sec_adv_phy=2,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})

def test_verify_AE_Secondary_adv_with_max_skip_08_adv_4_C163818(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 8 and adv_type=4 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"nordic_ble.phy == 0 && (btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=4, ble_dut_address=ble_dut_address,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=8, data_len=31,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", pri_adv_phy=1, sec_adv_phy=2,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})

def test_verify_AE_Secondary_adv_with_max_skip_08_adv_5_C163819(ble_dut, ble_sniffer, wifi_sniffer, rs_helper_ble):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 8 and adv_type=5 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"nordic_ble.phy == 0 && (btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=5, ble_dut_address=ble_dut_address,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=8, data_len=31,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", pri_adv_phy=1, sec_adv_phy=2,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})

#Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M'

def test_verify_AE_2ADV_sets_C163820(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M 
    Test case          : This test case will verify 2 adv sets with pri phy 1m and sec phy 2m, adv type 0 and 1
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address,
                                    min_interval=32, max_interval=32, data_len=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    pri_adv_phy=1, sec_adv_phy=2,
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, 
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163821(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M 
    Test case          : This test case will verify 2 adv sets with pri phy 1m and sec phy 2m, adv type 1 and 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=0, ble_dut_address=ble_dut_address,
                                    min_interval=32, max_interval=32, data_len=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    pri_adv_phy=1, sec_adv_phy=2,
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, 
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163822(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M 
    Test case          : This test case will verify 2 adv sets with pri phy 1m and sec phy 2m, adv type 0 and 5
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=ble_dut_address,
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163823(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M 
    Test case          : This test case will verify 2 adv sets with pri phy 1m and sec phy 2m, adv type 0 and 2
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x2)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=2, ble_dut_address=ble_dut_address,
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, 
                                    pri_adv_phy=1, sec_adv_phy=2,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163824(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M 
    Test case          : This test case will verify 2 adv sets with pri phy 1m and sec phy 2m, adv type 0 and 4 with data len 200
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=4, ble_dut_address=ble_dut_address,
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=200, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, 
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163825(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M 
    Test case          : This test case will verify 2 adv sets with pri phy 1m and sec phy 2m, adv type 0 and 1 with data len 200 and 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address,
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, 
                                    pri_adv_phy=1, sec_adv_phy=2,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})


def test_verify_AE_2ADV_sets_C163826(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M 
    Test case          : This test case will verify 2 adv sets with pri phy 1m and sec phy 2m, adv type 0 and 1 with data len 474 and 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address,
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, 
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
### Extended Advertising, two Sets, Single PHY, LE primary phy is LE Coded PHY and sec phy is LE Coded

pytest.mark.skip ("blocked as for validation LE coded adv packets are not getting captured in NRF")
def test_verify_AE_2ADV_sets_C163827(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M 
    Test case          : This test case will verify 2 adv sets with pri phy 1m and sec phy 2m, adv type 0 and 1 with data len 474 and 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address,
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, 
                                    pri_adv_phy=3, sec_adv_phy=3,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

#Extended Advertising, Multiple Sets, Legacy and Extended

def test_verify_AE_2ADV_sets_C163834(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Extended Advertising, Multiple Sets, Legacy and Extended
    Test case          : This test case will verify 2 adv sets with adv type 0 and 10 and data length 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.advertising_header.pdu_type == 0x2)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=16, ble_dut_address=ble_dut_address,
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163835(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Extended Advertising, Multiple Sets, Legacy and Extended
    Test case          : This test case will verify 2 adv sets with adv type 0x13 and 0 and data length 0, 191
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.advertising_header.pdu_type == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=19, adv_type_s2=0, ble_dut_address=ble_dut_address,
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
def test_verify_AE_2ADV_sets_C163836(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Extended Advertising, Multiple Sets, Legacy and Extended
    Test case          : This test case will verify 2 adv sets with adv type 0 and 0x13 and data length 191, 31
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.advertising_header.pdu_type == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=19, ble_dut_address=ble_dut_address,
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163837(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Extended Advertising, Multiple Sets, Legacy and Extended
    Test case          : This test case will verify 2 adv sets with adv type 0x13 and 0x10 and data length 31
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.advertising_header.pdu_type == 0x0)"
    packet_filter2 = f"(btle.advertising_header.pdu_type == 0x2)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=19, adv_type_s2=16, ble_dut_address=ble_dut_address,
                                    min_interval=32, max_interval=32, data_len=31, data_len_s2=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163838(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Extended Advertising, Multiple Sets, Legacy and Extended
    Test case          : This test case will verify 2 adv sets with adv type 0x13 and 0x10 and data length 31
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.advertising_header.pdu_type == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=21, adv_type_s2=4, ble_dut_address=ble_dut_address,
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=200, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163839(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Extended Advertising, Multiple Sets, Legacy and Extended
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1D and data length 200, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.advertising_header.pdu_type == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=29, ble_dut_address=ble_dut_address,
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163840(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Extended Advertising, Multiple Sets, Legacy and Extended
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x12 and data length 474, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.advertising_header.pdu_type == 0x6)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=18, ble_dut_address=ble_dut_address,
                                    min_interval=32, max_interval=32, data_len=474, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
#Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy     
def test_verify_AE_2ADV_sets_C163841(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy 
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1 and data length 0
    Device roles       : DUT is performing Peripheral role 
    """
    rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=random_address,
                                    pri_adv_phy=1, sec_adv_phy=3, random_address=random_address, 
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163842(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy 
    Test case          : This test case will verify 2 adv sets with adv type 0x1 and 0x0 and data length 0
    Device roles       : DUT is performing Peripheral role 
    """
    rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=0, ble_dut_address=random_address,
                                    pri_adv_phy=1, sec_adv_phy=3, random_address=random_address, 
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163843(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy 
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x5 and data length 191, 0
    Device roles       : DUT is performing Peripheral role 
    """
    rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=random_address,
                                    pri_adv_phy=1, sec_adv_phy=3, random_address=random_address, 
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163844(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy 
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x2 and data length 191
    Device roles       : DUT is performing Peripheral role 
    """
    rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x2)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=2, ble_dut_address=random_address,
                                    pri_adv_phy=1, sec_adv_phy=3, random_address=random_address, 
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163845(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy 
    Test case          : This test case will verify 2 adv sets with adv type 0x1 and 0x4 and data length 200
    Device roles       : DUT is performing Peripheral role 
    """
    rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=4, ble_dut_address=random_address,
                                    pri_adv_phy=1, sec_adv_phy=3, random_address=random_address, 
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=200, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163846(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy 
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1 and data length 200, 0
    Device roles       : DUT is performing Peripheral role 
    """
    rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=random_address,
                                    pri_adv_phy=1, sec_adv_phy=3, random_address=random_address, 
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163847(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy 
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x5 and data length 474, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=3, random_address=random_address, 
                                    min_interval=32, max_interval=32, data_len=474, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
#Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M

def test_verify_AE_2ADV_sets_C163848(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1 and data length 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, random_address_s2=random_address, 
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163849(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M
    Test case          : This test case will verify 2 adv sets with adv type 0x1 and 0x0 and data length 0, 191
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=0, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, random_address_s2=random_address, 
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163850(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x5 and data length 191, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, random_address_s2=random_address, 
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163851(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x2 and data length 191, 191
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x2)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=2, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, random_address_s2=random_address, 
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163852(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M
    Test case          : This test case will verify 2 adv sets with adv type 0x1 and 0x4 and data length 200, 200
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=4, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, random_address_s2=random_address, 
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=200, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163853(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1 and data length 200, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, random_address_s2=random_address, 
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163854(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x2 and data length 474, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, random_address_s2=random_address, 
                                    min_interval=32, max_interval=32, data_len=474, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

#Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M

def test_verify_AE_2ADV_sets_C163855(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1 and data length 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=2, random_address_s2=random_address, 
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163856(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M
    Test case          : This test case will verify 2 adv sets with adv type 0x1 and 0x0 and data length 0, 191
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=0, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=2, random_address_s2=random_address, 
                                    min_interval=32, max_interval=32, data_len=0, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163857(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x5 and data length 191, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=2, random_address_s2=random_address, 
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163858(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x2 and data length 191, 191
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x2)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=2, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=2, random_address_s2=random_address, 
                                    min_interval=32, max_interval=32, data_len=191, data_len_s2=191, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163859(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M
    Test case          : This test case will verify 2 adv sets with adv type 0x1 and 0x4 and data length 200, 200
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, adv_type_s2=4, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=2, random_address_s2=random_address, 
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=200, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

def test_verify_AE_2ADV_sets_C163860(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x1 and data length 200, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=1, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=2, random_address_s2=random_address, 
                                    min_interval=32, max_interval=32, data_len=200, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
def test_verify_AE_2ADV_sets_C163861(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x2 and data length 474, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=2, random_address_s2=random_address, 
                                    min_interval=32, max_interval=32, data_len=474, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
# Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =LE COded and Sec Phy LE COded 
def test_verify_AE_2ADV_sets_C163862(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M
    Test case          : This test case will verify 2 adv sets with adv type 0x0 and 0x2 and data length 474, 0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    packet_filter2 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_type_s2=5, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=3, sec_adv_phy=3, random_address_s2=random_address, 
                                    min_interval=32, max_interval=32, data_len=474, data_len_s2=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, adv_handle_s2=1, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
# #Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected.
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163869(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 1m, addr_type public, adv_min 20ms, adv_max 28ms
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, max_ae_events=20, adv_async_required=True, test_case_id="C163869",
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163870(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 2m, addr_type public, adv_min 20ms, adv_max 28ms
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163870",
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163871(ble_dut, rs_helper_ble):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy LE coded, sec phy Le Coded, addr_type public, adv_min 20ms, adv_max 28ms
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=3, sec_adv_phy=3, max_ae_events=20, adv_async_required=True,
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5)
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163872(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 1m, addr_type random_address, adv_min 20ms, adv_max 28ms
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163872",
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163873(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 2m, addr_type random_address, adv_min 20ms, adv_max 28ms
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163873",
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163874(ble_dut, rs_helper_ble):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy LE coded, sec phy Le coded, addr_type random_address, adv_min 20ms, adv_max 28ms
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=3, sec_adv_phy=3, max_ae_events=20, adv_async_required=True,
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address)
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163875(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 1m, addr_type public, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, max_ae_events=20, adv_async_required=True, test_case_id="C163875",
                                    min_interval=80, max_interval=160, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163876(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 2m, addr_type public, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163876",
                                    min_interval=80, max_interval=160, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163877(ble_dut, rs_helper_ble):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy LE coded, sec phy Le Coded, addr_type public, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=3, sec_adv_phy=3, max_ae_events=20, adv_async_required=True,
                                    min_interval=80, max_interval=160, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5)
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163878(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 1m, addr_type random_address, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163878",
                                    min_interval=80, max_interval=160, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163879(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 2m, addr_type random_address, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163879",
                                    min_interval=32, max_interval=80, data_len=160, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163880(ble_dut, rs_helper_ble):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy LE coded, sec phy Le coded, addr_type random_address, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, 
                                    pri_adv_phy=3, sec_adv_phy=3, max_ae_events=20, adv_async_required=True,
                                    min_interval=32, max_interval=80, data_len=160, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address)
    
#Enable - Disable Ext Adv in Loop ,adv type = non conn non scan undirected. 
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163881(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop ,adv type = non conn non scan undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 1m, addr_type public, adv_min ,0x20 adv_max 0x28
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, max_ae_events=20, adv_async_required=True, test_case_id="C163881",
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163882(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 2m, addr_type public, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163882",
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163883(ble_dut, rs_helper_ble):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy LE coded, sec phy Le Coded, addr_type public, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=3, sec_adv_phy=3, max_ae_events=20, adv_async_required=True,
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5)
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163884(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 1m, addr_type random_address, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163884",
                                    min_interval=32, max_interval=40, data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163885(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy 1m, sec phy 2m, addr_type random_address, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, max_ae_events=20, adv_async_required=True, test_case_id="C163885",
                                    min_interval=32, max_interval=32, data_len=40, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163886(ble_dut, rs_helper_ble):
    """
    Test case category : Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected
    Test case          : This test case will verify continues enable disable EXT AE, pry phy LE coded, sec phy Le coded, addr_type random_address, adv_min 0x50, adv_max 0xA0
    Device roles       : DUT is performing Peripheral role 
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=3, sec_adv_phy=3, max_ae_events=20, adv_async_required=True,
                                    min_interval=32, max_interval=80, data_len=160, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, loop_count=5, random_address=random_address)
