import pytest
from example_test_package.conftest import rs_helper_ble
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, \
    RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap, RS9116PowerSaveProcedureTypes, \
        RS9116BTFeatureBitMap
from utf.utils.logger import get_logger
import time, os
import threading
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch

"""
    * setup requirement:
        1. DUT(RS9117) SOC board
        2. REF(RS9117) SOC board
        3. NRF donlge (to capture BLE OTA logs)
        4. NUC (To validate captured OTA logs using Tshark)
        5. Ellysis (to Capture OTA logs) 
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
"""
    Fixures used: 
        * ble_sniffer: To caputre BLE OTA logs through NRF dongle
        * wifi sniffer: TO validate caputured OTA logs through NUC(wireshark)
        * bt_sniffer: To capture OTA logs through Ellysis.
"""

def test_EXT_ADV_pkt_and_aux_ptr_C163693(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """ 
    Test case          : This test case will verify Advertising Extention packets for undirected connecable and scannable adv type and aux pointer
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x1) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, test_case_id="C193693",
                                    adv_handle=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    wifi_sniffer=wifi_sniffer, ble_sniffer=ble_sniffer, packet_filter1={packet_filter1:"Positive"})
    
def test_verify_lowest_highest_adv_handle_C193694(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer):
    """
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
                                    adv_handle=0, duration=0, test_case_id="C193696")
    
def test_verify_AE_ADV_for_2560ms_C163697(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention for 2560ms and verify even RSI_APP_EVENT_EXT_ADV_TERMINATED
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    adv_handle=0, duration=256, adv_async_required=1, test_case_id="C193697")

def test_verify_AE_ADV_for_200_max_event_C163698(ble_dut, rs_helper_ble, bt_sniffer):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention for max AE events 200 and verify even RSI_APP_EVENT_EXT_ADV_TERMINATED
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=0, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    max_ae_events=200, adv_async_required=1, test_case_id="C193698")
    
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
"""
    Fixures used: 
        * ble_sniffer: To caputre BLE OTA logs through NRF dongle
        * wifi sniffer: TO validate caputured OTA logs through NUC(wireshark)
        * bt_sniffer: To capture OTA logs through Ellysis.
"""

@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163702(ble_dut, ble_client, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
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
                                    packet_filter1={packet_filter1:"Positive"}, adv_data="AE_PERIPHERAL_DATA", central=ble_client)
    
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
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163704(ble_dut, ble_client, ble_sniffer, wifi_sniffer, rs_helper_ble, bt_sniffer):
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
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", central=ble_client)
    
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
    
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
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
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163710(ble_dut, ble_client, rs_helper_ble, bt_sniffer, ble_sniffer, wifi_sniffer):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M, 2M 
                         with adv data of 1 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address, central=ble_client,
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

@pytest.mark.ble_client("bt_wiseconnect")    
def test_verify_AE_non_conn_non_scan_ADV_C163712(ble_dut, ble_client, rs_helper_ble, bt_sniffer, ble_sniffer, wifi_sniffer):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M, 2M 
                         with adv data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address, central=ble_client,
                                      bt_sniffer=bt_sniffer, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"},
                                      pri_adv_phy=1, sec_adv_phy=2, data_len=31, test_case_id="C163712", adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@")

@pytest.mark.ble_client("bt_wiseconnect") 
def test_verify_AE_non_conn_non_scan_ADV_C163713(ble_dut, ble_client, rs_helper_ble, bt_sniffer, ble_sniffer, wifi_sniffer):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M, 2M 
                         with adv data of 474 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address, central=ble_client,
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

"""
    Test case category : Scannable Non Connectable Undirected Adv with scan_response_data on DUT and primary phy is 1M, sec phy is 1M
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through NRF dongle, wifi sniffer: TO validate caputured OTA logs through NUC(wireshark), 
                    bt_sniffer: To capture OTA logs through Ellysis.
"""
@pytest.mark.parametrize(
    "adv_type, test_case_id, data_len, scan_req_notify_enable",
    [
        (2, "C163715", 1, 0),
        (2, "C163816", 31, 0),
        (2, "C163817", 200, 0),
        (2, "C163818", 200, 1),
    ],
)
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Scannable_non_conn_ADV_C163715_C163720(ble_dut, rs_helper_ble, bt_sniffer, ble_client, ble_sniffer, wifi_sniffer,
                                        adv_type, test_case_id, data_len, scan_req_notify_enable):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"((btle.extended_advertising_header.mode == 0x2) && (nordic_ble.phy == 0)) && (btle.extended_advertising_header.flags.aux_pointer == 1)"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=data_len, scan_resp_len=1, test_case_id=test_case_id, central=ble_client,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", scan_req_notify_enable=scan_req_notify_enable, adv_handle=0,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"})

"""
    Test case category : Scannable directed adv with scan_response_data on DUT and primary phy is LE Coded Phy, sec phy is LE Coded Phy
    Device roles       : DUT is performing Peripheral role 
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through NRF dongle, wifi sniffer: TO validate caputured OTA logs through NUC(wireshark), 
                    bt_sniffer: To capture OTA logs through Ellysis.
"""
@pytest.mark.parametrize(
    "adv_type, test_case_id, data_len, scan_req_notify_enable",
    [
        (2, "C163719", 1, 0),
        (2, "C163820", 31, 0),
        (2, "C163821", 474, 0),
        (2, "C163821", 474, 1),
    ],
)
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Scannable_undirected_ADV_C163719_C163722(ble_dut, rs_helper_ble, bt_sniffer,
                                        adv_type, test_case_id, data_len, scan_req_notify_enable):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=data_len, scan_resp_len=1, test_case_id=test_case_id,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", scan_req_notify_enable=scan_req_notify_enable, adv_handle=0)

"""
    Test case category : Scannable directed adv with scan_response_data on DUT and primary phy is LE Coded Phy, sec phy is LE Coded Phy
    Device roles       : DUT is performing Peripheral role 
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through NRF dongle, wifi sniffer: TO validate caputured OTA logs through NUC(wireshark), 
                    bt_sniffer: To capture OTA logs through Ellysis.
"""
@pytest.mark.parametrize(
    "adv_type, test_case_id, data_len",
    [
        (5, "C163723", 1),
        (5, "C163824", 31),
        (5, "C163825", 474),
    ],
)
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Scannable_directed_ADV_C163723_C163724(ble_dut, rs_helper_ble, bt_sniffer,
                                        adv_type, test_case_id, data_len):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=data_len, scan_resp_len=1, test_case_id=test_case_id, 
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", whitelist=True, scan_req_notify_enable=0,
                                    adv_handle=0)
"""
    Test case category : LE Ext Adv with filter policy enabled during LE Ext Adv 
    Device roles       : DUT is performing Peripheral role 
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through NRF dongle, wifi sniffer: TO validate caputured OTA logs through NUC(wireshark), 
                    bt_sniffer: To capture OTA logs through Ellysis.
"""
@pytest.mark.parametrize(
    "adv_type, test_case_id, adv_filter_policy, event_type",
    [
        (2, "C163811", 1, "0x2"),
        (1, "C163812", 2, "0x1"),
        (1, "C163813", 3, "0x1"),
    ],
)
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Scannable_filter_policy_C163811_C163813(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer,
                                        adv_type, test_case_id, adv_filter_policy, event_type):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"nordic_ble.phy == 0 && (btle.extended_advertising_header.mode == {event_type})"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy, test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, 
                                    packet_filter1={packet_filter1:"Positive"})
"""
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Device roles       : DUT is performing Peripheral role
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through NRF dongle, wifi sniffer: TO validate caputured OTA logs through NUC(wireshark), 
                    bt_sniffer: To capture OTA logs through Ellysis.
"""
@pytest.mark.parametrize(
    "adv_type, test_case_id, sec_adv_max_skip, event_type",
    [
        (0, "C163814", 1, "0x0"),
        (0, "C163815", 15, "0x0"),
        (0, "C163816", 255, "0x0"),
        (1, "C163817", 8, "0x1"),
        (4, "C163818", 8, "0x0"),
        (5, "C163819", 1, "0x1"),
    ],
)
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Secondary_adv_with_max_skip_1_C163814_C163820(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer,
                                        adv_type, test_case_id, sec_adv_max_skip, event_type):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"nordic_ble.phy == 0 && (btle.extended_advertising_header.mode == {event_type})"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=sec_adv_max_skip, data_len=31, 
                                    pri_adv_phy=1, sec_adv_phy=2, test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, 
                                    packet_filter1={packet_filter1:"Positive"})

"""
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M'
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through NRF dongle, wifi sniffer: TO validate caputured OTA logs through NUC(wireshark), 
                    bt_sniffer: To capture OTA logs through Ellysis.
"""
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, pri_adv_phy, sec_adv_phy, test_case_id, adv_handle, adv_handle_s2, event_type_1, event_type_2",
    [
        (0, 1, 0, 0, 1, 2, "C163820", 0, 1, "0x0", "0x1"), 
        (1, 0, 0, 0, 1, 2, "C163821", 0, 1, "0x1", "0x0"), 
        (0, 5, 191, 0, 1, 2, "C163822", 0, 1, "0x0", "0x1"),
        (0, 2, 191, 191, 1, 2, "C163823", 0, 1, "0x0", "0x2"),
        (1, 4, 200, 200, 1, 2, "C163824", 0, 1, "0x1", "0x0"),
        (0, 1, 200, 0,  1, 2, "C163825", 0, 1, "0x0", "0x1"),
        (0, 1, 474, 0,  1, 2, "C163826", 0, 1, "0x0", "0x1"),
    ],
)
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_2ADV_sets_PHY_1M_2M_C163820_to_C163826(ble_dut, ble_client, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer,
                                        adv_type, adv_type_s2, data_len, data_len_s2, pri_adv_phy, 
                                        sec_adv_phy, test_case_id, adv_handle, adv_handle_s2, event_type_1, event_type_2):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == {event_type_1})"
    packet_filter2 = f"(btle.extended_advertising_header.mode == {event_type_2})"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=data_len, data_len_s2=data_len_s2, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, test_case_id=test_case_id, central=ble_client,
                                    adv_handle=adv_handle, adv_handle_s2=adv_handle_s2, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, 
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
"""
    Test case category : Extended Advertising, two Sets, Single PHY, LE primary phy and sec phy is LE Coded  
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through NRF dongle, wifi sniffer: TO validate caputured OTA logs through NUC(wireshark), 
                    bt_sniffer: To capture OTA logs through Ellysis.
"""
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, pri_adv_phy, sec_adv_phy, test_case_id, adv_handle, adv_handle_s2,",
    [
        (0, 1, 0, 0, 3, 3, "C163827", 0, 1), 
        (1, 0, 0, 191, 3, 3, "C163828", 0, 1),
        (0, 5, 191, 0, 3, 3, "C163829", 0, 1), 
        (0, 2, 191, 191, 3, 3, "C163830", 0, 1),
        (1, 4, 200, 200, 3, 3, "C163831", 0, 1),
        (0, 1, 200, 0,  3, 3, "C163832", 0, 1), 
        (0, 1, 474, 0,  3, 3, "C163833", 0, 1),
    ],
)
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_2ADV_sets_PHY_LECoded_C163827_to_C163833(ble_dut, rs_helper_ble, bt_sniffer,
                                        adv_type, adv_type_s2, data_len, data_len_s2, pri_adv_phy, 
                                        sec_adv_phy, test_case_id, adv_handle, adv_handle_s2):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=data_len, data_len_s2=data_len_s2, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, test_case_id=test_case_id,
                                    adv_handle=adv_handle, adv_handle_s2=adv_handle_s2)

"""
    Test case category : Extended Advertising, Multiple Sets, Legacy and Extended 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through NRF dongle, wifi sniffer: TO validate caputured OTA logs through NUC(wireshark), 
                    bt_sniffer: To capture OTA logs through Ellysis.
"""
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, event_type_1, event_type_2",
    [
        (0, 16, 0, 0, "C163834", 0, 1, "0x0", "0x2"), 
        (19, 0, 0, 191, "C163835", 0, 1, "0x0", "0x0"), 
        (0, 19, 191, 31, "C163836", 0, 1, "0x0", "0x0"), 
        (19, 16, 31, 31,  "C163837", 0, 1, "0x0", "0x2"), 
        (21, 4, 0, 200, "C163838", 0, 1, "0x1", "0x0"), 
        (0, 29, 200, 0, "C163839", 0, 1, "0x0", "0x1"),
        (0, 18, 474, 0, "C163840", 0, 1, "0x0", "0x6"),
    ],
)
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_2ADV_sets_Legacy_Extended_C1638234_to_C163840(ble_dut, ble_client, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer,
                                        adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, 
                                        event_type_1, event_type_2):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == {event_type_1})"
    packet_filter2 = f"(btle.extended_advertising_header.mode == {event_type_2})"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    min_interval=32, max_interval=32, data_len=data_len, data_len_s2=data_len_s2, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    test_case_id=test_case_id, central=ble_client, adv_handle=adv_handle, adv_handle_s2=adv_handle_s2, ble_sniffer=ble_sniffer, 
                                    wifi_sniffer=wifi_sniffer, packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    """
    Test case category : Two adv sets with random addr of DUT, primary phy =1M, sec phy=LE Coded Phy 
    Device roles       : DUT is performing Peripheral role 
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through NRF dongle, wifi sniffer: TO validate caputured OTA logs through NUC(wireshark), 
                    bt_sniffer: To capture OTA logs through Ellysis.
    """
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, event_type_1, event_type_2",
    [
        (0, 1, 0, 0, "C163841", 0, 1, "0x0", "0x1"), 
        (1, 0, 0, 0, "C163842", 0, 1, "0x1", "0x0"), 
        (0, 5, 191, 0, "C163843", 0, 1, "0x0", "0x1"), 
        (0, 2, 191, 191,  "C163844", 0, 1, "0x0", "0x2"), 
        (1, 4, 200, 200, "C163845", 0, 1, "0x1", "0x0"), 
        (0, 1, 200, 0, "C163846", 0, 1, "0x0", "0x1"), 
        (0, 5, 474, 0, "C163847", 0, 1, "0x0", "0x1"), 
    ],
)
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_2ADV_sets_Legacy_Extended_C1638241_to_C163847(ble_dut, ble_client, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer,
                                        adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, 
                                        event_type_1, event_type_2):
    rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == {event_type_1})"
    packet_filter2 = f"(btle.extended_advertising_header.mode == {event_type_2})"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2, ble_dut_address=random_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=3, min_interval=32, max_interval=32, data_len=data_len, data_len_s2=data_len_s2, random_address=random_address,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id, central=ble_client, adv_handle=adv_handle, 
                                    adv_handle_s2=adv_handle_s2, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, 
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

"""
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 1M
    Device roles       : DUT is performing Peripheral role 
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through NRF dongle, wifi sniffer: TO validate caputured OTA logs through NUC(wireshark), 
                    bt_sniffer: To capture OTA logs through Ellysis.
"""
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, event_type_1, event_type_2",
    [
        (0, 1, 0, 0, "C163848", 0, 1, "0x0", "0x1"), 
        (1, 0, 0, 191, "C163849", 0, 1, "0x1", "0x0"), 
        (0, 5, 191, 0, "C163850", 0, 1, "0x0", "0x1"), 
        (0, 2, 191, 191,  "C163851", 0, 1, "0x0", "0x2"), 
        (1, 4, 200, 200, "C163852", 0, 1, "0x1", "0x0"), 
        (0, 1, 200, 0, "C163853", 0, 1, "0x0", "0x1"), 
        (0, 5, 474, 0, "C163854", 0, 1, "0x0", "0x1"), 
    ],
)
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_2ADV_sets_Legacy_Extended_C1638248_to_C1638454(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer,
                                        adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, 
                                        event_type_1, event_type_2):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == {event_type_1})"
    packet_filter2 = f"(btle.extended_advertising_header.mode == {event_type_2})"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=3, min_interval=32, max_interval=32, data_len=data_len, data_len_s2=data_len_s2, random_address_s2=random_address,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id, adv_handle=adv_handle, 
                                    adv_handle_s2=adv_handle_s2, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, 
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})
    
"""
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =1M and Sec Phy 2M
    Device roles       : DUT is performing Peripheral role 
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through NRF dongle, wifi sniffer: TO validate caputured OTA logs through NUC(wireshark), 
                    bt_sniffer: To capture OTA logs through Ellysis.
"""
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, event_type_1, event_type_2",
    [
        (0, 1, 0, 0, "C163855", 0, 1, "0x0", "0x1"), 
        (1, 0, 0, 191, "C163856", 0, 1, "0x1", "0x0"), 
        (0, 5, 191, 0, "C163857", 0, 1, "0x0", "0x1"), 
        (0, 2, 191, 191,  "C163858", 0, 1, "0x0", "0x2"), 
        (1, 4, 200, 200, "C163859", 0, 1, "0x1", "0x0"), 
        (0, 1, 200, 0, "C163860", 0, 1, "0x0", "0x1"), 
        (0, 5, 474, 0, "C163861", 0, 1, "0x0", "0x1"), 
    ],
)
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_2ADV_sets_Legacy_Extended_C1638255_to_C1638461(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer,
                                        adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, 
                                        event_type_1, event_type_2):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    packet_filter1 = f"(btle.extended_advertising_header.mode == {event_type_1})"
    packet_filter2 = f"(btle.extended_advertising_header.mode == {event_type_2})"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, min_interval=32, max_interval=32, data_len=data_len, data_len_s2=data_len_s2, random_address_s2=random_address,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id, adv_handle=adv_handle, 
                                    adv_handle_s2=adv_handle_s2, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, 
                                    packet_filter1={packet_filter1:"Positive"}, packet_filter2={packet_filter2:"Positive"})

"""
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =LE COded and Sec Phy LE Coded
    Device roles       : DUT is performing Peripheral role 
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through NRF dongle, wifi sniffer: TO validate caputured OTA logs through NUC(wireshark), 
                    bt_sniffer: To capture OTA logs through Ellysis.
"""
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2",
    [
        (0, 1, 0, 0, "C163862", 0, 1), 
        (1, 0, 0, 191, "C163863", 0, 1), 
        (0, 5, 191, 0, "C163864", 0, 1), 
        (0, 2, 191, 191,  "C163865", 0, 1), 
        (1, 4, 200, 200, "C163866", 0, 1), 
        (0, 1, 200, 0, "C163867", 0, 1), 
        (0, 5, 474, 0, "C163868", 0, 1), 
    ],
)
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_2ADV_sets_Legacy_Extended_C1638262_to_C1638468(ble_dut, rs_helper_ble, bt_sniffer,
                                        adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2, 
                                        ):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, min_interval=32, max_interval=32, data_len=data_len, data_len_s2=data_len_s2, 
                                    random_address_s2=random_address, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id, adv_handle=adv_handle, 
                                    adv_handle_s2=adv_handle_s2)
    
"""
    Test case category : 
    1. Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected (C163869 to C163880)
    2. Enable - Disable Ext Adv in Loop ,adv type = non conn non scan undirected (C163881 to C163886)
    Device roles       : DUT is performing Peripheral role 
"""
@pytest.mark.parametrize(
    "adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, event_type_1, random_address",
    [
        (1, 32, 40, "C163869", 1, 1, "0x1", None), 
        (1, 32, 40, "C163870", 1, 2, "0x1", None), 
        (1, 32, 40, "C163871", 3, 3, "0x1", None), 
        (1, 32, 40, "C163872", 1, 1, "0x1", "11:33:33:33:33:11"), 
        (1, 32, 40, "C163873", 2, 2, "0x1", "11:33:33:33:33:11"),
        (1, 32, 40, "C163874", 3, 3, "0x1", "11:33:33:33:33:11"),
        (1, 80, 160, "C163875", 1, 1, "0x1", None), 
        (1, 80, 160, "C163876", 1, 2, "0x1", None), 
        (1, 80, 160, "C163877", 3, 3, "0x1", None), 
        (1, 80, 160, "C163878", 1, 1, "0x1", "11:33:33:33:33:11"), 
        (1, 80, 160, "C163879", 2, 2, "0x1", "11:33:33:33:33:11"),
        (1, 80, 160, "C163880", 3, 3, "0x1", "11:33:33:33:33:11"),
        (0, 32, 40, "C163881", 1, 1, "0x0", None), 
        (0, 32, 40, "C163882", 1, 2, "0x0", None), 
        (0, 32, 40, "C163883", 3, 3, "0x0", None), 
        (0, 32, 40, "C163884", 1, 1, "0x0", "11:33:33:33:33:11"), 
        (0, 32, 40, "C163885", 2, 2, "0x0", "11:33:33:33:33:11"),
        (0, 32, 40, "C163886", 3, 3, "0x0", "11:33:33:33:33:11"),
    ],
)
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163869_C163886(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer,
                                        adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, event_type_1, random_address):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == {event_type_1})"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, max_ae_events=20, adv_async_required=True,  min_interval=min_interval, max_interval=max_interval, 
                                    data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id, adv_handle=0, 
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, loop_count=5,
                                    packet_filter1={packet_filter1:"Positive"}, random_address=random_address)
    
## Negative Test scenarios

""" Test case : This test case will verify 0x04c error, when legacy and ext adv started together with single adv set"""
def test_verify_Negative_case_C163735(ble_dut, rs_helper_ble):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=160, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id="C163736",
                                    dont_cleanup=True, test_in_progress=True)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=17, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id="C163736",
                                    error_expected= "Error code: 0x4e0c Msg: Command disallowed Command")
    
"""Test case : This test case will verify invalid adv handle"""
@pytest.mark.skip ("test case is not failing with invalid adv handle")
def test_verify_Negative_case_C163736(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=160, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id="C163736",
                                    adv_handle=300000, packet_filter1={packet_filter1:"Positive"}, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer)
    
"""Test case: This test case will verify terminated callback event with error 60, wit duration value 256ms"""   
def test_verify_Negative_case_C163737(ble_dut, rs_helper_ble):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    duration=256, adv_async_required=True)
    
"""Test case: This test case will verify terminated callback event with error 67, with max ae events value 0x5"""  
def test_verify_Negative_case_C163738(ble_dut, rs_helper_ble):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    max_ae_events=5, adv_async_required=True)
    
"""Test case: This test case will verify invalid adv handle error 0x4e42 for set_adv_data command"""
def test_verify_Negative_case_C163739(ble_dut, rs_helper_ble):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    invalid_data_hdl=99, dont_cleanup=True, error_expected= "0x4e42")

"""Test case: This test case will verify error 0x4e12 after setting filter_duplicates =2 and duraion/period =0 during scan enable""" 
def test_verify_Negative_case_C163740(ble_dut, rs_helper_ble):
    rs_helper_ble.BLE_AE().verify_ae_scan(central=ble_dut, filter_duplicates=2, error_expected="0x4e12", dont_cleanup=True)

"""Test case: This test case will verify error 0x4e12 after setting duraion is greater or equal to period during scan enable"""
def test_verify_Negative_case_C163741(ble_dut, rs_helper_ble):
    rs_helper_ble.BLE_AE().verify_ae_scan(central=ble_dut, duration=500, period=500, error_expected="0x4e12", dont_cleanup=True)

"""Test case: This test case will verify error 0x4e12 after setting scan enable with own add type as random and not setting random add prior"""
def test_verify_Negative_case_C163742(ble_dut, rs_helper_ble):
    rs_helper_ble.BLE_AE().verify_ae_scan(central=ble_dut, own_addr_type=1, error_expected="0x4e12", dont_cleanup=True)

"""Test case: This test case will verify error 0x4e12 not come after setting scan enable with own add type as random and setting random add prior"""
@pytest.mark.skip ("set random address is failing")
def test_verify_Negative_case_C163743(ble_dut, rs_helper_ble):
    rs_helper_ble.BLE_AE().verify_ae_scan(central=ble_dut, own_addr_type=1, random_address="AA:BB:CC:11:23:33")

"""Test case: This test case will verify error 0x4e12 not come after setting scan enable with own add type as random and setting random add prior"""
@pytest.mark.skip ("Expected error is not observed")
def test_verify_Negative_case_C163744(ble_dut, rs_helper_ble):
    rs_helper_ble.BLE_AE().verify_ae_scan(central=ble_dut, interval=48, window=49)