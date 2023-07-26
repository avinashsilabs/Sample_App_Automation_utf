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
    pytest.mark.dut("rs9116_sapi"),
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

@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_legacy_adv_connectable_dir_C163687(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE LEGACY ADVERTISING
    Test case          : This test case will verify Legacy advertisement with ADV type Connectable Directed,
                         and low duty cycle
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=21,
                                    ble_client=ble_client, print_all_adv_devices=0)
    

@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_legacy_adv_connectable_dir_high_duty_cycle_C163688(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE LEGACY ADVERTISING
    Test case          : This test case will verify Legacy advertisement with ADV type Connectable Directed,
                         and high duty cycle
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=29,
                                    ble_client=ble_client, print_all_adv_devices=0)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_legacy_adv_scanable_undir_31byte_C163689(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE LEGACY ADVERTISING
    Test case          : This test case will verify Legacy advertisement with ADV type Scannable Undirected,
                         and ADV data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=18, data_len=31, adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@",
                                    ble_client=ble_client, print_all_adv_devices=0)

@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_legacy_adv_connectable_scanable_undir_1byte_c163690(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE LEGACY ADVERTISING
    Test case          : This test case will verify Legacy advertisement with ADV type Connectable Scannable Undirected,
                         and ADV data of 1 byte
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=19, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    ble_client=ble_client, print_all_adv_devices=0)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_legacy_adv_connectable_scanable_undir_0byte_c163691(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE LEGACY ADVERTISING
    Test case          : This test case will verify Legacy advertisement with ADV type Connectable Scannable Undirected,
                         and ADV data of 0 byte
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=19, data_len=0, 
                                      adv_data="AE_PERIPHERAL_DATA_0",
                                      ble_client=ble_client, print_all_adv_devices=0)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_legacy_adv_connectable_scanable_undir_31byte_c163692(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE LEGACY ADVERTISING
    Test case          : This test case will verify Legacy advertisement with ADV type Connectable Scannable Undirected,
                         and ADV data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=19, data_len=31, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6",
                                    ble_client=ble_client, print_all_adv_devices=0)

@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_lowest_highest_adv_handle_C193694(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention with lowest and highest adv_handle
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    logger().info(f"\n\n ** Verifying AE with lowest handle ie. 0x00 **\n\n")
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, print_all_adv_devices=0, adv_handle=0)
    
    logger().info(f"\n\n ** Verifying AE with highest handle ie. 0xef **\n\n")
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, print_all_adv_devices=0, adv_handle=239)
    
#  #######################  LE Ext Adv - BLE Advertising Extension  ####################

@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_ADV_for_infinite_time_C163696(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention for infinite time with duration paramerter 0x0000
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, print_all_adv_devices=0, adv_handle=0,
                                    adv_time=60, duration=0)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_ADV_for_2560ms_C163697(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention for 2560ms and verify even RSI_APP_EVENT_EXT_ADV_TERMINATED
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, print_all_adv_devices=0, adv_handle=0,
                                    duration=256, adv_async_required=1, no_scan=1)

@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_ADV_for_200_max_event_C163698(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention for max AE events 200 and verify even RSI_APP_EVENT_EXT_ADV_TERMINATED
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, print_all_adv_devices=1, adv_handle=0,
                                    max_ae_events=200, adv_async_required=1, no_scan=1)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_ADV_with_randomm_address_C163701(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention with random address
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, own_address_type=1, print_all_adv_devices=0,
                                    random_address="11:33:33:33:33:11")
    
#     #######################  LE Ext Adv - Non connectable Non Scannable undirected adv ####################
    
@pytest.mark.skip #getting data len 0 even after configuring it with 1 
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163702(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M 
                         with adb data of 1bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, pri_adv_phy=1, sec_adv_phy=1, data_len=1, 
                                    adv_data="AE_PERIPHERAL_DATA")
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163703(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M 
                         with adv data of 0 bytes and max ae events: 0x32 ie.50
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, pri_adv_phy=1, sec_adv_phy=1, data_len=0, 
                                    adv_data="AE_PERIPHERAL_DATA", max_ae_events=50, adv_async_required=1, no_scan=1)
    
pytest.mark.skip ("#getting data len 0 even after configuring it with 31") 
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163704(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M 
                         with adv data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0, adv_handle=1,
                                    ble_client=ble_client, print_all_adv_devices=0, data_len=31, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", duration=0)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163705(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M 
                         with adv data length of 200 bytes and Adv duration is 5 sec: 0x1F4
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, pri_adv_phy=1, sec_adv_phy=1, data_len=200, 
                                    adv_data="AE_PERIPHERAL_DATA", duration=500, adv_async_required=1, no_scan=1)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163707(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY LE Coded 
                         with adv data of 0 bytes and max ae events: 0x32 ie.50
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, pri_adv_phy=3, sec_adv_phy=3, data_len=0, 
                                    adv_data="AE_PERIPHERAL_DATA", max_ae_events=50, adv_async_required=1, no_scan=1)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163709(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY LE Coded
                         with adv data length of 200 bytes and Adv duration is 5 sec: 0x1F4
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, pri_adv_phy=3, sec_adv_phy=3, data_len=200, 
                                    adv_data="AE_PERIPHERAL_DATA", duration=500, adv_async_required=1, no_scan=1)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163711(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri PHY is 1M and sec PHY is 2M 
                         with adv data of 0 bytes and max ae events: 0x32 ie.50
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, pri_adv_phy=1, sec_adv_phy=2, data_len=0, 
                                    adv_data="AE_PERIPHERAL_DATA", max_ae_events=50, adv_async_required=1, no_scan=1)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163714(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri PHY is 1M and sec PHY is 2M
                         with adv data length of 200 bytes and Adv duration is 5 sec: 0x1F4
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, pri_adv_phy=1, sec_adv_phy=2, data_len=200, 
                                    adv_data="AE_PERIPHERAL_DATA", duration=500, adv_async_required=1, no_scan=1)
    
    
# #Scannable Non Connectable Undirected Adv with scan_response_data on DUT and primary phy is 1M, sec phy is 1M#

@pytest.mark.skip ("#Advertising is not getting stopped fw:45")
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Scannable_non_conn_ADV_C163715(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable Non Connectable Undirected Adv 
    Test case          : This test case will verify Scannable Non Connectable Undirected Adv with pri PHY is 1M and sec PHY is 1M
                         with adv data of 31 bytes and scan_data is 1 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=2, ble_client=ble_client,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, scan_resp_len=1, 
                                    adv_data="AE_PERIPHERAL_DATA_DATA", scan_req_notify_enable=0,
                                    print_all_adv_devices=0)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Scannable_non_conn_ADV_C163716(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable Non Connectable Undirected Adv 
    Test case          : This test case will verify Scannable Non Connectable Undirected Adv with pri PHY is 1M and sec PHY is 1M
                         with adv data of 31 bytes and scan_data is 31 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=2, ble_client=ble_client,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", scan_req_notify_enable=0,
                                    print_all_adv_devices=0)

@pytest.mark.skip ("#Advertising is not getting stopped fw:45 ")   
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Scannable_non_conn_ADV_C163717(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable Non Connectable Undirected Adv 
    Test case          : This test case will verify Scannable Non Connectable Undirected Adv with pri PHY is 1M and sec PHY is 1M
                         with adv data of 200 bytes and scan_data is 200 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=2, ble_client=ble_client,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=200, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@",
                                    scan_req_notify_enable=0, print_all_adv_devices=0)
    
@pytest.mark.skip ("#scan_resp event is not receiving") 
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Scannable_non_conn_ADV_C163718(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable Non Connectable Undirected Adv 
    Test case          : This test case will verify Scannable Non Connectable Undirected Adv with pri PHY is 1M and sec PHY is 1M
                         with adv data of 200 bytes and scan_data is 200 byte,  scan_req_notify_enable = 1
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=2, ble_client=ble_client,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=200, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@",
                                    scan_req_notify_enable=1, print_all_adv_devices=0)
    
#Scannable undirected adv with scan_response_data on DUT and primary phy is LE Coded Phy, sec phy is LE Coded Phy.

@pytest.mark.skip ("#facing issue with LE coded")
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Scannable_undirected_ADV_C163719(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Scannable undirected adv 
    Test case          : This test case will verify Scannable undirected Adv with pri PHY and sec PHY is LE Coded
                         with adv data of 31 bytes and scan_data is 1 byte,  scan_req_notify_enable = 0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=2, ble_client=ble_client,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=31, scan_resp_len = 1, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@",
                                    scan_req_notify_enable=0, print_all_adv_devices=0)

@pytest.mark.skip ("#facing issue with LE coded adv report not received ")  
@pytest.mark.ble_client("bt_wiseconnect")
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

@pytest.mark.skip ("#le coded issue adv report not received")
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
    
# #LE Ext Adv with filter policy enabled during LE Ext Adv
@pytest.mark.skip ("#advertising is not stopping ")
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Scannable_filter_policy_C163811(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv with filter policy enabled during LE Ext Adv 
    Test case          : This test case will verify Scannable Adv with filter policy 1
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=2, ble_client=ble_client,
                                    data_len=31, adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", whitelist=1, adv_filter_policy=1,
                                    print_all_adv_devices=0)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Scannable_filter_policy_C163812(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv with filter policy enabled during LE Ext Adv 
    Test case          : This test case will verify Connectable Adv with filter policy 2
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=1, ble_client=ble_client,
                                    data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", whitelist=1, adv_filter_policy=2,
                                    scan_req_notify_enable=0, print_all_adv_devices=0)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Scannable_filter_policy_C163813(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv with filter policy enabled during LE Ext Adv 
    Test case          : This test case will verify Scannable Adv with filter policy 3 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=1, ble_client=ble_client,
                                    data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", whitelist=1, adv_filter_policy=3,
                                    scan_req_notify_enable=0, print_all_adv_devices=0)
    
#Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M 
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Secondary_adv_with_max_skip_1_C163814(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 1 and adv_type=0 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0, ble_client=ble_client,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=1, data_len=31,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHE", pri_adv_phy=1, sec_adv_phy=2,
                                    scan_req_notify_enable=1, print_all_adv_devices=0)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Secondary_adv_with_max_skip_15_C163815(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 1 and adv_type=0
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0, ble_client=ble_client,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=15, data_len=31,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", pri_adv_phy=1, sec_adv_phy=2,
                                    scan_req_notify_enable=1, print_all_adv_devices=0)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Secondary_adv_with_max_skip_255_C163816(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 255 and adv_type=0 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0, ble_client=ble_client,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=255, data_len=31,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", pri_adv_phy=1, sec_adv_phy=2,
                                    scan_req_notify_enable=1, print_all_adv_devices=0)

@pytest.mark.skip ("#adv report not received, adv happening on only phy 2M unable to change phy2 on scanning side")
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Secondary_adv_with_max_skip_08_adv_1_C163817(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 8 and adv_type=1 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=1, ble_client=ble_client,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=8, data_len=31,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", pri_adv_phy=1, sec_adv_phy=2,
                                    scan_req_notify_enable=1, print_all_adv_devices=0)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Secondary_adv_with_max_skip_08_adv_4_C163818(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 8 and adv_type=4 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=4, ble_client=ble_client,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=8, data_len=31,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", pri_adv_phy=1, sec_adv_phy=2,
                                    scan_req_notify_enable=1, print_all_adv_devices=1)

@pytest.mark.skip ("#adv report not received, adv happening on only phy 2M unable to change phy2 on scanning side")    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_Secondary_adv_with_max_skip_08_adv_5_C163819(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 8 and adv_type=5 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=5, ble_client=ble_client,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=8, data_len=31,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", pri_adv_phy=1, sec_adv_phy=2,
                                    scan_req_notify_enable=1, print_all_adv_devices=0)

#Extended Advertising, two Sets, Single PHY, LE primary phy is 1M PHY and sec phy is 2M
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_2ADV_sets_C163820(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 8 and adv_type=5 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0, adv_type_s2=1, ble_client=ble_client,
                                    min_interval=32, max_interval=32, data_len=0, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    print_all_adv_devices=1, adv_handle=0, adv_handle_s2=None)