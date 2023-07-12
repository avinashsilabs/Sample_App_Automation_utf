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
                                    ble_client=ble_client, print_all_adv_devices=1)
    

@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_legacy_adv_connectable_dir_high_duty_cycle_C163688(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE LEGACY ADVERTISING
    Test case          : This test case will verify Legacy advertisement with ADV type Connectable Directed,
                         and high duty cycle
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=29,
                                    ble_client=ble_client, print_all_adv_devices=1)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_legacy_adv_scanable_undir_31byte_C163689(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE LEGACY ADVERTISING
    Test case          : This test case will verify Legacy advertisement with ADV type Scannable Undirected,
                         and ADV data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=18, data_len=19, adv_data="BLE_AE_ADV_DATA_1",
                                    ble_client=ble_client, print_all_adv_devices=1)

@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_legacy_adv_connectable_scanable_undir_1byte_c163690(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE LEGACY ADVERTISING
    Test case          : This test case will verify Legacy advertisement with ADV type Connectable Scannable Undirected,
                         and ADV data of 1 byte
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=19, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    ble_client=ble_client, print_all_adv_devices=1)
    
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
                                      ble_client=ble_client, print_all_adv_devices=1)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_legacy_adv_connectable_scanable_undir_31byte_c163692(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE LEGACY ADVERTISING
    Test case          : This test case will verify Legacy advertisement with ADV type Connectable Scannable Undirected,
                         and ADV data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=19, data_len=31, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6_",
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
                                    ble_client=ble_client, print_all_adv_devices=1, adv_handle=0)
    
    logger().info(f"\n\n ** Verifying AE with highest handle ie. 0xef **\n\n")
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, print_all_adv_devices=1, adv_handle=239)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_ADV_for_infinite_time_C163696(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention for infinite time with duration paramerter 0x0000
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, print_all_adv_devices=0, adv_handle=0, data_len=31, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", adv_time=60, duration=0)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_ADV_for_2560ms_C163697(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Advertising Extension 
    Test case          : This test case will verify Advertising Extention for 2560ms and verify even RSI_APP_EVENT_EXT_ADV_TERMINATED
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, print_all_adv_devices=1, adv_handle=0,
                                    duration=256, adv_async_required=1, no_scan=1)

@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_ADV_for_2560ms_C163698(ble_dut, ble_client, rs_helper_ble):
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
                                    ble_client=ble_client, own_address_type=1, print_all_adv=0,
                                    random_address="11:33:33:33:33:11")
    
    #######################  LE Ext Adv - Non connectable Non Scannable undirected adv ####################
    
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
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_AE_non_conn_non_scan_ADV_C163704(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M 
                         with adv data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0,
                                    ble_client=ble_client, data_len=31, adv_time=60, print_all_adv_devices=0,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA")
