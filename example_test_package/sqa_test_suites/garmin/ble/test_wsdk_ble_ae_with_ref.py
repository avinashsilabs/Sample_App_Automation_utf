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
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=1,
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_legacy_adv_connectable_dir_high_duty_cycle_C163688(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE LEGACY ADVERTISING
    Test case          : This test case will verify Legacy advertisement with ADV type Connectable Directed,
                         and high duty cycle
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=29,
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_legacy_adv_scanable_undir_31byte_C163689(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE LEGACY ADVERTISING
    Test case          : This test case will verify Legacy advertisement with ADV type Scannable Undirected,
                         and ADV data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=18, data_len=31, adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address)

@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_legacy_adv_connectable_scanable_undir_1byte_c163690(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE LEGACY ADVERTISING
    Test case          : This test case will verify Legacy advertisement with ADV type Connectable Scannable Undirected,
                         and ADV data of 1 byte
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=19, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_legacy_adv_connectable_scanable_undir_0byte_c163691(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE LEGACY ADVERTISING
    Test case          : This test case will verify Legacy advertisement with ADV type Connectable Scannable Undirected,
                         and ADV data of 0 byte
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=19, data_len=0, 
                                      adv_data="AE_PERIPHERAL_DATA_0", ble_dut_address=ble_dut_address,
                                      print_all_adv_devices=0)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_legacy_adv_connectable_scanable_undir_31byte_c163692(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE LEGACY ADVERTISING
    Test case          : This test case will verify Legacy advertisement with ADV type Connectable Scannable Undirected,
                         and ADV data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=19, data_len=31, 
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6", ble_dut_address=ble_dut_address,
                                    print_all_adv_devices=0)
    
def test_verify_AE_Secondary_adv_with_max_skip_08_adv_5_C163819(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Test case          : This test case will verify handling of Secondary Advertising with max_skip param = 8 and adv_type=5 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=5, central=ble_client, ble_dut_address=ble_dut_address,
                                    min_interval=320, max_interval=352, sec_adv_max_skip=8, data_len=31,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERAL_DATA_", pri_adv_phy=1, sec_adv_phy=2,
                                    )