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
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=17,
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
    
# ##LE Periodic Advertising - Synchronization on DUT for adv type = non con non scan undirected 
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_perodic_adv_C163726(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Periodic Advertising - Synchronization on DUT for adv type = non con non scan undirected 
    Test case          : This test case will verify Periodic Advertising with periodic data of 200bytes with pri 1m and sec phy 2m
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0, data_len=200, adv_data_type=2,
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6", ble_dut_address=ble_dut_address, pri_adv_phy=1, sec_adv_phy=1,
                                    print_all_adv_devices=0)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_perodic_adv_C163727(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Periodic Advertising - Synchronization on DUT for adv type = non con non scan undirected 
    Test case          : This test case will verify Periodic Advertising with periodic data of 200bytes with pri 1m and sec phy 2m
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0, data_len=200, adv_data_type=2,
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6", ble_dut_address=ble_dut_address, pri_adv_phy=1, sec_adv_phy=1,
                                    print_all_adv_devices=0)

@pytest.mark.skip("with LE coded ADV report is not getting received")    
@pytest.mark.ble_client("bt_wiseconnect")
def test_perodic_adv_C163728(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Periodic Advertising - Synchronization on DUT for adv type = non con non scan undirected 
    Test case          : This test case will verify Periodic Advertising with periodic data of 200bytes with pri Le Coded and sec phy LE coded
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0, data_len=200, adv_data_type=2,
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6", ble_dut_address=ble_dut_address, pri_adv_phy=3, sec_adv_phy=3,
                                    print_all_adv_devices=0)

##LE Periodic Advertising - Synchronization on DUT for adv type = non con non scan directed     

@pytest.mark.ble_client("bt_wiseconnect")
def test_perodic_adv_C163729(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Periodic Advertising - Synchronization on DUT for adv type = non con non scan directed 
    Test case          : This test case will verify Periodic Advertising with periodic data of 200bytes with pri 1M and sec phy 1M
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=4, data_len=200, adv_data_type=2,
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6", ble_dut_address=ble_dut_address, pri_adv_phy=1, sec_adv_phy=1,
                                    print_all_adv_devices=0)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_perodic_adv_C163730(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Periodic Advertising - Synchronization on DUT for adv type = non con non scan directed 
    Test case          : This test case will verify Periodic Advertising with periodic data of 200bytes with pri 1M and sec phy 1M
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=4, data_len=200, adv_data_type=2,
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6", ble_dut_address=ble_dut_address, pri_adv_phy=1, sec_adv_phy=2,
                                    print_all_adv_devices=0)

@pytest.mark.skip("with LE coded ADV report is not getting received")                           
@pytest.mark.ble_client("bt_wiseconnect")
def test_perodic_adv_C163731(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Periodic Advertising - Synchronization on DUT for adv type = non con non scan directed 
    Test case          : This test case will verify Periodic Advertising with periodic data of 200bytes with pri LE coded and sec phy LE coded
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=4, data_len=200, adv_data_type=2,
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6", ble_dut_address=ble_dut_address, pri_adv_phy=3, sec_adv_phy=3,
                                    print_all_adv_devices=0)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_perodic_adv_C163732(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : LE Periodic Advertising - Synchronization on DUT for adv type = non con non scan directed 
    Test case          : This test case will verify Periodic Advertising with periodic data of 200bytes with pri 1M and sec phy 1M
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0, adv_type_s2=0, data_len=200, adv_data_type=2,
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6", ble_dut_address=ble_dut_address, pri_adv_phy=1, sec_adv_phy=1,
                                    print_all_adv_devices=0, adv_handle=0, adv_handle_s2=1, min_interval=32, max_interval=32,
                                    min_interval_s2=32, max_interval_s2=32, random_address="11:22:33:44:55:66")
    
## BLE Extended Scan 

@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Scan_C163747(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Scan with scanning phy as 1M
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, scanning_phys=1)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Scan_C163749(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Scan with scan_Filter type as 0x1
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=2, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, scanning_phys=1, scanning_filter_policy=1, scanning_whitelist=True,
                                    dont_cleanup=True)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Scan_C163750(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Scan with scan_Filter type as 0x2
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=1, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, scanning_filter_policy=2, scanning_whitelist=True)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Scan_C163751(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Scan with scan_Filter type as 0x3
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=5, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, scanning_filter_policy=3, scanning_whitelist=True)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Scan_C163752(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Scan with filter_duplicates as 0 and adv type as scannable 
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=2, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, filter_duplicates=0, dont_cleanup=True)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Scan_C163753(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Scan with filter_duplicates as 0 and adv type as scannable 
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=2, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, filter_duplicates=1, dont_cleanup=True, stop_scan=0)

@pytest.mark.skip("need to understand test case req from manual poc")    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Scan_C163754(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Scan with with filter_duplicates as 0 and adv type as scannable
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=2, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, filter_duplicates=2,
                                    scanning_whitelist=True)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Scan_Passive_C163755(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Passive Scan with 100% dut cycle and scan window and pri phy 1M and sec phy 2M
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=5, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, scanning_phys=1, pri_adv_phy=1, sec_adv_phy=2,
                                    scanning_whitelist=True, scan_type_pri=0, scan_type_sec=0, scan_interval_pri=1600, scan_interval_sec=1600, 
                                    scan_window_pri=1600, scan_window_sec=1600, scan_set_2=1)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Scan_Passive_C163756(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Passive Scan with 25% dut cycle and scan window and pri phy 1M and sec phy 2M
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=5, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, scanning_phys=1, pri_adv_phy=1, sec_adv_phy=2,
                                    scanning_whitelist=True, scan_type_pri=0, scan_type_sec=0, scan_interval_pri=4096, scan_interval_sec=4096, 
                                    scan_window_pri=592, scan_window_sec=592, scan_set_2=1)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Scan_Passive_C163757(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Passive Scan with 50% dut cycle and scan window and pri phy 1M and sec phy 2M
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=5, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, scanning_phys=1, pri_adv_phy=1, sec_adv_phy=2,
                                    scanning_whitelist=True, scan_type_pri=0, scan_type_sec=0, scan_interval_pri=4096, scan_interval_sec=4096, 
                                    scan_window_pri=1280, scan_window_sec=1280, scan_set_2=1)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Passive_Scan_C163758(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Passive Scan with 10 ms scan interval and scan window and pri phy 1M and sec phy 2M
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=5, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, scanning_phys=1, pri_adv_phy=1, sec_adv_phy=2,
                                    scanning_whitelist=True, scan_type_pri=0, scan_type_sec=0, scan_interval_pri=16, scan_interval_sec=16, 
                                    scan_window_pri=16, scan_window_sec=16, scan_set_2=1)
    
@pytest.mark.skip("LE coded scan is not working")
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Passive_Scan_C163759(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Passive Scan with 100% dut cycle and scan window and pri phy and sec phy LE coded
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=5, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, scanning_phys=1, pri_adv_phy=3, sec_adv_phy=3,
                                    scanning_whitelist=True, scan_type_pri=0, scan_type_sec=0, scan_interval_pri=16, scan_interval_sec=16, 
                                    scan_window_pri=16, scan_window_sec=16, scan_set_2=1)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Scan_Active_C163763(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Passive Scan with 100% dut cycle and scan window and pri phy 1M and sec phy 2M
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=5, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, scanning_phys=1, pri_adv_phy=1, sec_adv_phy=2,
                                    scanning_whitelist=True, scan_type_pri=1, scan_type_sec=1, scan_interval_pri=1600, scan_interval_sec=1600, 
                                    scan_window_pri=1600, scan_window_sec=1600, scan_set_2=1)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Scan_Active_C163764(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Passive Scan with 25% dut cycle and scan window and pri phy 1M and sec phy 2M
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=5, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, scanning_phys=1, pri_adv_phy=1, sec_adv_phy=2,
                                    scanning_whitelist=True, scan_type_pri=1, scan_type_sec=1, scan_interval_pri=4096, scan_interval_sec=4096, 
                                    scan_window_pri=592, scan_window_sec=592, scan_set_2=1)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Scan_Active_C163765(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Passive Scan with 50% dut cycle and scan window and pri phy 1M and sec phy 2M
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=5, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, scanning_phys=1, pri_adv_phy=1, sec_adv_phy=2,
                                    scanning_whitelist=True, scan_type_pri=1, scan_type_sec=1, scan_interval_pri=4096, scan_interval_sec=4096, 
                                    scan_window_pri=1280, scan_window_sec=1280, scan_set_2=1)
    
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Scan_Active_C163766(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Passive Scan with 10 ms scan interval and scan window and pri phy 1M and sec phy 2M
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=5, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, scanning_phys=1, pri_adv_phy=1, sec_adv_phy=2,
                                    scanning_whitelist=True, scan_type_pri=1, scan_type_sec=1, scan_interval_pri=16, scan_interval_sec=16, 
                                    scan_window_pri=16, scan_window_sec=16, scan_set_2=1)
    #scan phy = 1M phy adv set1 : pri phy = 1M, sec phy = 1M adv type = non con non scan undir , adv data = 200 bytes scan rsp data = 200 bytes adv set2 : pri phy = 1M, sec phy = 1M ad

@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_EXT_Passive_Scan_C163771(ble_dut, ble_client, rs_helper_ble):
    """
    Test case category : BLE Extended Scan 
    Test case          : This test case will verify BLE Extended Passive Scan with 10 ms scan interval and scan window and pri phy 1M and sec phy 2M
    Device roles       : DUT is performing Peripheral role where Second DUT is performing Central
    """
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, central=ble_client, adv_type=0, data_len=1, adv_data="BLE_AE_ADV_DATA_1",
                                    print_all_adv_devices=0, ble_dut_address=ble_dut_address, scanning_phys=1, pri_adv_phy=1, sec_adv_phy=1,
                                    scanning_whitelist=True, scan_type_pri=0, scan_type_sec=0, scan_interval_pri=16, scan_interval_sec=16, 
                                    scan_window_pri=16, scan_window_sec=16, scan_set_2=1)