import pytest
import test_sta_ble_garmin as sb
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap, \
    RS9116AsyncEventType, RS9116BTFeatureBitMap, RS9116PowerSaveProcedureTypes
from utf.utils.logger import get_logger

def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC)

    Test Steps:
        1. Configure the DUT in Wlan coex mode
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify power management bit to be enable in Null data frames 
        5. Initiate BLE advertise/scan

    Author: Jyothi Nagireddy
"""


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE ,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_ble_18929(wifi_dut, wifi_access_point, ble_dut, ble_clients, rs_helper_ble, ble_client):
    remote_devices_count = 3
    test_case_no = 18929
    ble_obj = sb.BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client,
                           ble_clients=ble_clients, test_case_no=test_case_no,  remote_devices_count=remote_devices_count)
    try:
        wlan_obj = sb.WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18959)
        wlan_obj.start()
        ble_obj.start()
        wlan_obj.wait_for_exit()
        ble_obj.wait_for_exit()
    except Exception as e:
        logger().info("\n got exception: {}".format(str(e)))
        assert False, "Failed"
    finally:
        logger().info(f"*********clean_up********")
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE ,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_ble_18935(wifi_dut, wifi_access_point, ble_dut, ble_clients, rs_helper_ble, ble_client):
    remote_devices_count = 2
    test_case_no = 18935
    ble_obj = sb.BleThread(wifi_dut=wifi_dut, ble_dut=ble_dut, ble_client=ble_client,
                           ble_clients=ble_clients, test_case_no=test_case_no,  remote_devices_count=remote_devices_count)
    try:
        wlan_obj = sb.WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=18959)
        wlan_obj.start()
        ble_obj.start()
        wlan_obj.wait_for_exit()
        ble_obj.wait_for_exit()
    except Exception as e:
        logger().info("\n got exception: {}".format(str(e)))
        assert False, "Failed"
    finally:
         logger().info(f"*********clean_up********")
         ble_client.interfaces.bluetooth.close()
         rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_obj.dut_ble.bt_dut_address)
         wifi_dut.interfaces.wifi.leave()
