import pytest
from example_test_package.conftest import rs_helper_ble
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, \
    RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap, RS9116PowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf.interfaces.wifi import WlanError

from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryService
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryLevelCharacteristic
import time
import threading
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch

def logger():
    return get_logger(__name__)
"""
    * setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
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
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
            "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        },
    ),
]

class BleDeviceState():
    advertising  = 1
    scanning = 2
    initiating = 4
    connected = 8
    standby = 0

    def dut_as_master(self, ble_dut, ble_remote, ble_dut_address, smp_flag, rs_helper_ble):
        ble_remote_address=rs_helper_ble.ble_advertise_on_remote(adv_device=ble_remote, ble_dut_address=ble_dut_address)
        time.sleep(5)
        if smp_flag:
            rs_helper_ble.ble_connect_DUT_as_master(ble_dut=ble_dut, ble_remote=ble_remote, ble_dut_address=ble_dut_address, ble_remote_address=ble_remote_address, smp_flag=True)
        else:
            rs_helper_ble.ble_connect_DUT_as_master(ble_dut=ble_dut, ble_remote=ble_remote, ble_dut_address=ble_dut_address, ble_remote_address=ble_remote_address, smp_flag=False)
        return ble_remote_address

    def dut_as_slave(self, ble_dut, ble_remote, ble_dut_address, smp_flag, rs_helper_ble):
        ble_remote_address=rs_helper_ble.ble_scanning_on_remote(scan_device=ble_remote, bt_dut_address=ble_dut_address)
        rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_remote, bt_dut_address=ble_dut_address)
        if smp_flag:
            rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_remote, ble_dut_address=ble_dut_address, smp_flag=True)
        else:
            rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_remote, ble_dut_address=ble_dut_address, smp_flag=False)
        return ble_remote_address

def test_C91302_ble_connection_stability_dut_as_master(ble_dut, ble_client, rs_helper_ble):
#test case to verify connection stability for 15 min with smp where DUT is performing Central role
    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_test_C91302_ble_connection_stability_dut_as_master.log_{int(time.time())}"):
            connection_time=900
            ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
            ble_remote_address=rs_helper_ble.ble_advertise_on_remote(adv_device=ble_client, ble_dut_address=ble_dut_address)
            rs_helper_ble.ble_scanning_on_dut(scan_device=ble_dut, ble_client_address=ble_remote_address, timeout=60)
            rs_helper_ble.ble_stop_scanning_on_dut(scan_device=ble_dut)
            rs_helper_ble.ble_connect_DUT_as_master(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, ble_remote_address=ble_remote_address, smp_flag=True)
            time.sleep(connection_time)
            rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address)
    except Exception as e:
        logger().info("\n got exception: {}".format(str(e)))
        assert False, "Failed" 
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_client:BleDeviceState.advertising})
        
def test_C91314_ble_connect_with_diff_adv_interval(ble_dut, ble_client, rs_helper_ble):
#test case to verify BLE connection stability for 1 hr with different advertising  inverval where DUT is performing Peripheral role with adv interval 0x152
    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_test_C91314_ble_connect_with_diff_adv_interval.log_{int(time.time())}"):
            connection_time=3600
            ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
            rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address, ble_adv_int_min=211, ble_adv_int_max=211)
            rs_helper_ble.ble_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
            rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
            rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, smp_flag=True)
            time.sleep(connection_time)
            rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address)
    except Exception as e:
        logger().info("\n got exception: {}".format(str(e)))
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_client:BleDeviceState.standby})

def test_C18792_verify_ble_adv_on_dut(ble_dut, ble_client, rs_helper_ble):
    #test case to verify BLE advertising  on DUT with advertising  interval is 20ms
    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_test_C18792_verify_ble_adv_on_dut.log_{int(time.time())}"):
            adv_interval = int(20/0.625)
            ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
            rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address, ble_adv_int_min=adv_interval, ble_adv_int_max=adv_interval)
            rs_helper_ble.ble_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
            rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
    except Exception as e:
        logger().info("\n got exception: {}".format(str(e)))
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_client:BleDeviceState.scanning})

def test_C91303_ble_connect_disconnect_dut_as_slave(ble_dut, ble_client, rs_helper_ble):  
    #test case to verify connection stability where Dut is perfoming Peripheral/Slave role with multiple times connect disconnect
    try:
        connction_time=300
        no_of_reconnect=5
        ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_test_C91303_ble_connect_disconnect_dut_as_slave.log_{int(time.time())}"):
            for i in range(no_of_reconnect):
                rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
                rs_helper_ble.ble_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
                rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
                rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, smp_flag=True)
                time.sleep(connction_time)
                rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address)
                ble_client.interfaces.bluetooth.close()
                i=i+1
    except Exception as e:
        logger().info("\n got exception: {}".format(str(e)))
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_client:BleDeviceState.standby})

def test_C91326_ble_connect_disconnect_dut_as_dual_role(ble_dut, ble_client, rs_helper_ble):
#test case to verify connection stability where Dut is perfoming Dual role with multiple times connect disconnect
    try:
        connction_time=60
        test_time=7200
        ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut, bond_info=0)
        with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_test_C91326_ble_connect_disconnect_dut_as_dual_role.log_{int(time.time())}"):
            rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address, ble_adv_int_min=338, ble_adv_int_max=338)
            sw = Stopwatch()
            while sw.elapsed_sec < test_time:
                ble_remote_address=rs_helper_ble.ble_advertise_on_remote(adv_device=ble_client, ble_dut_address=ble_dut_address)
                rs_helper_ble.ble_scanning_on_dut(scan_device=ble_dut, ble_client_address=ble_remote_address, timeout=60)
                rs_helper_ble.ble_stop_scanning_on_dut(scan_device=ble_dut)
                rs_helper_ble.ble_connect_DUT_as_master(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, ble_remote_address=ble_remote_address, smp_flag=True)
                time.sleep(connction_time)
                rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address)
                ble_client.interfaces.bluetooth.close()
            ble_remote_address=rs_helper_ble.ble_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
            rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
    except Exception as e:
        if "dbus.exceptions.DBusException" in str(e):
            assert False, "\n\n *** Setup Issue"
        logger().info("\n got exception: {}".format(str(e)))
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_client:BleDeviceState.advertising })

def test_C91320_verify_ble_quick_disconnect(ble_dut, ble_client, rs_helper_ble):
    #test case to verify BLE quick disconnect
    try:
        ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
        for i in range(100):
            rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
            rs_helper_ble.ble_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
            rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
            rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, smp_flag=True)
            time.sleep(5)
            rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            i=i+1
    except Exception as e:
        logger().info("\n got exception: {}".format(str(e)))
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_client:BleDeviceState.standby})

def test_C91277_dual_role_connection_stability_secure_and_unencrypted(ble_dut, ble_clients, rs_helper_ble):
    #test case to verify Dual role connection stability with one secure connection and one unencrypted
    ble_obj = BleDeviceState()
    try:
        ble_remote_slave = ble_clients[0]
        ble_remote_master = ble_clients[1]
        connection_time=180
        loop=4
        ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)

        rs_helper_ble.ble_scanning_on_dut(scan_device=ble_dut, timeout=120)
        rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)

        for i in range(loop):
            logger().info("\n\n *** Iteration :  {} ***\n\n".format(i+1))
            if i%2==0:
                ble_obj.dut_as_slave(ble_dut=ble_dut, ble_remote=ble_remote_master, ble_dut_address=ble_dut_address, smp_flag=False, rs_helper_ble=rs_helper_ble)
                ble_remote_slave_add = ble_obj.dut_as_master(ble_dut=ble_dut, ble_remote=ble_remote_slave, ble_dut_address=ble_dut_address, smp_flag=True, rs_helper_ble=rs_helper_ble)
            else:
                ble_remote_slave_add = ble_obj.dut_as_master(ble_dut=ble_dut, ble_remote=ble_remote_slave, ble_dut_address=ble_dut_address, smp_flag=True, rs_helper_ble=rs_helper_ble)
                ble_obj.dut_as_slave(ble_dut=ble_dut, ble_remote=ble_remote_master, ble_dut_address=ble_dut_address, smp_flag=False, rs_helper_ble=rs_helper_ble)

            time.sleep(connection_time)
            rs_helper_ble.ble_disconnect_from_DUT(ble_dut=ble_dut, ble_remote_address=ble_remote_slave_add, ble_dut_address=ble_dut_address, start_adv=True)                                     
            ble_remote_slave.interfaces.bluetooth.close()
            rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_remote_master, ble_dut_address=ble_dut_address, start_adv=True)
            ble_remote_master.interfaces.bluetooth.close()
    except Exception as e:
        logger().info("\n got exception: {}".format(str(e)))
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_remote_slave:BleDeviceState.advertising, ble_remote_master:BleDeviceState.advertising})