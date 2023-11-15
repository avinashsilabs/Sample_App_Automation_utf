import pytest
from example_test_package.conftest import rs_helper_ble
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, \
    RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap, RS9116PowerSaveProcedureTypes
from utf.utils.logger import get_logger
from itertools import permutations
from utf.interfaces.wifi import WlanError

from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryService
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryLevelCharacteristic
import time, os
import threading
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
import paramiko
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

def ble_disconnect(ble_dut, ble_client, ble_dut_address, rs_helper_ble, device_num):
    rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address)
    logger().info(f"\n\n **** Device {device_num} disconnected ****\n\n")


def DUT_as_slave_connection(ble_dut, ble_client, ble_dut_address, rs_helper_ble, device_num, itr_count, bond_info=0,smp_flag=True):

    logger().info(f"\n\n **** DUT as slave device no : {device_num} ****\n\n")
    if bond_info == 0 or itr_count==1:
        rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
        ble_remote_address= rs_helper_ble.ble_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
        rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
        rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address,
                                               smp_flag=smp_flag, bond_info= bond_info,skip_pairing=not(smp_flag))
        return ble_remote_address
    else:
        rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
        rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address,
                                               smp_flag=True, bond_info=bond_info, skip_pairing=True)
        return 'success'


def DUT_as_master_connection(ble_dut, ble_client, ble_dut_address, rs_helper_ble, device_num, itr_count,bond_info,remote=None,
                             ble_remote_address=None, smp_flag=True):

    logger().info(f"\n\n **** DUT as master device no : {device_num} ****\n\n")
    if bond_info == 0 or itr_count == 1:
        ble_remote_address = rs_helper_ble.ble_advertise_on_remote(adv_device=ble_client,
                                                                   ble_dut_address=ble_dut_address)
        try:
            rs_helper_ble.ble_scanning_on_dut(scan_device=ble_dut, ble_client_address=ble_remote_address, timeout=60)
        except:
            try:
                rs_helper_ble.ble_stop_scanning_on_dut(scan_device=ble_dut)
            except:
                pass
            rs_helper_ble.ble_scanning_on_dut(scan_device=ble_dut, ble_client_address=ble_remote_address, timeout=60)
        time.sleep(5)
        rs_helper_ble.ble_stop_scanning_on_dut(scan_device=ble_dut)
        rs_helper_ble.ble_connect_DUT_as_master(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address,
                                                ble_remote_address=ble_remote_address, smp_flag=smp_flag, bond_info= 0)
        return ble_remote_address
    else:
        rs_helper_ble.ble_connect_DUT_as_master(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address,
                                                ble_remote_address=ble_remote_address[remote], smp_flag=False,
                                                bond_info=bond_info)
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
        assert False, "Test case failed with Excepton {}".format(str(e))
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
        assert False, "Test case failed with Excepton {}".format(str(e))
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
        assert False, "Test case failed with Excepton {}".format(str(e))
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_client:BleDeviceState.scanning})

def test_verify_ble_passive_scan_C18799(ble_dut, ble_client, rs_helper_ble):
    #test case to verify BLE passive scanning
    with BleLogs(start_collecting_logs=True, bt_log_path=f"reports/HCI_log_test_C18799_verify_ble_passive_scan.log_{int(time.time())}"):
        ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
        ble_remote_address=rs_helper_ble.ble_advertise_on_remote(adv_device=ble_client, ble_dut_address=ble_dut_address)
        rs_helper_ble.ble_scanning_on_dut(scan_device=ble_dut, ble_client_address=ble_remote_address, ble_scan_type=1, timeout=60)
        rs_helper_ble.ble_stop_scanning_on_dut(scan_device=ble_dut)

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
        assert False, "Test case failed with Excepton {}".format(str(e))
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_client:BleDeviceState.standby})

def test_C91326_ble_connect_disconnect_dut_as_dual_role(ble_dut, ble_client, ble_clients, rs_helper_ble, order=(1,)):
#test case to verify connection stability where Dut is perfoming Dual role with multiple times connect disconnect
    try:
        connection_time = 60
        test_time = 7200
        ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut, bond_info=1, set_smp=1)
        ble_remote_address = dict()
        sw = Stopwatch()
        itr_count=0
        while sw.elapsed_sec < test_time:
            itr_count+=1
            logger().info(f"\n\n **** Iteration no : {itr_count} ****\n\n")
            rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
            try:
                rs_helper_ble.ble_stop_advertising_on_DUT(adv_device=ble_dut)
            except:
                pass
            for remote in order:
                if itr_count == 1:
                    ble_remote_address[remote] = DUT_as_master_connection(ble_dut=ble_dut,
                                                                          ble_client=ble_clients[remote - 1],
                                                                          ble_dut_address=ble_dut_address,
                                                                          rs_helper_ble=rs_helper_ble,
                                                                          device_num=remote, itr_count=itr_count,
                                                                          bond_info=1)
                else:
                    DUT_as_master_connection(ble_dut=ble_dut, ble_client=ble_clients[remote - 1],
                                             ble_dut_address=ble_dut_address,
                                             rs_helper_ble=rs_helper_ble, device_num=remote,
                                             itr_count=itr_count, bond_info=1,
                                             ble_remote_address=ble_remote_address, remote=remote)

            try:
                rs_helper_ble.ble_stop_advertising_on_DUT(adv_device=ble_dut)
            except:
                pass
            time.sleep(connection_time)
            for remote in order:
                ble_disconnect(ble_dut=ble_dut, ble_client=ble_clients[remote - 1], ble_dut_address=ble_dut_address,
                               rs_helper_ble=rs_helper_ble, device_num=remote)

    except Exception as e:
        assert False, "Test case failed with Excepton {}".format(str(e))
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        for remote in order:
            try:
                if remote == 0:
                    ble_client.interfaces.bluetooth.close()
                else:
                    ble_clients[remote - 1].interfaces.bluetooth.close()
            except:
                pass

def test_C91320_verify_ble_quick_disconnect(ble_dut, ble_client, rs_helper_ble):
    #test case to verify BLE quick disconnect
    try:
        for i in range(100):
            logger().info(f"\n\n ** Iteration : {i+1}")
            if i < 1: #first time connection
                ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
                rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
                rs_helper_ble.ble_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
                rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
                rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, smp_flag=True)
            else:
                rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, smp_flag=True, skip_pairing=True)
            
            time.sleep(5)
            rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, start_adv=True)
            i+=1
    except Exception as e:
        assert False, "Test case failed with Excepton {}".format(str(e))
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_client:BleDeviceState.standby})

def test_C91277_dual_role_connection_stability_secure_and_unencrypted(ble_dut,ble_client, ble_clients, rs_helper_ble,order=(0,1)):
    #test case to verify Dual role connection stability with one secure connection and one unencrypted
    try:
        connection_time = 180
        ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut, bond_info=1, set_smp=1)
        ble_remote_address = dict()
        for itr_count in range(1, 5):
            logger().info(f"\n\n **** Iteration no : {itr_count} ****\n\n")
            for remote in order:
                if remote == 0:
                    DUT_as_slave_connection(ble_dut=ble_dut, ble_client=ble_client,
                                            ble_dut_address=ble_dut_address,
                                            rs_helper_ble=rs_helper_ble, device_num=remote,
                                            itr_count=itr_count, bond_info=0,smp_flag=False)
                else:
                    if itr_count == 1:
                        ble_remote_address[remote] = DUT_as_master_connection(ble_dut=ble_dut,
                                                                              ble_client=ble_clients[remote - 1],
                                                                              ble_dut_address=ble_dut_address,
                                                                              rs_helper_ble=rs_helper_ble,
                                                                              device_num=remote, itr_count=itr_count,
                                                                              bond_info=1)
                    else:
                        DUT_as_master_connection(ble_dut=ble_dut, ble_client=ble_clients[remote - 1],
                                                 ble_dut_address=ble_dut_address,
                                                 rs_helper_ble=rs_helper_ble, device_num=remote,
                                                 itr_count=itr_count, bond_info=1,
                                                 ble_remote_address=ble_remote_address, remote=remote)

            time.sleep(connection_time)
            for remote in order:
                if remote == 0:
                    ble_disconnect(ble_dut=ble_dut, ble_client=ble_client, ble_dut_address=ble_dut_address,
                                   rs_helper_ble=rs_helper_ble, device_num=remote)
                    ble_client.interfaces.bluetooth.close()
                else:
                    ble_disconnect(ble_dut=ble_dut, ble_client=ble_clients[remote - 1], ble_dut_address=ble_dut_address,
                                   rs_helper_ble=rs_helper_ble, device_num=remote)
                    # ble_clients[remote-1].interfaces.bluetooth.close()

    except Exception as e:
        assert False, "Test case failed with Excepton {}".format(str(e))
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        for remote in order:
            try:
                if remote == 0:
                    ble_client.interfaces.bluetooth.close()
                else:
                    ble_clients[remote - 1].interfaces.bluetooth.close()
            except:
                pass

def ble_static_activity(ble_dut, ble_remote_m1, ble_remote_m2, rs_helper_ble, adv_interval=None) :
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut, bond_info=0, set_smp=0)
    def adv_on_dut():
        if adv_interval:
            rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address, ble_adv_int_min=adv_interval, ble_adv_int_max=adv_interval)
        else: rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
    adv_on_dut()
    rs_helper_ble.ble_scanning_on_remote(scan_device=ble_remote_m1, bt_dut_address=ble_dut_address)
    rs_helper_ble.ble_scanning_on_remote(scan_device=ble_remote_m2, bt_dut_address=ble_dut_address)
    hci_log_m1 = f"reprots/hci.log_"+str(int(time.time()))
    hci_log_m2 = f"reports/hci.log_"+str(int(time.time()))
    with ble_remote_m1.interfaces.bluetooth.ble_logs(start_collecting_logs=True, bt_log_path=hci_log_m1):
        rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_remote_m1, ble_dut_address=ble_dut_address, smp_flag=False, min_conn_interval=36, max_conn_interval=36)
        time.sleep(5)
    adv_on_dut()    
    with ble_remote_m2.interfaces.bluetooth.ble_logs(start_collecting_logs=True, bt_log_path=hci_log_m2):
        rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_remote_m2, ble_dut_address=ble_dut_address, smp_flag=False, min_conn_interval=36, max_conn_interval=36)
    import os
    if os.path.isfile(hci_log_m1):       
        logger().info("\n\n {}".format("\n\n\n *** Verifying connection interval from HCI dump logs...! \n\n"))
        with open(hci_log_m1, 'r') as file:
            log = file.read()
            time.sleep(10)
            pattern_found = False
            if "Connection interval: 45.00 msec (0x0024)" in str(log): pattern_found=True
            assert pattern_found, "Failed...connection is not established with interval 45 ms!"
            logger().info("\n\n **** Found Connection interval: 45.00 msec (0x0024) string in HCI_Dump logs, which confirms connection is established with interval 45 ms")
    else: assert "HCI Logs are not captured"
    return ble_dut_address

def test_static_activity_C91315(ble_dut, ble_client, ble_clients, rs_helper_ble):
    #test case to verify 2 central connections with connection interval 45 ms
    try:
        ble_dut_address = ble_static_activity(ble_dut=ble_dut, ble_remote_m1=ble_client, ble_remote_m2=ble_clients[0], rs_helper_ble=rs_helper_ble)
    except Exception as e:
        assert False, "Test case failed with Excepton {}".format(str(e))
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        logger().info("\n\n\n ***** Initiating Clean UP....! ******\n\n\n")
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_client:BleDeviceState.connected, ble_clients[0]:BleDeviceState.connected})

def test_static_activity_C91316(ble_dut, ble_clients, rs_helper_ble):
    #test case to verify 2 central connections with connection interval 45 ms and advertising interval is 0x152
    try:
        ble_dut_address = ble_static_activity(ble_dut=ble_dut, ble_remote_m1=ble_clients[0], ble_remote_m2=ble_clients[1], adv_interval=211 ,rs_helper_ble=rs_helper_ble)
    except Exception as e:
        assert False, "Test case failed with Excepton {}".format(str(e))
    else:
        logger().info("\n\n **** Found Connection interval: 45.00 msec (0x0024) string in HCI_Dump logs, which confirms connection is established with interval 45 ms")
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        logger().info("\n\n\n ***** Initiating Clean UP....! ******\n\n\n")
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_clients[0]:BleDeviceState.connected, ble_clients[1]:BleDeviceState.connected})

def test_update_conn_param_in_loop_C91312_dut_as_slave(ble_dut, ble_client, rs_helper_ble):
    #test case to verify updating the connection parameter form remote in a loop for 10 min duration, where DUT is performing slave role
    test_duration = 600
    try:
        ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut, bond_info=1, set_smp=1)
        rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
        rs_helper_ble.ble_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
        rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
        rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, smp_flag=True)
        sw = Stopwatch()
        hci_logs = f"reports/hci.log_"+str(int(time.time()))
        with ble_client.interfaces.bluetooth.ble_logs(start_collecting_logs=True, bt_log_path=hci_logs):
            while sw.elapsed_sec < test_duration:
                ble_client.interfaces.bluetooth.hci_tool_manager.update_conn(dev_addr=ble_dut_address, 
                    min_conn_interval=36,max_conn_interval=36,conn_latency=0,
                    supervision_timeout=3200)
                time.sleep(15)
        if os.path.isfile(hci_logs):       
            logger().info("\n\n {}".format("\n\n\n *** Verifying updated connection parameter from HCI dump logs...! \n\n"))
            with open(hci_logs, 'r') as file:
                log = file.read()
                time.sleep(10)
                pattern_found = False
                if "Connection interval: 45.00 msec (0x0024)" in str(log): pattern_found=True
                assert pattern_found, "Failed...connection parameter is not updated..!"
                logger().info("\n\n **** Found Connection interval: 45.00 msec (0x0024) string in HCI_Dump logs, which confirms connection paramters are updated successfully..!")
        else: assert False, "HCI Logs are not captured"
        rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, start_adv=False)
    except Exception as e:
        assert False, "Found Exception {}".format(str(e))
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address)


def test_wrong_passkey_C18795(ble_dut, ble_client, rs_helper_ble):
    #test case to verify updating the connection parameter form remote in a loop for 10 min duration, where DUT is performing slave role
    try:
        ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut, capability=2)
        rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)

        #with Wrong pass key
        rs_helper_ble.ble_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address, pin_code=123456, capability="KeyboardOnly")
        rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
        logger().info("\n\n\n *** Initiating a connection with wrong passkey ***\n\n")
        connected = ble_client.interfaces.bluetooth.pair_and_connect(ble_dut_address)
        time.sleep(1)
        assert not connected, "BLE Connection is established even with Wrong Passkey, Expected SMP Fail with 0x4b04"

        #with correct passkey
        ble_client.interfaces.bluetooth.close()
        rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
        rs_helper_ble.ble_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
        rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
        logger().info("\n\n\n *** Initiating a connection with Correct passkey ***\n\n")
        rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, smp_flag=True)
        rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, start_adv=False)
    except Exception as e:
        assert False, "Test case is failed with exception:  {}".format(str(e))
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        logger().info("\n\n\n ***** Initiating Clean UP....! ******\n\n\n")
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_client:BleDeviceState.standby})

def test_C91278_dual_role_connection_stability_both_unsecure(rs_helper_ble, ble_dut, ble_client, ble_clients, order=(0,1)):
    #test case to verify Dual role unsecure connection stability
    try:
        connection_time = 5
        ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut, bond_info=0, set_smp=0)
        ble_remote_address = dict()
        for itr_count in range(1, 3):
            logger().info(f"\n\n **** Iteration no : {itr_count} ****\n\n")
            for remote in order:
                if remote == 0:
                    DUT_as_slave_connection(ble_dut=ble_dut, ble_client=ble_client,
                                            ble_dut_address=ble_dut_address,
                                            rs_helper_ble=rs_helper_ble, device_num=remote,
                                            itr_count=itr_count, bond_info=0,smp_flag=False)
                else:
                    DUT_as_master_connection(ble_dut=ble_dut, ble_client=ble_clients[remote - 1],
                                             ble_dut_address=ble_dut_address,
                                             rs_helper_ble=rs_helper_ble, device_num=remote,
                                             itr_count=itr_count, bond_info=0,
                                             ble_remote_address=ble_remote_address, remote=remote,smp_flag=False)

            time.sleep(connection_time)
            for remote in order:
                if remote == 0:
                    ble_disconnect(ble_dut=ble_dut, ble_client=ble_client, ble_dut_address=ble_dut_address,
                                   rs_helper_ble=rs_helper_ble, device_num=remote)
                    ble_client.interfaces.bluetooth.close()
                else:
                    ble_disconnect(ble_dut=ble_dut, ble_client=ble_clients[remote - 1], ble_dut_address=ble_dut_address,
                                   rs_helper_ble=rs_helper_ble, device_num=remote)
                    ble_clients[remote-1].interfaces.bluetooth.close()

    except Exception as e:
        assert False, "Test case failed with Excepton {}".format(str(e))
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        for remote in order:
            try:
                if remote == 0:
                    ble_client.interfaces.bluetooth.close()
                else:
                    ble_clients[remote - 1].interfaces.bluetooth.close()
            except:
                pass

def test_C91279_dual_role_connection_stability_both_secure(ble_dut,ble_client, ble_clients, rs_helper_ble, order=(0,1)):
    #test case to verify Dual role connection stability with one secure connection and one unencrypted
    try:
        connection_time = 5
        ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut, bond_info=1, set_smp=1)
        ble_remote_address = dict()
        for itr_count in range(1, 3):
            logger().info(f"\n\n **** Iteration no : {itr_count} ****\n\n")
            for remote in order:
                if remote == 0:
                    DUT_as_slave_connection(ble_dut=ble_dut, ble_client=ble_client,
                                            ble_dut_address=ble_dut_address,
                                            rs_helper_ble=rs_helper_ble, device_num=remote,
                                            itr_count=itr_count, bond_info=1)
                else:
                    if itr_count == 1:
                        ble_remote_address[remote] = DUT_as_master_connection(ble_dut=ble_dut,
                                                                              ble_client=ble_clients[remote - 1],
                                                                              ble_dut_address=ble_dut_address,
                                                                              rs_helper_ble=rs_helper_ble,
                                                                              device_num=remote, itr_count=itr_count,
                                                                              bond_info=1)
                    else:
                        DUT_as_master_connection(ble_dut=ble_dut, ble_client=ble_clients[remote - 1],
                                                 ble_dut_address=ble_dut_address,
                                                 rs_helper_ble=rs_helper_ble, device_num=remote,
                                                 itr_count=itr_count, bond_info=1,
                                                 ble_remote_address=ble_remote_address, remote=remote)

            time.sleep(connection_time)
            for remote in order:
                if remote == 0:
                    ble_disconnect(ble_dut=ble_dut, ble_client=ble_client, ble_dut_address=ble_dut_address,
                                   rs_helper_ble=rs_helper_ble, device_num=remote)
                else:
                    ble_disconnect(ble_dut=ble_dut, ble_client=ble_clients[remote - 1], ble_dut_address=ble_dut_address,
                                   rs_helper_ble=rs_helper_ble, device_num=remote)

    except Exception as e:
        assert False, "Test case failed with Excepton {}".format(str(e))
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        for remote in order:
            try:
                if remote == 0:
                    ble_client.interfaces.bluetooth.close()
                else:
                    ble_clients[remote - 1].interfaces.bluetooth.close()
            except:
                pass

def test_two_slave_conn_stability_both_secure_C91275(ble_dut, ble_client, ble_clients, rs_helper_ble):
    #test case to verify connection stability with 2 slave smp connections
    try:
        remote1 = ble_client
        remote2 = ble_clients[0]
        ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut, capability=1, set_smp=1)

        for i in range(5):
            #Initiating a connection from remote1 without giving a passkey
            logger().info(f"\n\n *** Iteration : {i+1}")
            rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
            if i == 0 :
                remote_1_add = rs_helper_ble.ble_scanning_on_remote(scan_device=remote1, bt_dut_address=ble_dut_address, pin_code=-1, capability="DisplayOnly")
                rs_helper_ble.ble_stop_scanning_on_remote(scan_device=remote1, bt_dut_address=ble_dut_address)
            logger().info(f"\n\n\n *** Initiating a connection from first Remote {remote_1_add} without entering passkey ***\n\n")
            connected = remote1.interfaces.bluetooth.pair_and_connect(ble_dut_address)
            time.sleep(1)
            assert not connected, "BLE Connection is established even with Wrong Passkey, Expected SMP Fail with 0x4b04"
            logger().info(f"\n\n ** Connection is not successfull with Remote 1 {remote_1_add} as passkey is not given...! \n")

            #Initiating a connection from remote2 without giving a passkey
            rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
            if i == 0:
                remote_2_add = rs_helper_ble.ble_scanning_on_remote(scan_device=remote2, bt_dut_address=ble_dut_address, pin_code=-1, capability="DisplayOnly")
                rs_helper_ble.ble_stop_scanning_on_remote(scan_device=remote2, bt_dut_address=ble_dut_address)
            logger().info(f"\n\n\n *** Initiating a connection from second Remote {remote_2_add} without entering passkey ***\n\n")
            connected = remote2.interfaces.bluetooth.pair_and_connect(ble_dut_address)
            time.sleep(1)
            assert not connected, "BLE Connection is established even with Wrong Passkey, Expected SMP Fail with 0x4b04"
            logger().info(f"\n\n ** Connection is not successfull with Remote 2 {remote_2_add} as passkey is not given...! \n")

        time.sleep(10)
        ble_dut.interfaces.bluetooth.ble_stop_advertising(timeout=10)
        remote1.interfaces.bluetooth.close()

        logger().info("\n\n\n *** Initiating a connection with remote 1 and checking the stability for 15 min ***\n\n")
        rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
        remote_1_add = rs_helper_ble.ble_scanning_on_remote(scan_device=remote1, bt_dut_address=ble_dut_address)
        rs_helper_ble.ble_stop_scanning_on_remote(scan_device=remote1, bt_dut_address=ble_dut_address)
        rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, smp_flag=True)
        time.sleep(60)
        rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, start_adv=False)
    except Exception as e:
        assert False, "Test case is failed with exception:  {}".format(str(e))
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        logger().info("\n\n\n ***** Initiating Clean UP....! ******\n\n\n")
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_client:BleDeviceState.standby})

@pytest.mark.parametrize(
    "order",
    [
        i for i in [_ for i in range(1,6) for _ in  list(permutations([0,1,2,3,4],i))]
    ],
)
def test_1_to_5_325_combination_remote_unsecure_conn_reconn(ble_dut, ble_client, ble_clients, rs_helper_ble, order):
    # test case to verify connection stability with 2 master connections and 2 slave connections and scanning from DUT
    #includes C91282 and C91283
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/HCI_log_test_1_to_5_remote_conn_reconn.log_{int(time.time())}"):
            connection_time = 5
            ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut, bond_info=1, set_smp=1)
            logger().info(f"*****************Remote device order {order} *************************")
            ble_remote_address=dict()
            for itr_count in range(1, 3):
                logger().info(f"\n\n **** Iteration no : {itr_count} ****\n\n")
                for remote in order:
                    if remote in [0,1]:
                        if remote == 0:
                            DUT_as_slave_connection(ble_dut=ble_dut, ble_client=ble_client,
                                                    ble_dut_address=ble_dut_address,
                                                    rs_helper_ble=rs_helper_ble, device_num=remote,
                                                    itr_count=itr_count, bond_info=0, smp_flag=False)
                        else:
                            DUT_as_slave_connection(ble_dut=ble_dut, ble_client=ble_clients[remote-1],
                                                                            ble_dut_address=ble_dut_address,
                                                                            rs_helper_ble=rs_helper_ble, device_num=remote,
                                                                            itr_count=itr_count, bond_info=0, smp_flag=False)
                    else:
                        DUT_as_master_connection(ble_dut=ble_dut, ble_client=ble_clients[remote - 1],
                                                 ble_dut_address=ble_dut_address,
                                                 rs_helper_ble=rs_helper_ble, device_num=remote,
                                                 itr_count=itr_count, bond_info=0,
                                                 ble_remote_address=ble_remote_address, remote=remote, smp_flag=False)


                time.sleep(connection_time)
                for remote in order:
                    if remote == 0:
                        ble_disconnect(ble_dut=ble_dut, ble_client=ble_client, ble_dut_address=ble_dut_address,
                                       rs_helper_ble=rs_helper_ble, device_num=remote)
                        ble_client.interfaces.bluetooth.close()
                    else:
                        ble_disconnect(ble_dut=ble_dut, ble_client=ble_clients[remote-1], ble_dut_address=ble_dut_address,
                                       rs_helper_ble=rs_helper_ble, device_num=remote)
                        ble_clients[remote-1].interfaces.bluetooth.close()

    except Exception as e:
        assert False, "Test case failed with Excepton {}".format(str(e))
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        for remote in order:
            try:
                if remote==0:
                    ble_client.interfaces.bluetooth.close()
                else:
                    ble_clients[remote - 1].interfaces.bluetooth.close()
            except:
                pass

def test_secure_conn_disconn_for_255_itr_C91309(ble_dut,ble_client,rs_helper_ble,order=(0,)):
    try:
        connection_time = 5
        ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut, bond_info=1, set_smp=1)
        logger().info(f"*****************Remote device order {order} *************************")
        for itr_count in range(1, 25):
            logger().info(f"\n\n **** Iteration no : {itr_count} ****\n\n")
            for remote in order:
                if remote == 0:
                    DUT_as_slave_connection(ble_dut=ble_dut, ble_client=ble_client,
                                            ble_dut_address=ble_dut_address,
                                            rs_helper_ble=rs_helper_ble, device_num=remote,
                                            itr_count=itr_count, bond_info=1)
            time.sleep(connection_time)
            for remote in order:
                if remote == 0:
                    ble_disconnect(ble_dut=ble_dut, ble_client=ble_client, ble_dut_address=ble_dut_address,
                                   rs_helper_ble=rs_helper_ble, device_num=remote)

    except Exception as e:
        assert False, "Test case failed with Excepton {}".format(str(e))
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        try:
            ble_client.interfaces.bluetooth.close()
        except:
            pass


def test_ble_conn_disconn_with_resolve_list_C91322(ble_dut, ble_client, rs_helper_ble): #use latest hex file
    #Verifying the customer issue RSC-10396 : BLE connect-disconnect with resolving list
    try:
        ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/HCI_log_test_C91303_ble_connect_disconnect_dut_as_slave.log_{int(time.time())}"):
            logger().info(f"\n\n **** Iteration no : 1 ****\n\n")
            ble_dut.interfaces.wifi.ble_set_local_irk_value()
            rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
            rs_helper_ble.ble_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
            rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
            rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client,
                                                   ble_dut_address=ble_dut_address, smp_flag=True)
            rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_client,
                                                     ble_dut_address=ble_dut_address)

            for i in range(2,25):
                logger().info(f"\n\n **** Iteration no : {i} ****\n\n")
                ble_dut.interfaces.wifi.ble_start_advertising_with_values()
                rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client,
                                                       ble_dut_address=ble_dut_address, smp_flag=False)
                rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_client,
                                                         ble_dut_address=ble_dut_address)

            ble_client.interfaces.bluetooth.close()

    except Exception as e:
        assert False, "Test case failed with Excepton {}".format(str(e))
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        try:
            ble_client.interfaces.bluetooth.close()
        except:
            pass
