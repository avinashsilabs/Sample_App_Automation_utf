import pytest
from example_test_package.conftest import rs_helper_ble
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, \
    RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap, RS9116PowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf.interfaces.wifi import WlanError
from utf_wiseconnect.utils.rs_helper_commands_ble import RSHelperCommandsBle
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

    def dut_as_master(self, ble_dut, ble_remote, ble_dut_address, smp_flag, rs_helper_ble, ble_remote_address):
        time.sleep(5)
        if smp_flag:
            rs_helper_ble.ble_connect_DUT_as_master(ble_dut=ble_dut, ble_remote=ble_remote, ble_dut_address=ble_dut_address, ble_remote_address=ble_remote_address, smp_flag=True)
        else:
            rs_helper_ble.ble_connect_DUT_as_master(ble_dut=ble_dut, ble_remote=ble_remote, ble_dut_address=ble_dut_address, ble_remote_address=ble_remote_address, smp_flag=False)

    def dut_as_slave(self, ble_dut, ble_remote, ble_dut_address, smp_flag, rs_helper_ble, skip_pairing=False):
        if smp_flag:
            rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_remote, ble_dut_address=ble_dut_address, smp_flag=True, skip_pairing=skip_pairing)
        else:
            rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_remote, ble_dut_address=ble_dut_address, smp_flag=False, skip_pairing=skip_pairing)

#below apis are going to be used in multi connection test cases to initiate master connection
def master_conn(ble_dut, ble_dut_address, s_remote, conn_count, rs_helper_ble):
    s_remote_addr = rs_helper_ble.ble_advertise_on_remote(adv_device=s_remote, ble_dut_address=ble_dut_address)
    logger().info(f"\n\n ** Initiating a {conn_count} connection with slave remote 1 {s_remote_addr}**\n\n")
    rs_helper_ble.ble_scanning_on_dut(scan_device=ble_dut, ble_client_address=s_remote_addr, timeout=60)
    rs_helper_ble.ble_stop_scanning_on_dut(scan_device=ble_dut)
    time.sleep(5)
    rs_helper_ble.ble_connect_DUT_as_master(ble_dut=ble_dut, ble_remote=s_remote, ble_dut_address=ble_dut_address,
                                                    ble_remote_address=s_remote_addr, smp_flag=False)
    
#below apis are going to be used in multi connection test cases to initiate slave connection       
def slave_conn(ble_dut, ble_dut_address, m_remote, conn_count, rs_helper_ble):
    rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
    m_remote_add = rs_helper_ble.ble_scanning_on_remote(scan_device=m_remote, bt_dut_address=ble_dut_address)
    rs_helper_ble.ble_stop_scanning_on_remote(scan_device=m_remote, bt_dut_address=ble_dut_address)
    logger().info(f"\n\n ** Initiating a {conn_count} connection with Master remote 1 {m_remote_add}**\n\n")
    rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=m_remote, ble_dut_address=ble_dut_address,
                                                    smp_flag=True)
    
#@pytest.mark.skip #test case is not completely implemented as need support from test agent team for MIC error
def test_5_remote_2m_3s_conn_reconn_c91282(ble_dut, ble_clients, rs_helper_ble):
    #test case to verify connection stability with 3 master connections and 2 slave connections
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/HCI_log_test_C91302_ble_connection_stability_dut_as_master.log_{int(time.time())}"):
            connection_time = 5
            ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut, bond_info=0, set_smp=0)
            for itr_count in range(0, 1):
                logger().info(f"\n\n **** Iteration no : {itr_count} ****\n\n")
    
                ble_remote_address_m1 = DUT_as_slave_connection(ble_dut=ble_dut, ble_client=ble_clients[0],
                                                                ble_dut_address=ble_dut_address,
                                                                rs_helper_ble=rs_helper_ble, device_num=1,
                                                                itr_count=itr_count)

                ble_remote_address_m2 = DUT_as_slave_connection(ble_dut=ble_dut, ble_client=ble_clients[1],
                                                                ble_dut_address=ble_dut_address,
                                                                rs_helper_ble=rs_helper_ble, device_num=2,
                                                                itr_count=itr_count, restart_bt_service = False, register_agent = False)

                ble_remote_address_s1 = DUT_as_master_connection(ble_dut=ble_dut, ble_client=ble_clients[2],
                                                                    ble_dut_address=ble_dut_address,
                                                                    rs_helper_ble=rs_helper_ble, device_num=3,
                                                                    itr_count=itr_count, restart_bt_service = False, register_agent = False, index = 0)

                ble_remote_address_s2 = DUT_as_master_connection(ble_dut=ble_dut, ble_client=ble_clients[3],
                                                                    ble_dut_address=ble_dut_address,
                                                                    rs_helper_ble=rs_helper_ble, device_num=4,
                                                                    itr_count=itr_count, restart_bt_service = False, register_agent = False, index = 1)

                ble_remote_address_s3 = DUT_as_master_connection(ble_dut=ble_dut, ble_client=ble_clients[4],
                                                                    ble_dut_address=ble_dut_address,
                                                                    rs_helper_ble=rs_helper_ble, device_num=5,
                                                                    itr_count=itr_count, restart_bt_service = False, register_agent = False, index = 2)

                time.sleep(connection_time)

                ble_disconnect(ble_dut=ble_dut, ble_client=ble_clients[0], ble_dut_address=ble_dut_address,
                                rs_helper_ble=rs_helper_ble, device_num=1)

                ble_disconnect(ble_dut=ble_dut, ble_client=ble_clients[1], ble_dut_address=ble_dut_address,
                                rs_helper_ble=rs_helper_ble, device_num=2)
                
                
                # ble_disconnect(ble_dut=ble_dut, ble_client=ble_clients[2], ble_dut_address=ble_dut_address,
                #                 rs_helper_ble=rs_helper_ble, device_num=3)

                # ble_disconnect(ble_dut=ble_dut, ble_client=ble_clients[3], ble_dut_address=ble_dut_address,
                #                 rs_helper_ble=rs_helper_ble, device_num=4)

                # ble_disconnect(ble_dut=ble_dut, ble_client=ble_clients[4], ble_dut_address=ble_dut_address,
                #                 rs_helper_ble=rs_helper_ble, device_num=5)
    
                rs_helper_ble.ble_disconnect_from_DUT(ble_dut=ble_dut, ble_remote_address=ble_remote_address_s1, ble_dut_address=ble_dut_address, start_adv = False, timeout=10)
                rs_helper_ble.ble_disconnect_from_DUT(ble_dut=ble_dut, ble_remote_address=ble_remote_address_s2, ble_dut_address=ble_dut_address, start_adv = False, timeout=10)
                rs_helper_ble.ble_disconnect_from_DUT(ble_dut=ble_dut, ble_remote_address=ble_remote_address_s3, ble_dut_address=ble_dut_address, start_adv = False, timeout=10)
                
                ble_clients[0].interfaces.bluetooth.close()
                ble_clients[1].interfaces.bluetooth.close()
                ble_clients[2].interfaces.bluetooth.close()
                ble_clients[3].interfaces.bluetooth.close()
                ble_clients[4].interfaces.bluetooth.close()

    except Exception as e:
        assert False, "Test case failed with Excepton {}".format(str(e))
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        ble_clients[0].interfaces.bluetooth.close()
        ble_clients[1].interfaces.bluetooth.close()
        ble_clients[2].interfaces.bluetooth.close()
        ble_clients[3].interfaces.bluetooth.close()
        ble_clients[4].interfaces.bluetooth.close()
        try:
            rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address,
            ble_remotes={ble_clients[0]: BleDeviceState.advertising})
            # rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address,
            #                           ble_remotes={ble_client: BleDeviceState.advertising})
        except Exception as e:
            logger().info(f"\n\nTest case failed with Excepton {str(e)} \n\n")

def ble_disconnect(ble_dut, ble_client, ble_dut_address, rs_helper_ble, device_num):
    rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address)
    logger().info(f"\n\n **** Device {device_num} disconnected ****\n\n")


def DUT_as_slave_connection(ble_dut, ble_client, ble_dut_address, rs_helper_ble, device_num, itr_count, restart_bt_service = True, register_agent = True):

    logger().info(f"\n\n **** DUT as slave device no : {device_num} ****\n\n")
    rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
    rs_helper_ble.ble_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address, restart_bt_service=restart_bt_service, register_agent=register_agent )
    rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
    rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address,
                                           smp_flag=False )
    return 'success'



def DUT_as_master_connection(ble_dut, ble_client, ble_dut_address, rs_helper_ble, device_num, itr_count,
                             ble_remote_address=None, restart_bt_service = True, register_agent = True, index=0):

    logger().info(f"\n\n **** DUT as master device no : {device_num} ****\n\n")
    ble_remote_address = rs_helper_ble.ble_advertise_on_remote(adv_device=ble_client,
                                                               ble_dut_address=ble_dut_address, restart_bt_service=restart_bt_service, register_agent=register_agent,index = index )
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
                                            ble_remote_address=ble_remote_address, smp_flag=False)
    return ble_remote_address

