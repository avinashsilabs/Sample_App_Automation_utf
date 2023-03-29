import time
import pytest
import re
from utf.interfaces.bluetooth import BLEDeviceState
import threading
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryLevelCharacteristic
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryService
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService, \
    HeartRateControlPointCharacteristic
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import BodySensorLocationCharacteristic
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, \
    RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap, RS9116BTFeatureBitMap


def logger():
    return get_logger(__name__)

"""
    * setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI
    Author: 
        NandanBaban.Patil@silabs.com
"""

class BleDeviceState():
    advertising  = 1
    scanning = 2
    initiating = 4
    connected = 8
    standby = 0

class ble_gatt():
    def __init__(self, gatt_server=None, gatt_client=None):
        super().__init__()
        self.gatt_server=gatt_server
        self.gatt_client=gatt_client
        self.data = "LzY0"

    def add_service(self, service_uuid):
        logger().info(f"\n\n ***** Configuring ble GATT service {hex(service_uuid)} in DUT ***** \n\n")
        self.gatt_server.interfaces.wifi.ble_add_service(uid=hex(service_uuid))

    def add_characteristic(self, characteristic_uuid):
        logger().info(f"\n\n ***** Configuring ble GATT characteristic {hex(characteristic_uuid)} in DUT ***** \n\n")
        self.gatt_server.interfaces.wifi.ble_add_char_serv_att(uid=hex(characteristic_uuid))

    def service_discovery(self, service_uuid, char_uuid):
        # resolving charecteristic
        logger().info("\n\n ***** Performing GATT profile discovery on Remote (raspi) ***** \n\n\n")
        services, chars = self.gatt_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(services) > 0, "Unable to fetch services"
        assert len(chars) > 0, "Unable to get characteristics list from ble_client"

        char_path, char_props = self.gatt_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=services,
                                                                                            service_uid=service_uuid,
                                                                                            char_uid=char_uuid)
        assert char_path is not None, "Failed to discover chracteristics"
        assert len(char_props) > 0, "Failed to discover characteristics properties"
        return char_path

    def gatt_read(self, char_path, data):
            # read value
            result = self.gatt_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            assert result == data, "Failed to read data {}".format(data)
            logger().info("\n *** read response : {}\n\n".format(result))

    def gatt_notify_tx(self, char_path, char_uuid, notify_time=30, data=None):
        # subscribe to notifications
        logger().info("\n\n\n ***** Enabling Notification on Remote (raspi) ***** \n\n\n")
        self.gatt_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        self.gatt_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path, char_uid=char_uuid)

        sw = Stopwatch()
        while sw.elapsed_sec < notify_time:
            self.gatt_server.interfaces.bluetooth.ble_notify_custom_value(data=data)
            time.sleep(1)

        logger().info("\n\n\n ***** validating Received notifications on Remote *****\n\n")
        notifications = self.gatt_client.interfaces.bluetooth.gatt_adapter.notifications[char_uuid]
        logger().info("\n * NOtifications: \n {} \n\n".format(notifications))
        assert len(notifications) > 0, "received data is empty"
        assert notifications[0] == data, "failed to fetch data"

class gatt_remote_discovery_thread(threading.Thread):
    def __init__(self, gatt_obj, service_uuid, char_uuid, test_time):
        super().__init__()
        self.gatt_obj=gatt_obj
        self.service_uuid=service_uuid
        self.char_uuid=char_uuid
        self.test_time=test_time

    def continuous_service_discovery(self):
        sw = Stopwatch()
        while sw.elapsed_sec < self.test_time:
            logger().info("\n\n\n *** Performing service discovery on remote *** \n\n\n")
            self.gatt_obj.service_discovery(service_uuid=self.service_uuid, char_uuid=self.char_uuid)
            time.sleep(15)

    def run(self):
        self.exception = None
        try:
            self.continuous_service_discovery()
        except BaseException as e:
                self.exception = e

    def join(self):
        threading.Thread.join(self)
        if self.exception:
            raise self.exception

class gatt_read_thread(threading.Thread):
    def __init__(self, gatt_obj, char_path, test_time, data):
        super().__init__()
        self.gatt_obj=gatt_obj
        self.char_path=char_path
        self.test_time=test_time
        self.data=data

    def continuous_read(self):
        sw = Stopwatch()
        while sw.elapsed_sec < self.test_time:
            logger().info("\n\n\n *** Performing read operation on remote *** \n\n\n")
            self.gatt_obj.gatt_read(char_path=self.char_path, data=self.data)
            time.sleep(10)

    def run(self):
        self.exception = None
        try:
            self.continuous_read()
        except BaseException as e:
            self.exception = e

    def join(self):
        threading.Thread.join(self)
        if self.exception:
            raise self.exception
                
class gatt_update_conn_param_thread(threading.Thread):
    def __init__(self, ble_dut, ble_client_address, min_interval=36, max_interval=36, latency=0, supervision_timeout=3200):
        super().__init__()
        self.min_interval = min_interval
        self.max_interval = max_interval
        self.latency = latency
        self.supervision_timeout = supervision_timeout
        self.ble_dut=ble_dut
        self.ble_client_address = ble_client_address
    
    def update_conn_param(self):    
        logger().info("\n\n\n *** Updating connection parameter *** \n\n\n")
        self.ble_dut.interfaces.bluetooth.ble_update_connect_params(ble_remote_dev_address=self.ble_client_address, min_int=self.min_interval, max_int=self.max_interval, latency=self.latency, supervision_timeout=self.supervision_timeout)
            
    def run(self):
        self.exception = None
        try:
            self.update_conn_param()
        except BaseException as e:
            self.exception = e

    def join(self):
        threading.Thread.join(self)
        if self.exception:
            raise self.exception

class gatt_notify_tx_thread(threading.Thread):
    def __init__(self, gatt_obj, char_path, char_uuid, notify_time, data):
        super().__init__()
        self.gatt_obj=gatt_obj
        self.char_path=char_path
        self.char_uuid=char_uuid
        self.notify_time=notify_time
        self.data=data
    def continuous_notify_tx(self):
        self.gatt_obj.gatt_notify_tx(char_path=self.char_path, char_uuid=self.char_uuid, notify_time=self.notify_time, data=self.data)
            
    def run(self):
        self.exception = None
        try:
            self.continuous_notify_tx()        
        except BaseException as e:
            self.exception = e

    def join(self):
        threading.Thread.join(self)
        if self.exception:
            raise self.exception

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

#test case to verify positive case GATT notification without DLE 20bytes tx, DUT is performing BLE GATT server
def test_gatt_notifcations_without_DLE_20byte_C91289(ble_dut, ble_client, rs_helper_ble):
    service_uuid = "0000180d-0000-1000-8000-00805f9b34fb" #HeartRate Service
    char_uuid = "0000180f-0000-1000-8000-00805f9b34fb"
    data = "sAmPe_TeXtsAmPe_TeXt" #20bytes of data
    
    gatt_obj = ble_gatt(gatt_server=ble_dut, gatt_client=ble_client)
    
    try:
        # Configuring BLE Server on DUT
        ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
        gatt_obj.add_service(service_uuid=0x180D) #adding heartrate Service
        gatt_obj.add_characteristic(characteristic_uuid=0x180F)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x180F, data=data)

        # Establishing BLE connection with DUT as slave
        rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
        rs_helper_ble.ble_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
        rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
        rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, smp_flag=True)
        
        #resolving charecteristic
        char_path = gatt_obj.service_discovery(service_uuid=service_uuid, char_uuid=char_uuid)
        
        # reading value on characterisics from remote (GATT_client)
        gatt_obj.gatt_read(char_path=char_path, data=data)

        # subscribe to notifications
        gatt_obj.gatt_notify_tx(char_path=char_path, char_uuid=char_uuid, notify_time=60, data=data)

        rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, start_adv=False)
    except Exception as e:
        assert False, "Test case failed with exception: {}".format(str(e))
    else:
        logger().info("\n\n\n *** Test case is passed successfully..! ***")
    finally:
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_client:BleDeviceState.standby})

#test case to verify positive case GATT notification with DLE 230 bytes tx, DUT is performing BLE GATT server
def test_gatt_notifcations_with_DLE_230byte_C91290(ble_dut, ble_client, rs_helper_ble):
    service_uuid = "0000180d-0000-1000-8000-00805f9b34fb" #HeartRate Service
    char_uuid = "0000180f-0000-1000-8000-00805f9b34fb"
    data = "testwenbytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybyte1sofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofybytesatatestw"

    gatt_obj = ble_gatt(gatt_server=ble_dut, gatt_client=ble_client)

    try:
        # Configuring BLE Server on DUT
        ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
        gatt_obj.add_service(service_uuid=0x180D) #adding heartrate Service
        gatt_obj.add_characteristic(characteristic_uuid=0x180F)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x180F)

        # Establishing BLE connection with DUT as slave
        rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
        rs_helper_ble.ble_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
        rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
        rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, smp_flag=True)

        #resolving charecteristic
        char_path = gatt_obj.service_discovery(service_uuid=service_uuid, char_uuid=char_uuid)

        # reading value on characterisics from remote (GATT_client)
        ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

        # subscribe to notifications
        gatt_obj.gatt_notify_tx(char_path=char_path, char_uuid=char_uuid, notify_time=60, data=data)

    except Exception as e:
        assert False, "Test case failed with exception: {}".format(str(e))
    else:
        logger().info("\n\n\n *** Test case is passed successfully..! ***")
    finally:
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_client:BleDeviceState.standby})

#test case to verify positive case GATT notification without DLE 20bytes tx with other procedures, DUT is performing BLE GATT server
def test_gatt_notifcations_with_other_procedure_20byte_C91293(ble_dut, ble_client, rs_helper_ble):
    service_uuid = "0000180d-0000-1000-8000-00805f9b34fb" #HeartRate Service
    char_uuid = "0000180f-0000-1000-8000-00805f9b34fb"
    data = "sAmPe_TeXtsAmPe_TeXt" #20bytes of data

    gatt_obj = ble_gatt(gatt_server=ble_dut, gatt_client=ble_client)

    try:
        # Configuring BLE Server on DUT
        ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut, set_smp=1)
        
        gatt_obj.add_service(service_uuid=0x180D) #adding heartrate Service
        gatt_obj.add_characteristic(characteristic_uuid=0x180F)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x180F, data=data)

        # Establishing BLE connection with DUT as slave
        rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
        #rs_helper_ble.ble_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address,
                                                                            service_classes=[HeartRateService])
        time.sleep(10)
        assert ble_client_address, f"Unable to get ble_client_address"
        rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)
        rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, smp_flag=True)

        #performing service discovery on remote
        char_path = gatt_obj.service_discovery(service_uuid=service_uuid, char_uuid=char_uuid)
        
        #gatt_obj.gatt_read(char_path=char_path, data=data)
        test_time=120

        service_discovery = gatt_remote_discovery_thread(gatt_obj=gatt_obj, service_uuid=service_uuid, char_uuid=char_uuid, test_time=test_time)
        notify_tx = gatt_notify_tx_thread(gatt_obj=gatt_obj, char_path=char_path, char_uuid=char_uuid, notify_time=test_time, data=data)
        update_param = gatt_update_conn_param_thread(ble_dut=ble_dut, ble_client_address=ble_client_address, min_interval=36, max_interval=36, latency=0, supervision_timeout=3200,)
        read = gatt_read_thread(gatt_obj=gatt_obj, char_path=char_path, test_time=test_time, data=data)

        service_discovery.start()
        notify_tx.start()
        update_param.start()
        read.start()            
        try:
            service_discovery.join()
            notify_tx.join()
            update_param.join()
            read.join()
        except Exception as e:
            assert False,"Got Exception: {}".format(str(e))

        rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, start_adv=False)

    except Exception as e:
        assert False, "Test case failed with exception: {}".format(str(e))
    else:
        logger().info("\n\n\n *** Test case is passed successfully..! ***")
    finally:
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_client:BleDeviceState.standby})

def test_negative_write_C91306(ble_dut, ble_client, rs_helper_ble):
    #test case to verify negative scinario of performing write operaion on read only characteristic
    try:
        ble_dut_address=rs_helper_ble.ble_gatt_start(ble_dut=ble_dut)
        assert ble_dut_address, "Unable to find ble_dut_address"

        rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address,
                                                                            service_classes=[HeartRateService])
        assert ble_client_address, f"Unable to get ble_client_address"
        time.sleep(5)
        rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_client, bt_dut_address=ble_dut_address)

        #initiating a connection from remote
        rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_client, ble_dut_address=ble_dut_address, smp_flag=False)

        # resolve HeartRate profile
        start_handle, end_handle = ble_dut.interfaces.wifi.ble_get_profile_async(ble_remote_dev_address=ble_client_address,
                                                                              uuid=int(HeartRateService.UUID, 16))
        assert start_handle is not None
        assert end_handle is not None

        # resolve characteristics of HeartRate profile
        uuids, write_handles, char_properties = ble_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=ble_client_address, start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))
        logger().info(f"UUID's are:{uuids}\nwrite_handles:{write_handles}")

        assert BodySensorLocationCharacteristic.Sensor_Location_UUID in uuids, "Unable to find BodySensor uuid"
        index = uuids.index(BodySensorLocationCharacteristic.Sensor_Location_UUID)

        assert char_properties[index].isdigit(), "Character property found is not an integer"
        assert BodySensorLocationCharacteristic.prop_int == int(char_properties[index]), "Invalid character property found"

        write_handle = int(write_handles[index], 16)
        assert write_handle > 0, "Unable to get write handle for configured service"

        # read value
        logger().info("Getting attribute value for configured service")
        att_value = ble_dut.interfaces.wifi.ble_get_att_value_async(ble_remote_dev_address=ble_client_address,
                                                                 char_property=write_handle)
    
        assert int(att_value) > 0, "Attribute value not found"
        logger().info(f"Attribute Value is:{att_value}")

        try:
            ble_dut.interfaces.wifi.ble_set_att_value_async(
                ble_remote_dev_address=ble_client_address,
                char_property=(write_handle + 1),
                value=3,
            )
        except Exception as e:
            if "0x4a0e" in str(e):
                logger().info("\n\n\n *** Got expected Exception, while performing write operation on read only characteristic..! ***\n\n\n")
        else:
            assert False, "Didn't found any error while performing write operation on read only characteristic"

    except Exception as e:
        assert False, "Test case failed with exception: {e}".format(str(e))
    else:
        logger().info("\n\n\n *** Test case is passed successfully..! ***")
    finally:
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address, ble_remotes={ble_client:BleDeviceState.standby})