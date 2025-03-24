import time
import pytest
import re
import string
import random
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import (BodySensorLocationCharacteristic,
                                                                                HeartRateControlPointCharacteristic,
                                                                                HeartRateMeasurementCharacterstic)
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService

from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertService
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertLevelCharacteristic
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
import os
import threading


def logger():
    return get_logger(__name__)


lock = threading.Lock()
"""
    setup requirement:
        1. DUT(917-SDK)
        2. EFR32
        3. Raspberry PI4

        Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Enable the wlan and bt power save mode in dut after the connection
        3. Initiates ble in DUT 
        4. Connect to the remote device/connect to the dut

    Author: Bhuvaneswari
"""


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                        Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                              Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                                   Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                               Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
]


class Ble_Data_Transfer:

    def __init__(self, ble_dut, ble_client, sl_collections, set_local_name="ble_set_name"):
        self.ble_client_address2 = None
        self.ble_client_address1 = None
        self.ble_dut = ble_dut
        self.ble_client = ble_client
        self.sl_collections = sl_collections
        self.set_local_name = set_local_name
        self.ble_dut_address = None
        self.ble_client_address = None
        self.scan_state=None

    def add_service(self, service_uuid):
        logger().info(f"***** Configuring ble GATT service {hex(service_uuid)} in DUT *****")
        self.ble_dut.interfaces.wifi.ble_add_service(uid=hex(service_uuid))

    def add_characteristic(self, characteristic_uuid):
        logger().info(f"***** Configuring ble GATT characteristic {hex(characteristic_uuid)} in DUT *****")
        self.ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=hex(characteristic_uuid))

    def add_char_value(self, value):
        logger().info(f"***** Configuring ble GATT characteristic value {value} in DUT *****")
        self.ble_dut.interfaces.wifi.ble_add_char_serv_att_value(value=value)

    def ble_gatt_init(self, set_smp=1):
        # Initializing DUT BLE Device
        logger().info("start ble GATT service in DUT")
        self.ble_dut_address = self.ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp)
        self.ble_dut.interfaces.bluetooth.ble_set_cap_data(remote_addr_type=0, smp_io_cap=3, smp_auth_req_bonding=1,
                                                           smp_auth_req_mitm=1, smp_auth_req_sc=0,
                                                           smp_max_enc_key_size=16,
                                                           smp_local_oob_data_flag_not_present=0, smp_enc_key=1,
                                                           smp_id_key=1, smp_sign_key=1)
        assert self.ble_dut_address, "Unable to find ble_dut_address"
        return self.ble_dut_address

    def set_local_get_local_name_validation(self):
        logger().info(f"set local name task")
        logger().info(f"Setting BLE local name:{self.set_local_name}")
        time.sleep(3)
        self.ble_dut.interfaces.wifi.bt_set_local_name(self.set_local_name)
        status = self.ble_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f"Get local name : {status}")
        assert status == self.set_local_name, "Set local name and get local name not match"

    def advertising_dut(self, adv_status=None):
        logger().info("***** Advertising from DUT *****")
        self.ble_dut.interfaces.wifi.ble_start_advertising()
        # dut_state = int(self.ble_dut.interfaces.wifi.ble_get_device_state())
        # logger().info(f"DUT Advertising Status :{dut_state}")
        # assert dut_state == adv_status#9
        logger().info("***** DUT Advertising is Successful *****")

    def stop_advertising_dut(self):
        logger().info("***** Stop advertising from DUT *****")
        self.ble_dut.interfaces.wifi.ble_stop_advertising()
        dut_state = int(self.ble_dut.interfaces.wifi.ble_get_device_state())
        logger().info(f"DUT Stop Advertising Status :{dut_state}")

    def advertising_remote(self, service=None):
        logger().info("***** Advertising from Remote (raspi) *****")
        if service is None:
            logger().info(f"***** Start advertising from Remote with SMP and without service *****")
            self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=self.ble_dut_address)
        else:
            logger().info(f"***** Start advertising from Remote with SMP and {service} service *****")
            self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=self.ble_dut_address, service_classes=[service])

        assert self.ble_client_address is not None, "Unable to fetch bluetooth address from Remote device"
        logger().info(f"Advertised remote BLE device")
        return self.ble_client_address

    def stop_advertising_remote(self):
        self.ble_client.interfaces.bluetooth.stop_advertising()

    def power_save(self):
        logger().info("***** Wlan and BLE Power Save from DUT *****")
        self.ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        self.ble_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

    def check_device_state_on_rasp(self):
        status = self.ble_client.interfaces.bluetooth.get_connection_status(self.ble_dut_address)
        logger().info(f"Connection status in remote device '{self.ble_client.name}' is:{status}")
        assert status, f"Remote device '{self.ble_client.name}' is not connected to DUT"
        return status

    def check_device_state_on_dut(self):
        state = self.ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
        return state_int

    def scan_from_dut(self):
        scan_result = ""
        logger().info("Start scanning....")
        # Start scanning and connect to BLE client
        self.ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=self.ble_client_address)
        self.scan_state = True
        time.sleep(30)
        events = self.ble_dut.interfaces.bluetooth.get_async_events()
        device_found = False
        for event in events:
            if str(self.ble_client_address) in event.event_data:
                logger().info(f"{self.ble_client_address} device found successfully")
                device_found = True
                break
        assert device_found, "Failed to find client BT address...."
        logger().info(f"Found BLE client address: {self.ble_client_address}")
        logger().info("Remote device found in scan results, BLE scanning is successful")
        time.sleep(2)
        state = self.ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        if state_int == 2:
            logger().info("Device is scanning status try to stop scanning")
            self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
            self.scan_state = False

        return self.ble_client_address

    def scan_conn_from_dut_device(self):
        self.scan_from_dut()
        self.power_save()
        timeout = 120
        retries = 3
        for retry in range(retries):
            try:
                logger().info(f"Initiating connection, this can take up to {timeout} seconds....")
                self.ble_dut.interfaces.bluetooth.ble_connect(
                    ble_remote_dev_address=self.ble_client_address,
                    timeout=timeout
                )
                time.sleep(40)
                logger().info("Checking connection status of BLE")
                state = self.ble_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
                logger().info("BLE Connection success")
                break
            except Exception as ex:
                logger().info(f"Exception occurred while connecting to BLE device: {str(ex)}")
                logger().info(f"BLE connection failed with retries {retry + 1}")
                if retry == retries - 1:
                    raise

    def scan_from_remote_devices(self):
        logger().info("***** Scan from DUT  *****")
        logger().info("Start scanning")
        self.ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=self.ble_client_address)
        logger().info(f"Remote device found in scan results ,BLE scanning is successful")

    def scan_conn_from_remote_device(self, service=None):
        logger().info("***** Scan and Connect from Remote (raspi) *****")

        # Start Scan from Remote
        if service is None:
            logger().info("Scan with SMP and without service from Remote")
            self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=self.ble_dut_address
            )
        else:
            logger().info(f"Scan with SMP and with service: {service} from Remote")
            self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=self.ble_dut.interfaces.wifi.ble_address, service_classes=[service]
            )
        assert self.ble_client_address, "The client address is not found"
        time.sleep(5)
        self.ble_client.interfaces.bluetooth.stop_scanning()

        # Verify Device in Scan List
        logger().info("Verifying device in scan list...")
        found_devices = self.ble_client.interfaces.bluetooth.get_devices()
        for device in found_devices:
            if device == self.ble_dut.interfaces.wifi.ble_address:
                logger().info(f"Device found in scan list:{device}")
                break

        assert self.ble_dut.interfaces.wifi.ble_address in found_devices, "Failed to find DUT address in scan list"
        assert (found_devices[self.ble_dut.interfaces.wifi.ble_address] ==
                self.ble_dut.interfaces.wifi.ble_advertising_data), "Failed to find DUT in scan list"

        logger().info("Device found in scan list")
        self.ble_dut.interfaces.wifi.ble_scanning = False
        self.ble_dut.interfaces.wifi.ble_advertising = False

        # Connect to DUT
        logger().info("Connect start from remote to DUT")
        retries = 3
        for retry in range(retries):
            try:
                self.ble_client.interfaces.bluetooth.pair_and_connect(self.ble_dut.interfaces.wifi.ble_address)
                time.sleep(40)

                # Check Connection Status
                logger().info("Checking connection status of BLE")
                assert self.check_device_state_on_dut() == BLEDeviceState.Connected
                break

            except Exception as ex:
                logger().info(f"Exception occurred while connecting to BLE device: {str(ex)}")
                logger().info(f"BLE connection failed with retries {retry + 1}")

                if retry == retries - 1:
                    raise

        return self.ble_client_address

    def service_discovery_on_dut(self, service_uid=None, char_uid=None):
        time.sleep(3)
        servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        time.sleep(5)
        logger().info(f"{servs} {chars}")
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"

        char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs,
            service_uid=service_uid,
            char_uid=char_uid)
        time.sleep(5)
        logger().info(f"{char_props}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
        logger().info("------CHARACTERISTICS----")
        return char_path, char_props

    def get_all_profiles_remote(self):
        uuids = self.ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=self.ble_client_address)
        logger().info(f"UUIds {uuids}")
        assert len(uuids) > 0, "uuids are empty"

    def service_discovery_on_remote(self, service_uuid=None, char_uuid=None, characteristic=None):
        logger().info("\n\n ***** Performing GATT profile discovery on Remote (raspi)  ***** \n\n\n")
        # get all profiles
        uuids = self.ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=self.ble_client_address,
                                                                    async_timeout=60)
        logger().info(f"UUIds {uuids}")
        assert len(uuids) > 0, "uuids are empty"
        #  resolve profile
        start_handle, end_handle, data = self.ble_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=self.ble_client_address,
            uuid=int(service_uuid, 16),
            async_timeout=60)
        logger().info(f"start_handle:{start_handle}, end_handle:{end_handle}")
        assert start_handle is not None
        assert end_handle is not None
        #
        char_uuids, write_handles, char_properties = self.ble_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=self.ble_client_address,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
            async_timeout=60)
        logger().info(
            f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
            f"{char_properties}")

        assert char_uuid in char_uuids, "Unable to find {} uuid".format(char_uuid)
        index = char_uuids.index(char_uuid)
        logger().info(f"UUID's are:{char_uuids}")
        logger().info(f"write_handles:{write_handles}")
        logger().info(f"index:{index}")
        assert char_properties[index].isdigit(), "Character property found is not an integer"
        assert characteristic.prop_int == int(char_properties[index]), "Invalid character property found"

        write_handle = int(write_handles[index], 16)
        logger().info(f"write_handle:{write_handle}")
        assert write_handle > 0, "Unable to get write handle for configured service"

        return write_handle

    def configure_buffer_mode(self, mode=None, count=None):
        logger().info(f"*******Configure Buffer Mode:{mode} and Buffer count:{count} ****************")
        self.ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=self.ble_client_address,
                                                                buffer_mode=mode,
                                                                buffer_count=count)
        logger().info(f"*******Configure Buffer Mode:{mode} and Buffer count:{count} Success ****************")

    def disconnect_form_dut(self, ble_client=None):
        logger().info("\n\n\n ***** Disconnect from DUT ***** \n\n\n")
        state = self.ble_dut.interfaces.bluetooth.ble_get_device_state()
        if state == 0:
            logger().info(f"Already device disconnection status in remote' {ble_client.name}' is:{state}")
        else:
            time.sleep(2)
            self.ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
            time.sleep(2)
            state = self.ble_dut.interfaces.bluetooth.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            logger().info(f"DisConnection status in remote device '{ble_client.name}' is:{state}")
        time.sleep(5)

    def disconnect_from_remote(self, ble_client=None):
        logger().info("\n\n\n ***** Disconnect from Remote(raspi) ***** \n\n\n")
        status = ble_client.interfaces.bluetooth.get_connection_status(self.ble_dut_address)
        if status == 0:
            logger().info(f"Already DisConnection status in remote device '{ble_client.name}' is:{status}")
        else:
            ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)
            status = ble_client.interfaces.bluetooth.get_connection_status(self.ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            logger().info(f"DisConnection status in remote device '{ble_client.name}' is:{status}")

    def clear_dut(self, ble_client=None):
        logger().info("Checking connection status of BLE")
        state = self.ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        if state_int == 8:
            logger().info("Device is connected status try to disconnect")
            self.disconnect_form_dut()
        elif state_int == 2:
            logger().info("Device is scanning status try to stop scanning")
            self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
        elif state_int == 1:
            logger().info("Device is advertising status try to stop advertising")
            self.ble_dut.interfaces.wifi.ble_stop_advertising()
        # if len(ble_client) >= 2:
        ble_client.interfaces.bluetooth.close()
        logger().info(" *************DUT Clearing Stop Success *******************")

    def ble_master(self, ble_client=None, service=None):
        logger().info(".....Dut as master connection ......")
        # Adv Remote device
        self.ble_client_address1 = self.advertising_remote(service=service)
        # Start scan and connect from dut
        self.scan_conn_from_dut_device()
        return self.ble_client_address1

    def ble_slave(self, adv_status=None, ble_client=None, service=None):
        logger().info(".....Dut as slave connection ......")
        self.ble_dut_address = self.ble_dut.interfaces.wifi.ble_address
        # Set DUT Local name
        self.set_local_get_local_name_validation()
        # Set DUT To Advertising
        self.advertising_dut(adv_status)
        # Power Save Mode WLAN And BLE
        self.power_save()
        # Scan and Connect From Remote Device
        self.ble_client_address2 = self.scan_conn_from_remote_device(service=service)
        return self.ble_client_address2


class WriteWithResponseFunctionality:
    def __init__(self, ble_dut=None, ble_clients=None, ble_client_address=None, write_handle=None, data=None,
                 data_length=None, write_time=None, write_count=None, allocated_mem_addr=None):
        super().__init__()
        self.ble_dut = ble_dut
        self.ble_clients = ble_clients
        self.ble_client_address = ble_client_address
        self.write_handle = write_handle
        self.data = data
        self.data_length = data_length
        self.write_time = write_time
        self.write_count = write_count
        self.allocated_mem_addr = allocated_mem_addr

    def run(self):
        logger().info(f"*******Write With Response Start****************")
        write_data_count = 0
        def write():
            time.sleep(2)
            self.ble_dut.interfaces.bluetooth.ble_set_att_value_async(
                ble_remote_dev_address=self.ble_client_address,
                char_property=self.write_handle, data=self.data, data_length=self.data_length,
                data_address=self.allocated_mem_addr)
            time.sleep(7)

        if self.write_count:
            for i in range(self.write_count):
                with lock:
                    write()
        else:
            sw = Stopwatch()
            while sw.elapsed_sec <= self.write_time:
                with lock:
                    write()
                    write_data_count += 1
        if not self.write_count:
            self.write_count = write_data_count


class WriteWithoutResponseFunctionality:
    def __init__(self, ble_dut=None, ble_clients=None, ble_client_address=None, data=None, data_length=None,
                 write_handle=None, write_time=None, write_count=None, allocated_mem_addr=None,
                 bt_mon_log_file_name=None):
        super().__init__()
        self.ble_dut = ble_dut
        self.ble_clients = ble_clients
        self.ble_client_address = ble_client_address
        self.data = data
        self.data_length = data_length
        self.write_handle = write_handle
        self.write_time = write_time
        self.write_count = write_count
        self.allocated_mem_addr = allocated_mem_addr
        self.bt_mon_log_file_name = bt_mon_log_file_name

    def run(self):
        logger().info(f"*******Write Without Response Start****************")

        def write():
            bt_mon_log_file = self.bt_mon_log_file_name
            time.sleep(2)
            with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file):
                self.ble_dut.interfaces.wifi.ble_set_att_cmd(ble_remote_dev_address=self.ble_client_address,
                                                             handle=self.write_handle, data_length=self.data_length,
                                                             data=self.data, data_address=self.allocated_mem_addr)


                time.sleep(3)

        data_count = 0
        if self.write_count:
            for i in range(self.write_count):
                with lock:
                    time.sleep(2)
                    write()
        else:
            sw = Stopwatch()
            while sw.elapsed_sec <= self.write_time:
                with lock:
                    write()
                    data_count += 1

        if not self.write_count:
            self.write_count = data_count
        logger().info(f"*******Write Without Response End****************")


class TxNotificationFunctionality:
    def __init__(self, ble_dut=None, ble_clients=None, ble_client_address=None, data=None, service_uid=None, char_uid=None,
                 char_path=None, allocated_mem_addr=None):
        super().__init__()
        self.ble_dut = ble_dut
        self.ble_clients = ble_clients
        self.ble_client_address = ble_client_address
        self.data = data
        self.service_uid = service_uid
        self.char_uid = char_uid
        self.char_path = char_path
        self.allocated_mem_addr = allocated_mem_addr
        self.notification_count = 0

    def run(self):
        logger().info("******************** Start TX Notifications functionality ***********************")
        sw = Stopwatch()
        count = 0
        while sw.elapsed_sec < 200:
            with lock:
                self.ble_dut.interfaces.wifi.ble_notify_custom_value(ble_remote_dev_address=self.ble_client_address,
                                                                     data=self.data, data_address=self.allocated_mem_addr)
                time.sleep(6)
                logger().info("******************** Validate Data ********************")
                notifications = self.ble_clients.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
                logger().info(f' *********************** Notification is {notifications} ***********************')
                self.notification_count += 1
                logger().info("DATA RECEIVED ON REMOTE SIDE")
                count += 1


class RxNotificationFunctionality:
    def __init__(self, ble_dut=None, ble_clients=None, ble_client_address=None, data=None, svc=None, charc=None,
                 write_handle=None, enable_notify=1, notify_time=600, rx_notification_count=None):
        super().__init__()
        self.ble_dut = ble_dut
        self.ble_clients = ble_clients
        self.ble_client_address = ble_client_address
        self.data = data
        self.svc = svc
        self.charc = charc
        self.write_handle = write_handle
        self.enable_notify = enable_notify
        self.notify_time = notify_time
        self.rx_notification_count = rx_notification_count

    def run(self):
        sw = Stopwatch()
        def write():
            logger().info("Sending notifications")
            self.ble_clients.interfaces.bluetooth.send_gatt_charc_notification(self.svc, self.charc, self.data)
            logger().info("---------send_gatt_charc_notification-------------")
            time.sleep(7)

        rx_notification_count = 0
        time.sleep(1)
        if self.rx_notification_count:
            for i in range(self.rx_notification_count):
                with lock:
                    write()
        else:
            sw = Stopwatch()
            while sw.elapsed_sec <= self.notify_time:
                with lock:
                    write()
                    rx_notification_count +=1

        if not self.rx_notification_count:
            self.rx_notification_count = rx_notification_count

        logger().info(f"RX_Notification count: {self.rx_notification_count}")


class TxIndicationFunctionality:
    def __init__(self, ble_dut=None, ble_client=None, ble_client_address=None, char_path=None, char_uuid=None,
                 data=None, indication_time=None, data_length=None, allocated_mem_addr=None, handle=None, indication_count=None):
        super().__init__()
        self.ble_dut = ble_dut
        self.ble_client = ble_client
        self.ble_client_address = ble_client_address
        self.char_path = char_path
        self.char_uuid = char_uuid
        self.data = data
        self.indication_time = indication_time
        self.data_length = data_length
        self.allocated_mem_addr = allocated_mem_addr
        self.handle = handle
        self.indication_count = indication_count

    def run(self):
        def write():
            logger().info(f"****** Indication value****************")
            self.ble_dut.interfaces.bluetooth.ble_indicate_value(ble_remote_dev_address=self.ble_client_address,
                                                                 handle=self.handle, data=self.data,
                                                                 data_length=self.data_length,
                                                                 data_address=self.allocated_mem_addr)
            time.sleep(5)

        indication_count = 0
        if self.indication_count:
            for i in range(self.indication_count):
                with lock:
                    write()
        else:
            sw = Stopwatch()
            while sw.elapsed_sec <= self.indication_time:
                with lock:
                    write()
                    indication_count +=1

        if not self.indication_count:
            self.indication_count = indication_count
        logger().info(f"Indication_count: {self.indication_count}")


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_write_without_response_C664436(ble_dut, ble_clients, sl_collections,
                                                                              ble_sniffer):
    bt_mon_log_file_name = (f"reports/test_ble_dut_as_master_and_slave_235_bytes_write_without_response_C664436"
                            f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_write_without_response_C664436")
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init(set_smp=1)
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="ImmediateAlertService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2, service="ImmediateAlertService")
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))

            # get remote device profile
            write_handle1 = ble_obj1.service_discovery_on_remote(service_uuid=ImmediateAlertService.UUID,
                                                                 char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
                                                                 characteristic=ImmediateAlertLevelCharacteristic)
            # Configure buffer modes
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)

            ble_fun1 = WriteWithoutResponseFunctionality(ble_dut, ble_clients=ble_client1,
                                                         ble_client_address=ble_client_address1,
                                                         write_handle=write_handle1, data_length=240, data=data,
                                                         write_count=50, allocated_mem_addr=allocated_mem_addr,
                                                         bt_mon_log_file_name=bt_mon_log_file_name)

            # get remote device profile
            write_handle2 = ble_obj2.service_discovery_on_remote(service_uuid=ImmediateAlertService.UUID,
                                                                 char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
                                                                 characteristic=ImmediateAlertLevelCharacteristic)
            # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            ble_fun2 = WriteWithoutResponseFunctionality(ble_dut, ble_clients=ble_client2,
                                                         ble_client_address=ble_client_address2,
                                                         write_handle=write_handle2, data_length=240, data=data,
                                                         write_count=50, allocated_mem_addr=allocated_mem_addr,
                                                         bt_mon_log_file_name=bt_mon_log_file_name)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)
            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part
            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_CMD") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.write_count/2), "No ATT_WRITE_CMD packets are present"
            logger().info("ATT_WRITE_CMD packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_CMD") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.write_count/2), "No ATT_WRITE_CMD packets are present"
            logger().info("ATT_WRITE_CMD packets are sent successfully")
    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        logger().info(ble_obj1.scan_state)
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        # # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_tx_indication_C664440(ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (f"reports/test_ble_dut_as_master_and_slave_240_bytes_tx_indication_C664440"
                            f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_tx_indication_C664440")

            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            char_path = None
            char_path1 = None
            allocated_mem_addr = None
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()

            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=34)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")

            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="HealthThermometerService")
            time.sleep(60)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            char_path, char_props = ble_obj1.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)

            # Configure Buffer Mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            time.sleep(2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            logger().info(f"****** Indication Start****************")
            ble_client1.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            ble_client1.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                     char_uid=char_uid)
            ble_fun1 = TxIndicationFunctionality(ble_dut, ble_client=ble_client1,
                                                 ble_client_address=ble_client_address1, char_path=char_path,
                                                 char_uuid=char_uid, data=data, data_length=240,
                                                 allocated_mem_addr=allocated_mem_addr, handle=12, indication_count=50)
            char_path1, char_props = ble_obj2.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            time.sleep(2)
            logger().info(f"****** Indication Start****************")
            ble_client2.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path1)
            ble_client2.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path1,
                                                                                     char_uid=char_uid)
            ble_fun2 = TxIndicationFunctionality(ble_dut, ble_client=ble_client2,
                                                 ble_client_address=ble_client_address2, char_path=char_path1,
                                                 char_uuid=char_uid, data=data, data_length=240,
                                                 allocated_mem_addr=allocated_mem_addr, handle=12, indication_count=50)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.indication_count/2), "No ATT_HANDLE_VALUE_IND packets are present"
            logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                   sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.indication_count/2), "No ATT_HANDLE_VALUE_IND packets are present"

            logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        logger().info(ble_obj1.scan_state)
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if char_path:
            logger().info("disabling the notifications")
            ble_client1.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            logger().info("unsubscribe to notifications")
            ble_client1.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        if char_path1:
            logger().info("disabling the notifications")
            ble_client2.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path1)
            logger().info("unsubscribe to notifications")
            ble_client2.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        logger().info("DISCONNECTING THE DEVICES")
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_rx_notification_C664442(ble_dut, ble_clients, sl_collections,
                                                                       ble_sniffer):
    bt_mon_log_file_name = (f"reports/test_ble_dut_as_master_and_slave_240_bytes_rx_notification_C664442"
                            f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_rx_notification_C664442")

            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            write_handle1 = None
            write_handle2 = None
            svc = 'HealthThermometerService'
            charc = 'CustomNotifyCharacteristic'
            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()
            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="HealthThermometerService")
            time.sleep(30)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            write_handle1 = ble_obj1.service_discovery_on_remote(HealthThermometerService.UUID,
                                                                 CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                                 CustomNotifyCharacteristic)
            # # Configure Buffer Mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            logger().info("******************** Start RX Notifications functionality ***********************")
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address1,
                                                           handle=(write_handle1 + 1),
                                                           enable_notify=1)
            time.sleep(2)
            # Get All Profiles
            ble_fun1 = RxNotificationFunctionality(ble_dut, ble_clients=ble_client1,
                                                   ble_client_address=ble_client_address1, data=data, svc=svc,
                                                   charc=charc, write_handle=write_handle1, enable_notify=1,
                                                   rx_notification_count=50)
            write_handle2 = ble_obj2.service_discovery_on_remote(HealthThermometerService.UUID,
                                                                 CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                                 CustomNotifyCharacteristic)
            # # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            logger().info("******************** Start RX Notifications functionality ***********************")
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address2,
                                                           handle=(write_handle2 + 1),
                                                           enable_notify=1)
            time.sleep(3)
            # Get All Profiles
            ble_fun2 = RxNotificationFunctionality(ble_dut, ble_clients=ble_client2,
                                                   ble_client_address=ble_client_address2, data=data, svc=svc,
                                                   charc=charc, write_handle=write_handle2, enable_notify=1,
                                                   rx_notification_count=50)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            logger().info(f"BLE-CLIENT-ADDRESS1:{ble_client_address1}")
            logger().info(f"BLE-CLIENT-ADDRESS2: {ble_client_address2}")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (sniffer_data_df[
                                                                     '+BD Address (LE PKT)'] == f"0x{ble_client_address1.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.rx_notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (sniffer_data_df[
                                                                     '+BD Address (LE PKT)'] == f"0x{ble_client_address2.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.rx_notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        logger().info(ble_obj1.scan_state)
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if write_handle1:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address1,
                                                           handle=(write_handle1 + 1), enable_notify=0)
            time.sleep(2)
        if write_handle2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address2,
                                                           handle=(write_handle2 + 1), enable_notify=0)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_tx_notification_C664444(ble_dut, ble_clients, sl_collections,
                                                                       ble_sniffer):
    bt_mon_log_file_name = (f"reports/test_ble_dut_as_master_and_slave_240_bytes_tx_notification_C664444"
                            f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_tx_notification_C664444")

            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            char_path = None
            char_path1 = None
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()

            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)

            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="HealthThermometerService")
            time.sleep(60)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            char_path, char_props = ble_obj1.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            ble_client1.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            logger().info(f' *********************** subscribe to notifications ***********************')
            ble_client1.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            ble_client1.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=char_path, char_uid=char_uid)

            ble_obj1.configure_buffer_mode(mode=1, count=2)
            time.sleep(5)
            ble_fun1 = TxNotificationFunctionality(ble_dut, ble_clients=ble_client1,
                                                   ble_client_address=ble_client_address1, data=data,
                                                   service_uid=service_uid, char_uid=char_uid,
                                                   allocated_mem_addr=allocated_mem_addr, char_path=char_path)
            char_path1, char_props = ble_obj2.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            ble_client2.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path1)
            logger().info(f' *********************** subscribe to notifications ***********************')
            ble_client2.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path1)
            ble_client2.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=char_path1, char_uid=char_uid)

            # # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            ble_fun2 = TxNotificationFunctionality(ble_dut, ble_clients=ble_client2,
                                                   ble_client_address=ble_client_address2, data=data,
                                                   service_uid=service_uid, char_uid=char_uid,
                                                   allocated_mem_addr=allocated_mem_addr, char_path=char_path1)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if char_path:
            logger().info(f' *********************** unsubscribe to notifications ***********************')
            ble_client1.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            ble_client1.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
            time.sleep(2)
        if char_path1:
            logger().info(f' *********************** unsubscribe to notifications ***********************')
            ble_client2.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path1)
            ble_client2.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_write_without_response_tx_indication_C664447(
        ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_write_without_response_tx_indication_C664447"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_write_without_response_tx_indication_C664447")
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr =None
            char_path1 = None
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)

            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init(set_smp=1)
            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=34)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="ImmediateAlertService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="HealthThermometerService")
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            # get remote device profile
            write_handle1 = ble_obj1.service_discovery_on_remote(service_uuid=ImmediateAlertService.UUID,
                                                                 char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
                                                                 characteristic=ImmediateAlertLevelCharacteristic)
            # Configure buffer modes
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            ble_fun1 = WriteWithoutResponseFunctionality(ble_dut, ble_clients=ble_client1,
                                                         ble_client_address=ble_client_address1,
                                                         write_handle=write_handle1, data_length=240, data=data,
                                                         write_count=50, allocated_mem_addr=allocated_mem_addr,
                                                         bt_mon_log_file_name=bt_mon_log_file_name)
            char_path1, char_props = ble_obj2.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            logger().info(f"****** Indication Start****************")
            ble_client2.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path1)
            ble_client2.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path1,
                                                                                     char_uid=char_uid)

            ble_fun2 = TxIndicationFunctionality(ble_dut, ble_client=ble_client2,
                                                 ble_client_address=ble_client_address2, char_path=char_path1,
                                                 char_uuid=char_uid, data=data, indication_count=50, data_length=240,
                                                 allocated_mem_addr=allocated_mem_addr, handle=12)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_CMD") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.write_count/2), "No ATT_WRITE_CMD packets are present"
            logger().info("ATT_WRITE_CMD packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.indication_count/2), "No ATT_HANDLE_VALUE_IND packets are present"
            logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if char_path1:
            logger().info("disabling the notifications")
            ble_client2.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path1)
            logger().info("unsubscribe to notifications")
            ble_client2.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        logger().info("DISCONNECTING THE DEVICES")
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_write_without_response_tx_notification_C664448(
        ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_write_without_response_tx_notification_C664448"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_write_without_response_tx_notification_C664448")
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            char_path = None
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)

            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init(set_smp=1)
            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)

            logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="ImmediateAlertService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2, service="HealthThermometerService")
            time.sleep(30)
            ble_obj1.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            # get remote device profile
            write_handle1 = ble_obj1.service_discovery_on_remote(service_uuid=ImmediateAlertService.UUID,
                                                                 char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
                                                                 characteristic=ImmediateAlertLevelCharacteristic)
            # Configure buffer modes
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            ble_fun1 = WriteWithoutResponseFunctionality(ble_dut, ble_clients=ble_client1,
                                                         ble_client_address=ble_client_address1,
                                                         write_handle=write_handle1, data_length=240, data=data,
                                                         write_count=50, allocated_mem_addr=allocated_mem_addr,
                                                         bt_mon_log_file_name=bt_mon_log_file_name)
            char_path, char_props = ble_obj2.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            ble_client2.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            logger().info(f' *********************** subscribe to notifications ***********************')
            ble_client2.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            ble_client2.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=char_path, char_uid=char_uid)

            # # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            time.sleep(5)
            ble_fun2 = TxNotificationFunctionality(ble_dut, ble_clients=ble_client2,
                                                   ble_client_address=ble_client_address2, data=data,
                                                   service_uid=service_uid, char_uid=char_uid,
                                                   allocated_mem_addr=allocated_mem_addr, char_path=char_path)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_CMD") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.write_count/2), "No ATT_WRITE_CMD packets are present"
            logger().info("ATT_WRITE_CMD packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if char_path:
            logger().info(f' *********************** unsubscribe to notifications ***********************')
            ble_client2.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            ble_client2.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_write_without_response_rx_notification_C664449(
        ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_write_without_response_rx_notification_C664449"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_write_without_response_rx_notification_C664449")

            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            write_handle2 = None
            svc = 'HealthThermometerService'
            charc = 'CustomNotifyCharacteristic'
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)

            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init(set_smp=1)
            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=34)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")
            logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="ImmediateAlertService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2, service="HealthThermometerService")
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            # get remote device profile
            write_handle1 = ble_obj1.service_discovery_on_remote(service_uuid=ImmediateAlertService.UUID,
                                                                 char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
                                                                 characteristic=ImmediateAlertLevelCharacteristic)
            # Configure buffer modes
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            ble_fun1 = WriteWithoutResponseFunctionality(ble_dut, ble_clients=ble_client1,
                                                         ble_client_address=ble_client_address1,
                                                         write_handle=write_handle1, data_length=240, data=data,
                                                         write_count=50, allocated_mem_addr=allocated_mem_addr,
                                                         bt_mon_log_file_name=bt_mon_log_file_name)

            write_handle2 = ble_obj2.service_discovery_on_remote(HealthThermometerService.UUID,
                                                                 CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                                 CustomNotifyCharacteristic)
            # # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            logger().info("******************** Start RX Notifications functionality ***********************")
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address2,
                                                           handle=(write_handle2 + 1),
                                                           enable_notify=1)
            time.sleep(2)
            # Get All Profiles
            ble_fun2 = RxNotificationFunctionality(ble_dut, ble_clients=ble_client2,
                                                   ble_client_address=ble_client_address2, data=data, svc=svc,
                                                   charc=charc, write_handle=write_handle2, enable_notify=1,
                                                   rx_notification_count=50)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_CMD") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.write_count/2), "No ATT_WRITE_CMD packets are present"
            logger().info("ATT_WRITE_CMD packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (sniffer_data_df[
                                                                     '+BD Address (LE PKT)'] == f"0x{ble_client_address2.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.rx_notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if write_handle2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address2,
                                                           handle=(write_handle2 + 1), enable_notify=0)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_tx_indication_write_without_response_C664462(
        ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_tx_indication_write_without_response_C664462"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_tx_indication_write_without_response_C664462")

            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            char_path = None
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()

            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=34)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")

            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2, service="ImmediateAlertService")
            time.sleep(30)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            char_path, char_props = ble_obj1.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            logger().info(f"CHAR-PATH:{char_path}")
            logger().info(f"CHAR-PROPS:{char_props}")
            # Configure Buffer Mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            time.sleep(4)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            logger().info(f"****** Indication Start****************")
            ble_client1.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            ble_client1.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                     char_uid=char_uid)

            ble_fun1 = TxIndicationFunctionality(ble_dut, ble_client=ble_client1,
                                                 ble_client_address=ble_client_address1, char_path=char_path,
                                                 char_uuid=char_uid, data=data, indication_count=50, data_length=240,
                                                 allocated_mem_addr=allocated_mem_addr, handle=12)

            # get remote device profile
            write_handle2 = ble_obj2.service_discovery_on_remote(service_uuid=ImmediateAlertService.UUID,
                                                                 char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
                                                                 characteristic=ImmediateAlertLevelCharacteristic)
            # Configure buffer modes
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            time.sleep(4)
            ble_fun2 = WriteWithoutResponseFunctionality(ble_dut, ble_clients=ble_client2,
                                                         ble_client_address=ble_client_address2,
                                                         write_handle=write_handle2, data_length=240, data=data,
                                                         write_count=50, allocated_mem_addr=allocated_mem_addr,
                                                         bt_mon_log_file_name=bt_mon_log_file_name)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.indication_count/2), "No ATT_HANDLE_VALUE_IND packets are present"
            logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_CMD") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.write_count/2), "No ATT_WRITE_CMD packets are present"
            logger().info("ATT_WRITE_CMD packets are sent successfully")

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if char_path:
            logger().info("disabling the notifications")
            ble_client1.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            logger().info("unsubscribe to notifications")
            ble_client1.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_tx_indication_tx_notification_C664464(
        ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_tx_indication_tx_notification_C664464"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_tx_indication_tx_notification_C664464")

            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            char_path1 = None
            char_path2 = None
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)

            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()
            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=62)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2, service="HealthThermometerService")
            time.sleep(30)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            char_path1, char_props = ble_obj1.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            # Configure Buffer Mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            logger().info(f"****** Indication Start****************")
            ble_client1.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path1)
            ble_client1.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path1,
                                                                                     char_uid=char_uid)

            ble_fun1 = TxIndicationFunctionality(ble_dut, ble_client=ble_client1,
                                                 ble_client_address=ble_client_address1, char_path=char_path1,
                                                 char_uuid=char_uid, data=data, indication_count=50, data_length=240,
                                                 allocated_mem_addr=allocated_mem_addr, handle=12)
            char_path2, char_props = ble_obj2.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            ble_client2.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path2)
            # # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            logger().info(f' *********************** subscribe to notifications ***********************')
            ble_client2.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path2)
            ble_client2.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=char_path2, char_uid=char_uid)
            logger().info(f"CHAR-PATH:{char_path2}")
            logger().info(f"CHAR-UID:{char_uid}")
            time.sleep(5)
            ble_fun2 = TxNotificationFunctionality(ble_dut, ble_clients=ble_client2,
                                                   ble_client_address=ble_client_address2, data=data,
                                                   service_uid=service_uid, char_uid=char_uid,
                                                   allocated_mem_addr=allocated_mem_addr, char_path=char_path2)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.indication_count/2), "No ATT_HANDLE_VALUE_IND packets are present"
            logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if char_path1:
            logger().info("disabling the notifications")
            ble_client1.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path1)
            logger().info("unsubscribe to notifications")
            ble_client1.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
            time.sleep(5)
        if char_path2:
            logger().info(f' *********************** unsubscribe to notifications ***********************')
            ble_client2.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path2)
            ble_client2.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
            time.sleep(5)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_tx_indication_rx_notification_C664465(
        ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_tx_indication_rx_notification_C664465"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_tx_indication_rx_notification_C664465")
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            write_handle2 = None
            char_path = None
            allocated_mem_addr = None
            svc = 'HealthThermometerService'
            charc = 'CustomNotifyCharacteristic'
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()
            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=34)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2, service="HealthThermometerService")
            time.sleep(30)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            char_path, char_props = ble_obj1.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            # Configure Buffer Mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            time.sleep(4)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            logger().info(f"****** Indication Start****************")
            ble_client1.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            ble_client1.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                     char_uid=char_uid)
            ble_fun1 = TxIndicationFunctionality(ble_dut, ble_client=ble_client1,
                                                 ble_client_address=ble_client_address1, char_path=char_path,
                                                 char_uuid=char_uid, data=data, indication_count=50, data_length=240,
                                                 allocated_mem_addr=allocated_mem_addr, handle=12)
            write_handle2 = ble_obj2.service_discovery_on_remote(HealthThermometerService.UUID,
                                                                 CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                                 CustomNotifyCharacteristic)
            # # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            logger().info("******************** Start RX Notifications functionality ***********************")
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address2,
                                                           handle=(write_handle2 + 1),
                                                           enable_notify=1)
            time.sleep(2)
            # Get All Profiles
            ble_fun2 = RxNotificationFunctionality(ble_dut, ble_clients=ble_client2,
                                                   ble_client_address=ble_client_address2, data=data, svc=svc,
                                                   charc=charc, write_handle=write_handle2, enable_notify=1,
                                                   rx_notification_count=50)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.indication_count/2), "No ATT_HANDLE_VALUE_IND packets are present"
            logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (sniffer_data_df[
                                                                     '+BD Address (LE PKT)'] == f"0x{ble_client_address2.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.rx_notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if char_path:
            logger().info("disabling the notifications")
            ble_client1.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            logger().info("unsubscribe to notifications")
            ble_client1.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        if write_handle2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address2,
                                                           handle=(write_handle2 + 1), enable_notify=0)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)

        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)

    
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_tx_notification_write_without_response_C664470(ble_dut, ble_clients,
                                                                                              sl_collections, ble_sniffer):
    bt_mon_log_file_name = (f"reports/test_ble_dut_as_master_and_slave_240_bytes_tx_notification_write_without_response_C664470"
                            f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_tx_notification_write_without_response_C664470")

            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            char_path = None
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()

            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)  
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)  

            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2, service="ImmediateAlertService")
            time.sleep(60)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            char_path, char_props = ble_obj1.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            ble_client1.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            logger().info(f' *********************** subscribe to notifications ***********************')
            ble_client1.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            ble_client1.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=char_path, char_uid=char_uid)
            
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            time.sleep(5)
            ble_fun1 = TxNotificationFunctionality(ble_dut, ble_clients=ble_client1,
                                                   ble_client_address=ble_client_address1, data=data,
                                                   service_uid=service_uid, char_uid=char_uid,
                                                   allocated_mem_addr=allocated_mem_addr, char_path=char_path)
            # get remote device profile
            write_handle2 = ble_obj2.service_discovery_on_remote(service_uuid=ImmediateAlertService.UUID,
                                                                 char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
                                                                 characteristic=ImmediateAlertLevelCharacteristic)
            # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            ble_fun2 = WriteWithoutResponseFunctionality(ble_dut, ble_clients=ble_client2,
                                                         ble_client_address=ble_client_address2,
                                                         write_handle=write_handle2, data_length=240, data=data,
                                                         write_count=50, allocated_mem_addr=allocated_mem_addr,
                                                         bt_mon_log_file_name=bt_mon_log_file_name)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)
            
            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part
            
            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (sniffer_data_df['Opcode'] == "* ATT_WRITE_CMD") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.write_count/2), "No ATT_WRITE_CMD packets are present"
            logger().info("ATT_WRITE_CMD packets are sent successfully")

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if char_path:
            logger().info(f' *********************** unsubscribe to notifications ***********************')
            ble_client1.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            ble_client1.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
            time.sleep(2)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_tx_notification_tx_indication_C664472(ble_dut, ble_clients,
                                                                                              sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_tx_notification_tx_indication_C664472"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_tx_notification_tx_indication_C664472")

            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            char_path = None
            char_path1 = None
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()

            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=62)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2, service="HealthThermometerService")
            time.sleep(30)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            char_path, char_props = ble_obj1.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            ble_client1.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            logger().info(f' *********************** subscribe to notifications ***********************')
            ble_client1.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            ble_client1.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=char_path, char_uid=char_uid)
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            time.sleep(5)
            ble_fun1 = TxNotificationFunctionality(ble_dut, ble_clients=ble_client1,
                                                   ble_client_address=ble_client_address1, data=data,
                                                   service_uid=service_uid, char_uid=char_uid,
                                                   allocated_mem_addr=allocated_mem_addr, char_path=char_path)
            char_path1, char_props = ble_obj2.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            time.sleep(2)
            logger().info(f"****** Indication Start****************")
            ble_client2.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path1)
            ble_client2.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path1,
                                                                                     char_uid=char_uid)
            ble_fun2 = TxIndicationFunctionality(ble_dut, ble_client=ble_client2,
                                                 ble_client_address=ble_client_address2, char_path=char_path1,
                                                 char_uuid=char_uid, data=data, indication_count=50, data_length=240,
                                                 allocated_mem_addr=allocated_mem_addr, handle=12)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)
            
            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part
            
            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.indication_count/2), "No ATT_HANDLE_VALUE_IND packets are present"
            logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if char_path:
            logger().info(f' *********************** unsubscribe to notifications ***********************')
            ble_client1.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            ble_client1.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
            time.sleep(2)
        if char_path1:
            logger().info("disabling the notifications")
            ble_client2.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path1)
            logger().info("unsubscribe to notifications")
            ble_client2.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        logger().info("DISCONNECTING THE DEVICES")
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_tx_notification_rx_notification_C664473(ble_dut, ble_clients,
                                                                                     sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_tx_notification_rx_notification_C664473"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_tx_notification_rx_notification_C664473")
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            char_path = None
            write_handle2 = None
            svc = 'HealthThermometerService'
            charc = 'CustomNotifyCharacteristic'
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()

            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)  
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)  

            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="HealthThermometerService")
            time.sleep(30)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            logger().info(f"DATA:{data}")
            logger().info(f"DATA_LENGTH: {len(data)}")
            allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            char_path, char_props = ble_obj1.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            ble_client1.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            logger().info(f' *********************** subscribe to notifications ***********************')
            ble_client1.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            ble_client1.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=char_path, char_uid=char_uid)
            
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            time.sleep(5)
            ble_fun1 = TxNotificationFunctionality(ble_dut, ble_clients=ble_client1,
                                                   ble_client_address=ble_client_address1, data=data,
                                                   service_uid=service_uid, char_uid=char_uid,
                                                   allocated_mem_addr=allocated_mem_addr, char_path=char_path)
            write_handle2 = ble_obj2.service_discovery_on_remote(HealthThermometerService.UUID,
                                                                 CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                                 CustomNotifyCharacteristic)
            # # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            logger().info("******************** Start RX Notifications functionality ***********************")
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address2,
                                                           handle=(write_handle2 + 1),
                                                           enable_notify=1)
            time.sleep(3)
            # Get All Profiles
            ble_fun2 = RxNotificationFunctionality(ble_dut, ble_clients=ble_client2,
                                                   ble_client_address=ble_client_address2, data=data, svc=svc,
                                                   charc=charc, write_handle=write_handle2, enable_notify=1,
                                                   rx_notification_count=50)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)
            
            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part
            
            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_client_address2.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.rx_notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if char_path:
            logger().info(f' *********************** unsubscribe to notifications ***********************')
            ble_client1.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            ble_client1.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
            time.sleep(2)
            time.sleep(2)
        if write_handle2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address2,
                                                           handle=(write_handle2 + 1), enable_notify=0)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_rx_notification_write_without_response_C664478(ble_dut, ble_clients,
                                                                                              sl_collections, ble_sniffer):
    bt_mon_log_file_name = (f"reports/test_ble_dut_as_master_and_slave_240_bytes_rx_notification_write_without_response_C664478"
                            f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_rx_notification_write_without_response_C664478")
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            write_handle1 = None
            allocated_mem_addr = None
            svc = 'HealthThermometerService'
            charc = 'CustomNotifyCharacteristic'
            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()
            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2, service="ImmediateAlertService")
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            time.sleep(30)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            write_handle1 = ble_obj1.service_discovery_on_remote(HealthThermometerService.UUID,
                                                                 CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                                 CustomNotifyCharacteristic)
            # # Configure Buffer Mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)

            logger().info("******************** Start RX Notifications functionality ***********************")
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address1,
                                                           handle=(write_handle1 + 1),
                                                           enable_notify=1)
            time.sleep(2)
            # Get All Profiles
            ble_fun1 = RxNotificationFunctionality(ble_dut, ble_clients=ble_client1,
                                                   ble_client_address=ble_client_address1, data=data, svc=svc,
                                                   charc=charc, write_handle=write_handle1, enable_notify=1,
                                                   rx_notification_count=50)
            # get remote device profile
            write_handle2 = ble_obj2.service_discovery_on_remote(service_uuid=ImmediateAlertService.UUID,
                                                                 char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
                                                                 characteristic=ImmediateAlertLevelCharacteristic)
            # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            ble_fun2 = WriteWithoutResponseFunctionality(ble_dut, ble_clients=ble_client2,
                                                         ble_client_address=ble_client_address2,
                                                         write_handle=write_handle2, data_length=240, data=data,
                                                         write_count=50, allocated_mem_addr=allocated_mem_addr,
                                                         bt_mon_log_file_name=bt_mon_log_file_name)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)
            
            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part
            
            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_client_address1.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.rx_notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (sniffer_data_df['Opcode'] == "* ATT_WRITE_CMD") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.write_count/2), "No ATT_WRITE_CMD packets are present"
            logger().info("ATT_WRITE_CMD packets are sent successfully")

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if write_handle1:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address1,
                                                           handle=(write_handle1 + 1), enable_notify=0)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        # Disconnect From Remote Device
        ble_obj1.check_device_state_on_dut()
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.check_device_state_on_dut()
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_rx_notification_tx_indication_C664480(ble_dut, ble_clients,
                                                                                              sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_rx_notification_tx_indication_C664480"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_rx_notification_tx_indication_C664480")

            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            write_handle1 = None
            char_path1 = None
            svc = 'HealthThermometerService'
            charc = 'CustomNotifyCharacteristic'
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()
            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="HealthThermometerService")
            time.sleep(30)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            write_handle1 = ble_obj1.service_discovery_on_remote(HealthThermometerService.UUID,
                                                                 CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                                 CustomNotifyCharacteristic)
            # # Configure Buffer Mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            logger().info("******************** Start RX Notifications functionality ***********************")
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address1,
                                                           handle=(write_handle1 + 1),
                                                           enable_notify=1)
            time.sleep(2)
            # Get All Profiles
            ble_fun1 = RxNotificationFunctionality(ble_dut, ble_clients=ble_client1,
                                                   ble_client_address=ble_client_address1, data=data, svc=svc,
                                                   charc=charc, write_handle=write_handle1, enable_notify=1,
                                                   rx_notification_count=50)
            char_path1, char_props = ble_obj2.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            time.sleep(2)
            logger().info(f"****** Indication Start****************")
            ble_client2.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path1)
            ble_client2.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path1,
                                                                                     char_uid=char_uid)
            time.sleep(2)
            ble_fun2 = TxIndicationFunctionality(ble_dut, ble_client=ble_client2,
                                                 ble_client_address=ble_client_address2, char_path=char_path1,
                                                 char_uuid=char_uid, data=data, indication_count=50, data_length=240,
                                                 allocated_mem_addr=allocated_mem_addr, handle=12)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)
            
            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part
            
            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_client_address1.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.rx_notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.indication_count/2), "No ATT_HANDLE_VALUE_IND packets are present"
            logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if write_handle1:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address1,
                                                           handle=(write_handle1 + 1), enable_notify=0)
            time.sleep(2)
        if char_path1:
            logger().info("disabling the notifications")
            ble_client2.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path1)
            logger().info("unsubscribe to notifications")
            ble_client2.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        logger().info("DISCONNECTING THE DEVICES")
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_rx_notification_tx_notification_C664481(ble_dut, ble_clients,
                                                                                     sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_rx_notification_tx_notification_C664481"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_rx_notification_tx_notification_C664481")

            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            write_handle1 = None
            char_path1 = None
            svc = 'HealthThermometerService'
            charc = 'CustomNotifyCharacteristic'
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()
            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="HealthThermometerService")
            time.sleep(60)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            write_handle1 = ble_obj1.service_discovery_on_remote(HealthThermometerService.UUID,
                                                                 CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                                 CustomNotifyCharacteristic)
            # # Configure Buffer Mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            logger().info("******************** Start RX Notifications functionality ***********************")
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address1,
                                                           handle=(write_handle1 + 1),
                                                           enable_notify=1)
            time.sleep(2)
            # Get All Profiles
            ble_fun1 = RxNotificationFunctionality(ble_dut, ble_clients=ble_client1,
                                                   ble_client_address=ble_client_address1, data=data, svc=svc,
                                                   charc=charc, write_handle=write_handle1, enable_notify=1,
                                                   rx_notification_count=50)
            char_path1, char_props = ble_obj2.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            ble_client2.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path1)
            logger().info(f' *********************** subscribe to notifications ***********************')
            ble_client2.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path1)
            ble_client2.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=char_path1, char_uid=char_uid)
            # # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            ble_fun2 = TxNotificationFunctionality(ble_dut, ble_clients=ble_client2,
                                                   ble_client_address=ble_client_address2, data=data,
                                                   service_uid=service_uid, char_uid=char_uid,
                                                   allocated_mem_addr=allocated_mem_addr, char_path=char_path1)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)
            
            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part
            
            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_client_address1.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.rx_notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if write_handle1:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address1,
                                                           handle=(write_handle1 + 1), enable_notify=0)

            time.sleep(2)
        if char_path1:
            logger().info(f' *********************** unsubscribe to notifications ***********************')
            ble_client2.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path1)
            ble_client2.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        logger().info("DISCONNECTING THE DEVICES")
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_200_bytes_tx_notification_C664486(ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (f"reports/test_ble_dut_as_master_and_slave_200_bytes_tx_notification_C664486"
                            f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_200_bytes_tx_notification_C664486")

            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            char_path = None
            char_path1 = None
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()

            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)

            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="HealthThermometerService")
            time.sleep(60)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))
            allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            char_path, char_props = ble_obj1.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            ble_client1.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            logger().info(f' *********************** subscribe to notifications ***********************')
            ble_client1.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            ble_client1.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=char_path, char_uid=char_uid)
            
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            time.sleep(5)
            ble_fun1 = TxNotificationFunctionality(ble_dut, ble_clients=ble_client1,
                                                   ble_client_address=ble_client_address1, data=data,
                                                   service_uid=service_uid, char_uid=char_uid,
                                                   allocated_mem_addr=allocated_mem_addr, char_path=char_path)
            char_path1, char_props = ble_obj2.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            ble_client2.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path1)
            logger().info(f' *********************** subscribe to notifications ***********************')
            ble_client2.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path1)
            ble_client2.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=char_path1, char_uid=char_uid)
            
            # # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            ble_fun2 = TxNotificationFunctionality(ble_dut, ble_clients=ble_client2,
                                                   ble_client_address=ble_client_address2, data=data,
                                                   service_uid=service_uid, char_uid=char_uid,
                                                   allocated_mem_addr=allocated_mem_addr, char_path=char_path1)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)
            
            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part
            
            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 203)]) >= int(ble_fun1.notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 203)]) >= int(ble_fun2.notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if char_path:
            logger().info(f' *********************** unsubscribe to notifications ***********************')
            ble_client1.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            ble_client1.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
            time.sleep(2)
        if char_path1:
            logger().info(f' *********************** unsubscribe to notifications ***********************')
            ble_client2.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path1)
            ble_client2.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_200_bytes_rx_notification_C664488(ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (f"reports/test_ble_dut_as_master_and_slave_200_bytes_rx_notification_C664488"
                            f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_200_bytes_rx_notification_C664488")

            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            write_handle1 = None
            write_handle2 = None
            svc = 'HealthThermometerService'
            charc = 'CustomNotifyCharacteristic'
            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()
            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="HealthThermometerService")
            time.sleep(30)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))
            write_handle1 = ble_obj1.service_discovery_on_remote(HealthThermometerService.UUID,
                                                                 CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                                 CustomNotifyCharacteristic)
            # # Configure Buffer Mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            logger().info("******************** Start RX Notifications functionality ***********************")
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address1,
                                                                handle=(write_handle1 + 1),
                                                                enable_notify=1)
            time.sleep(2)
            # Get All Profiles
            ble_fun1 = RxNotificationFunctionality(ble_dut, ble_clients=ble_client1,
                                                   ble_client_address=ble_client_address1, data=data, svc=svc,
                                                   charc=charc, write_handle=write_handle1, enable_notify=1,
                                                   rx_notification_count=50)
            write_handle2 = ble_obj2.service_discovery_on_remote(HealthThermometerService.UUID,
                                                                 CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                                 CustomNotifyCharacteristic)
            # # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            logger().info("******************** Start RX Notifications functionality ***********************")
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address2,
                                                           handle=(write_handle2 + 1),
                                                           enable_notify=1)
            time.sleep(3)
            # Get All Profiles
            ble_fun2 = RxNotificationFunctionality(ble_dut, ble_clients=ble_client2,
                                                   ble_client_address=ble_client_address2, data=data, svc=svc,
                                                   charc=charc, write_handle=write_handle2, enable_notify=1,
                                                   rx_notification_count=50)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)
            
            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part
            
            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_client_address1.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 203)]) >= int(ble_fun1.rx_notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_client_address2.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 203)]) >= int(ble_fun2.rx_notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if write_handle1:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address1,
                                                           handle=(write_handle1 + 1), enable_notify=0)
            time.sleep(2)
        if write_handle2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address2,
                                                           handle=(write_handle2 + 1), enable_notify=0)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_200_bytes_tx_indication_C664490(ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (f"reports/test_ble_dut_as_master_and_slave_200_bytes_tx_indication_C664490"
                            f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_200_bytes_tx_indication_C664490")

            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            char_path = None
            char_path1 = None
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()
            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=34)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")

            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="HealthThermometerService")
            time.sleep(60)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))
            char_path, char_props = ble_obj1.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            # Configure Buffer Mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            time.sleep(2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            logger().info(f"****** Indication Start****************")
            ble_client1.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            ble_client1.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                         char_uid=char_uid)
            ble_fun1 = TxIndicationFunctionality(ble_dut, ble_client=ble_client1,
                                                 ble_client_address=ble_client_address1, char_path=char_path,
                                                 char_uuid=char_uid, data=data, indication_count=50, data_length=200,
                                                 allocated_mem_addr=allocated_mem_addr, handle=12)
            char_path1, char_props = ble_obj2.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            time.sleep(2)
            logger().info(f"****** Indication Start****************")
            ble_client2.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path1)
            ble_client2.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path1,
                                                                                         char_uid=char_uid)
            ble_fun2 = TxIndicationFunctionality(ble_dut, ble_client=ble_client2,
                                                 ble_client_address=ble_client_address2, char_path=char_path1,
                                                 char_uuid=char_uid, data=data, indication_count=50, data_length=200,
                                                 allocated_mem_addr=allocated_mem_addr, handle=12)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)
            
            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part
            
            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            logger().info("validating indication packets")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 203)]) >= int(ble_fun1.indication_count/2), "No ATT_HANDLE_VALUE_IND packets are present"
            logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 203)]) >= int(ble_fun2.indication_count/2), "No ATT_HANDLE_VALUE_IND packets are present"
            logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if char_path:
            logger().info("disabling the notifications")
            ble_client1.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            logger().info("unsubscribe to notifications")
            ble_client1.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        if char_path1:
            logger().info("disabling the notifications")
            ble_client2.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path1)
            logger().info("unsubscribe to notifications")
            ble_client2.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        logger().info("DISCONNECTING THE DEVICES")
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_200_bytes_write_without_response_C664492(ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (f"reports/test_ble_dut_as_master_and_slave_200_bytes_write_without_response_C664492"
                            f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_200_bytes_write_without_response_C664492")
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init(set_smp=1)
            logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="ImmediateAlertService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2, service="ImmediateAlertService")
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))

            # get remote device profile
            write_handle1 = ble_obj1.service_discovery_on_remote(service_uuid=ImmediateAlertService.UUID,
                                                                 char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
                                                                 characteristic=ImmediateAlertLevelCharacteristic)
            # Configure buffer modes
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)

            ble_fun1 = WriteWithoutResponseFunctionality(ble_dut, ble_clients=ble_client1,
                                                         ble_client_address=ble_client_address1,
                                                         write_handle=write_handle1, data_length=200, data=data,
                                                         write_count=50, allocated_mem_addr=allocated_mem_addr,
                                                         bt_mon_log_file_name=bt_mon_log_file_name)

            # get remote device profile
            write_handle2 = ble_obj2.service_discovery_on_remote(service_uuid=ImmediateAlertService.UUID,
                                                                 char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
                                                                 characteristic=ImmediateAlertLevelCharacteristic)
            # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            ble_fun2 = WriteWithoutResponseFunctionality(ble_dut, ble_clients=ble_client2,
                                                         ble_client_address=ble_client_address2,
                                                         write_handle=write_handle2, data_length=200, data=data,
                                                         write_count=50, allocated_mem_addr=allocated_mem_addr,
                                                         bt_mon_log_file_name=bt_mon_log_file_name)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)
            
            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part
            
            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            logger().info("validating write without response")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (sniffer_data_df['Opcode'] == "* ATT_WRITE_CMD") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 203)]) >= int(ble_fun1.write_count/2), "No ATT_WRITE_CMD packets are present"
            logger().info("ATT_WRITE_CMD packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (sniffer_data_df['Opcode'] == "* ATT_WRITE_CMD") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 203)]) >= int(ble_fun2.write_count/2), "No ATT_WRITE_CMD packets are present"
            logger().info("ATT_WRITE_CMD packets are sent successfully")
    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        # Disconnect From Remote Device
        ble_obj1.check_device_state_on_dut()
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.check_device_state_on_dut()
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_write_with_response_C664438(ble_dut, ble_clients, sl_collections,
                                                                           ble_sniffer):
    bt_mon_log_file_name = (f"reports/test_ble_dut_as_master_and_slave_240_bytes_write_with_response_C664698"
                            f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_write_with_response_C664438")
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init(set_smp=1)

            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HeartRateService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2, service="HeartRateService")
            time.sleep(30)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            # get remote device profile
            write_handle1 = ble_obj1.service_discovery_on_remote(HeartRateService.UUID,
                                                                 HeartRateControlPointCharacteristic.UUID,
                                                                 HeartRateControlPointCharacteristic)
            # Configure buffer mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            ble_fun1 = WriteWithResponseFunctionality(ble_dut, ble_clients=ble_client1,
                                                      ble_client_address=ble_client_address1,
                                                      write_handle=write_handle1, data=data, write_count=50,
                                                      data_length=240, allocated_mem_addr=allocated_mem_addr)
            # get remote device profile
            write_handle2 = ble_obj2.service_discovery_on_remote(HeartRateService.UUID,
                                                                 HeartRateControlPointCharacteristic.UUID,
                                                                 HeartRateControlPointCharacteristic)
            # Configure buffer mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            ble_fun2 = WriteWithResponseFunctionality(ble_dut, ble_clients=ble_client2,
                                                      ble_client_address=ble_client_address2,
                                                      write_handle=write_handle2, data=data, write_count=50,
                                                      data_length=240, allocated_mem_addr=allocated_mem_addr)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            logger().info("validating write with response")
            assert len(sniffer_data_df.loc[(sniffer_data_df['Role'] == "* C") & (
                        sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_REQ") & (
                                                   sniffer_data_df[
                                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.write_count/2), "No ATT_WRITE_REQ packets are found"
            assert len(sniffer_data_df.loc[(sniffer_data_df['Role'] == "* P") & (
                        sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_REQ") & (
                                                   sniffer_data_df[
                                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.write_count/2), "No ATT_WRITE_REQ packets are found"
    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_write_without_response_write_with_response_C664446(
        ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_write_without_response_write_with_response_C664446"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_write_without_response_write_with_response_C664446")
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)

            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init(set_smp=1)
            logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="ImmediateAlertService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2, service="HeartRateService")
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            # get remote device profile
            write_handle1 = ble_obj1.service_discovery_on_remote(service_uuid=ImmediateAlertService.UUID,
                                                                 char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
                                                                 characteristic=ImmediateAlertLevelCharacteristic)
            # Configure buffer modes
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            time.sleep(5)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            ble_fun1 = WriteWithoutResponseFunctionality(ble_dut, ble_clients=ble_client1,
                                                         ble_client_address=ble_client_address1,
                                                         write_handle=write_handle1, data_length=240, data=data,
                                                         write_count=50, allocated_mem_addr=allocated_mem_addr,
                                                         bt_mon_log_file_name=bt_mon_log_file_name)
            # get remote device profile
            write_handle2 = ble_obj2.service_discovery_on_remote(HeartRateService.UUID,
                                                                 HeartRateControlPointCharacteristic.UUID,
                                                                 HeartRateControlPointCharacteristic)
            # Configure buffer mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            time.sleep(5)
            ble_fun2 = WriteWithResponseFunctionality(ble_dut, ble_clients=ble_client2,
                                                      ble_client_address=ble_client_address2,
                                                      write_handle=write_handle2, data=data, write_count=50,
                                                      data_length=240, allocated_mem_addr=allocated_mem_addr)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_CMD") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.write_count/2), "No ATT_WRITE_CMD packets are present"
            logger().info("ATT_WRITE_CMD packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_REQ") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.write_count/2), "No ATT_WRITE_REQ packet is sent"

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_write_with_response_write_without_response_C664454(
        ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_write_with_response_write_without_response_C664454"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_write_with_response_write_without_response_C664454")
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)

            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HeartRateService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="ImmediateAlertService")
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            # get remote device profile
            write_handle1 = ble_obj1.service_discovery_on_remote(HeartRateService.UUID,
                                                                 HeartRateControlPointCharacteristic.UUID,
                                                                 HeartRateControlPointCharacteristic)
            # Configure buffer mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            ble_fun1 = WriteWithResponseFunctionality(ble_dut, ble_clients=ble_client1,
                                                      ble_client_address=ble_client_address1,
                                                      write_handle=write_handle1, data=data, write_count=50,
                                                      data_length=240, allocated_mem_addr=allocated_mem_addr)

            # get remote device profile
            write_handle2 = ble_obj2.service_discovery_on_remote(service_uuid=ImmediateAlertService.UUID,
                                                                 char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
                                                                 characteristic=ImmediateAlertLevelCharacteristic)
            # Configure buffer modes
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            time.sleep(5)
            ble_fun2 = WriteWithoutResponseFunctionality(ble_dut, ble_clients=ble_client2,
                                                         ble_client_address=ble_client_address2,
                                                         write_handle=write_handle2, data_length=240, data=data,
                                                         write_count=50, allocated_mem_addr=allocated_mem_addr,
                                                         bt_mon_log_file_name=bt_mon_log_file_name)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()

            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)
            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part
            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_REQ") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.write_count/2), "No ATT_WRITE_REQ packets are found"
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_CMD") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.write_count/2), "No ATT_WRITE_CMD packets are present"
            logger().info("ATT_WRITE_CMD packets are sent successfully")

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_write_with_response_tx_indication_C664455(
        ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_write_with_response_tx_indication_C664455"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_write_with_response_tx_indication_C664455")
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            char_path1 = None
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)

            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()
            logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=34)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HeartRateService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="HealthThermometerService")
            time.sleep(30)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            # get remote device profile
            write_handle1 = ble_obj1.service_discovery_on_remote(HeartRateService.UUID,
                                                                 HeartRateControlPointCharacteristic.UUID,
                                                                 HeartRateControlPointCharacteristic)
            # Configure buffer mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            ble_fun1 = WriteWithResponseFunctionality(ble_dut, ble_clients=ble_client1,
                                                      ble_client_address=ble_client_address1,
                                                      write_handle=write_handle1, data=data, write_count=50,
                                                      data_length=240, allocated_mem_addr=allocated_mem_addr)
            char_path1, char_props = ble_obj2.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            time.sleep(2)
            logger().info(f"****** Indication Start****************")
            ble_client2.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path1)
            ble_client2.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path1,
                                                                                     char_uid=char_uid)

            ble_fun2 = TxIndicationFunctionality(ble_dut, ble_client=ble_client2,
                                                 ble_client_address=ble_client_address2, char_path=char_path1,
                                                 char_uuid=char_uid, data=data, indication_count=50, data_length=240,
                                                 allocated_mem_addr=allocated_mem_addr, handle=12)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())

            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_REQ") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.write_count/2), "No ATT_WRITE_REQ packets are found"
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.indication_count/2), "No ATT_HANDLE_VALUE_IND packets are present"
            logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if char_path1:
            logger().info("disabling the notifications")
            ble_client2.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path1)
            logger().info("unsubscribe to notifications")
            ble_client2.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        logger().info("DISCONNECTING THE DEVICES")
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_write_with_response_tx_notification_C664456(
        ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_write_with_response_tx_notification_C664456"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_write_with_response_tx_notification_C664456")
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            char_path = None
            allocated_mem_addr = None
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)

            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()
            logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=34)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HeartRateService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="HealthThermometerService")
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            # get remote device profile
            write_handle1 = ble_obj1.service_discovery_on_remote(HeartRateService.UUID,
                                                                 HeartRateControlPointCharacteristic.UUID,
                                                                 HeartRateControlPointCharacteristic)
            # Configure buffer mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            ble_fun1 = WriteWithResponseFunctionality(ble_dut, ble_clients=ble_client1,
                                                      ble_client_address=ble_client_address1,
                                                      write_handle=write_handle1, data=data, write_count=50,
                                                      data_length=240, allocated_mem_addr=allocated_mem_addr)
            char_path, char_props = ble_obj2.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            ble_client2.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            logger().info(f' *********************** subscribe to notifications ***********************')
            ble_client2.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            ble_client2.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=char_path, char_uid=char_uid)

            # # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            ble_fun2 = TxNotificationFunctionality(ble_dut, ble_clients=ble_client2,
                                                   ble_client_address=ble_client_address2, data=data,
                                                   service_uid=service_uid, char_uid=char_uid,
                                                   allocated_mem_addr=allocated_mem_addr, char_path=char_path)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            logger().info("validating write with response")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_REQ") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.write_count/2), "No ATT_WRITE_REQ packets are found"
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if char_path:
            logger().info(f' *********************** unsubscribe to notifications ***********************')
            ble_client2.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            ble_client2.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        logger().info("DISCONNECTING THE DEVICES")
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_write_with_response_rx_notification_C664457(
        ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_write_with_response_rx_notification_C664457"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_write_with_response_rx_notification_C664457")
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            write_handle2 = None
            allocated_mem_addr = None
            svc = 'HealthThermometerService'
            charc = 'CustomNotifyCharacteristic'
            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)

            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()
            logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=34)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HeartRateService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="HealthThermometerService")
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            # get remote device profile
            write_handle1 = ble_obj1.service_discovery_on_remote(HeartRateService.UUID,
                                                                 HeartRateControlPointCharacteristic.UUID,
                                                                 HeartRateControlPointCharacteristic)
            # Configure buffer mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            ble_fun1 = WriteWithResponseFunctionality(ble_dut, ble_clients=ble_client1,
                                                      ble_client_address=ble_client_address1,
                                                      write_handle=write_handle1, data=data, write_count=50,
                                                      data_length=240, allocated_mem_addr=allocated_mem_addr)

            write_handle2 = ble_obj2.service_discovery_on_remote(HealthThermometerService.UUID,
                                                                 CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                                 CustomNotifyCharacteristic)
            # # Configure Buffer Mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            logger().info("******************** Start RX Notifications functionality ***********************")
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address2,
                                                           handle=(write_handle2 + 1),
                                                           enable_notify=1)
            # Get All Profiles
            ble_fun2 = RxNotificationFunctionality(ble_dut, ble_clients=ble_client2,
                                                   ble_client_address=ble_client_address2, data=data, svc=svc,
                                                   charc=charc, write_handle=write_handle2, enable_notify=1,
                                                   rx_notification_count=50)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()

            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            logger().info("validating write with response")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_REQ") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.write_count/2), "No ATT_WRITE_REQ packets are found"
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (sniffer_data_df[
                                                                     '+BD Address (LE PKT)'] == f"0x{ble_client_address2.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.rx_notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if write_handle2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address2,
                                                           handle=(write_handle2 + 1), enable_notify=0)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        logger().info("DISCONNECTING THE DEVICES")
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_tx_indication_write_with_response_C664463(
        ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_tx_indication_write_with_response_C664463"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_tx_indication_write_with_response_C664463")

            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            char_path1 = None
            allocated_mem_addr = None
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)

            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()
            logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=62)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="HeartRateService")
            time.sleep(60)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            char_path1, char_props = ble_obj1.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            # Configure Buffer Mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            logger().info(f"****** Indication Start****************")
            ble_client1.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path1)
            ble_client1.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path1,
                                                                                     char_uid=char_uid)

            ble_fun1 = TxIndicationFunctionality(ble_dut, ble_client=ble_client1,
                                                 ble_client_address=ble_client_address1, char_path=char_path1,
                                                 char_uuid=char_uid, data=data, indication_count=50, data_length=240,
                                                 allocated_mem_addr=allocated_mem_addr, handle=12)
            write_handle2 = ble_obj2.service_discovery_on_remote(HeartRateService.UUID,
                                                                 HeartRateControlPointCharacteristic.UUID,
                                                                 HeartRateControlPointCharacteristic)
            # Configure buffer mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            ble_fun2 = WriteWithResponseFunctionality(ble_dut, ble_clients=ble_client2,
                                                      ble_client_address=ble_client_address2,
                                                      write_handle=write_handle2, data=data, write_count=50,
                                                      data_length=240, allocated_mem_addr=allocated_mem_addr)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.indication_count/2), "No ATT_HANDLE_VALUE_IND packets are present"
            logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_REQ") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.write_count/2), "No ATT_WRITE_REQ packets are found"
    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if char_path1:
            logger().info("disabling the notifications")
            ble_client1.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path1)
            logger().info("unsubscribe to notifications")
            ble_client1.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        logger().info("DISCONNECTING THE DEVICES")
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_tx_notification_write_with_response_C664471(
        ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_tx_notification_write_with_response_C664471"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_tx_notification_write_with_response_C664471")

            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            char_path = None
            allocated_mem_addr = None
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()

            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)

            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="HeartRateService")
            time.sleep(10)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            char_path, char_props = ble_obj1.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            ble_client1.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            logger().info(f' *********************** subscribe to notifications ***********************')
            ble_client1.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            ble_client1.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=char_path, char_uid=char_uid)

            ble_obj1.configure_buffer_mode(mode=1, count=2)
            time.sleep(5)
            ble_fun1 = TxNotificationFunctionality(ble_dut, ble_clients=ble_client1,
                                                   ble_client_address=ble_client_address1, data=data,
                                                   service_uid=service_uid, char_uid=char_uid,
                                                   allocated_mem_addr=allocated_mem_addr, char_path=char_path)
            write_handle2 = ble_obj2.service_discovery_on_remote(HeartRateService.UUID,
                                                                 HeartRateControlPointCharacteristic.UUID,
                                                                 HeartRateControlPointCharacteristic)
            # Configure buffer mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            ble_fun2 = WriteWithResponseFunctionality(ble_dut, ble_clients=ble_client2,
                                                      ble_client_address=ble_client_address2,
                                                      write_handle=write_handle2, data=data, write_count=50,
                                                      data_length=240, allocated_mem_addr=allocated_mem_addr)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            logger().info(f"ble_fun1.notification_count : {ble_fun1.notification_count}")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* C") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_REQ") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.write_count/2), "No ATT_WRITE_REQ packets are found"


    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if char_path:
            logger().info(f' *********************** unsubscribe to notifications ***********************')
            ble_client1.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            ble_client1.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        time.sleep(2)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        logger().info("DISCONNECTING THE DEVICES")
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_240_bytes_rx_notification_write_with_response_C664479(
        ble_dut, ble_clients, sl_collections, ble_sniffer):
    bt_mon_log_file_name = (
        f"reports/test_ble_dut_as_master_and_slave_240_bytes_rx_notification_write_with_response_C664479"
        f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_240_bytes_rx_notification_write_with_response_C664479")

            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            write_handle1 = None
            allocated_mem_addr = None
            svc = 'HealthThermometerService'
            charc = 'CustomNotifyCharacteristic'
            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init()
            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)
            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HealthThermometerService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2,
                                                     service="HeartRateService")
            time.sleep(30)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
            allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            write_handle1 = ble_obj1.service_discovery_on_remote(HealthThermometerService.UUID,
                                                                 CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                                 CustomNotifyCharacteristic)
            # # Configure Buffer Mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            logger().info("******************** Start RX Notifications functionality ***********************")
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address1,
                                                           handle=(write_handle1 + 1),
                                                           enable_notify=1)
            time.sleep(2)
            # Get All Profiles
            ble_fun1 = RxNotificationFunctionality(ble_dut, ble_clients=ble_client1,
                                                   ble_client_address=ble_client_address1, data=data, svc=svc,
                                                   charc=charc, write_handle=write_handle1, enable_notify=1,
                                                   rx_notification_count=50)
            write_handle2 = ble_obj2.service_discovery_on_remote(HeartRateService.UUID,
                                                                 HeartRateControlPointCharacteristic.UUID,
                                                                 HeartRateControlPointCharacteristic)
            # Configure buffer mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            ble_fun2 = WriteWithResponseFunctionality(ble_dut, ble_clients=ble_client2,
                                                      ble_client_address=ble_client_address2,
                                                      write_handle=write_handle2, data=data, write_count=50,
                                                      data_length=240, allocated_mem_addr=allocated_mem_addr)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (sniffer_data_df[
                                                                     '+BD Address (LE PKT)'] == f"0x{ble_client_address1.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun1.rx_notification_count/2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                       sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_REQ") & (
                                   sniffer_data_df[
                                       '+PDU Length (L2CAP)'] == 240)]) >= int(ble_fun2.write_count/2), "No ATT_WRITE_REQ packets are found"
    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        if write_handle1:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address1,
                                                           handle=(write_handle1 + 1), enable_notify=0)
        time.sleep(2)
        logger().info("******************** ble_remove_service ***********************")
        ble_dut.interfaces.bluetooth.ble_remove_service()
        logger().info("DISCONNECTING THE DEVICES")
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_as_master_and_slave_200_bytes_write_with_response_C664494(ble_dut, ble_clients, sl_collections,
                                                                           ble_sniffer):
    bt_mon_log_file_name = (f"reports/test_ble_dut_as_master_and_slave_200_bytes_write_with_response_C664494"
                            f"{int(time.time())}.log")
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(
                capture_file="test_ble_dut_as_master_and_slave_200_bytes_write_with_response_C664494")
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            allocated_mem_addr = None
            ble_obj1 = Ble_Data_Transfer(ble_dut, ble_client1, sl_collections)
            ble_obj2 = Ble_Data_Transfer(ble_dut, ble_client2, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj1.ble_gatt_init(set_smp=1)

            ble_client_address1 = ble_obj1.ble_master(ble_client=ble_client1, service="HeartRateService")
            ble_dut.interfaces.bluetooth.ble_set_smp()
            ble_client_address2 = ble_obj2.ble_slave(ble_client=ble_client2, service="HeartRateService")
            time.sleep(30)
            ble_obj1.check_device_state_on_dut()
            ble_obj2.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))
            # get remote device profile
            write_handle1 = ble_obj1.service_discovery_on_remote(HeartRateService.UUID,
                                                                 HeartRateControlPointCharacteristic.UUID,
                                                                 HeartRateControlPointCharacteristic)
            # Configure buffer mode
            ble_obj1.configure_buffer_mode(mode=1, count=2)
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
            ble_fun1 = WriteWithResponseFunctionality(ble_dut, ble_clients=ble_client1,
                                                      ble_client_address=ble_client_address1,
                                                      write_handle=write_handle1, data=data, write_count=50,
                                                      data_length=200, allocated_mem_addr=allocated_mem_addr)
            # get remote device profile
            write_handle2 = ble_obj2.service_discovery_on_remote(HeartRateService.UUID,
                                                                 HeartRateControlPointCharacteristic.UUID,
                                                                 HeartRateControlPointCharacteristic)
            # Configure buffer mode
            ble_obj2.configure_buffer_mode(mode=1, count=2)
            ble_fun2 = WriteWithResponseFunctionality(ble_dut, ble_clients=ble_client2,
                                                      ble_client_address=ble_client_address2,
                                                      write_handle=write_handle2, data=data, write_count=50,
                                                      data_length=200, allocated_mem_addr=allocated_mem_addr)
            thread1 = threading.Thread(target=ble_fun1.run)
            thread2 = threading.Thread(target=ble_fun2.run)
            thread1.start()
            time.sleep(2)
            thread2.start()
            thread1.join()
            thread2.join()
            # Mapping Master and Slave Address for Adding devices for sniffer
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex1 = re.split(":", ble_client_address1)
            ble_client_address_hex2 = re.split(":", ble_client_address2)

            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part

            slave_address1 = "0x"
            slave_address2 = "0x"
            for hex_data_part in ble_client_address_hex1:
                slave_address1 = slave_address1 + hex_data_part
            logger().info(f"slave_address1:{slave_address1}")
            for hex_data_part in ble_client_address_hex2:
                slave_address2 = slave_address2 + hex_data_part
            logger().info(f"slave_address2:{slave_address2}")
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            logger().info(sniffer_data_df.head())
            logger().info("validating write with response")
            assert len(sniffer_data_df.loc[(sniffer_data_df['Role'] == "* C") & (
                        sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_REQ") & (
                                                   sniffer_data_df[
                                                       '+PDU Length (L2CAP)'] == 203)]) >= int(ble_fun1.write_count/2), "No ATT_WRITE_REQ packets are found"
            assert len(sniffer_data_df.loc[(sniffer_data_df['Role'] == "* P") & (
                        sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                                       sniffer_data_df['Opcode'] == "* ATT_WRITE_REQ") & (
                                                   sniffer_data_df[
                                                       '+PDU Length (L2CAP)'] == 203)]) >= int(ble_fun2.write_count/2), "No ATT_WRITE_REQ packets are found"
    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        if ble_obj1.scan_state:
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
        # Disconnect From Remote Device
        ble_obj1.disconnect_from_remote(ble_client=ble_client1)
        # Disconnect from dut
        ble_obj2.disconnect_form_dut(ble_client=ble_client2)
        ble_client1.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client2.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        if allocated_mem_addr:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)

