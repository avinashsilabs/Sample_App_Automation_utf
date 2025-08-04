import time
import pytest
import re
import string
from utf.interfaces.bluetooth.hid_recorder import HidRecorder
import random
from utf.interfaces.wifi import WlanError
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.bluetooth.bluez.gatt_application.glucose_service import GlucoseService, \
    GlucoseMeasurementCharacteristic
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryService
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryLevelCharacteristic
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryService
from utf.interfaces.bluetooth.bluez.gatt_application.link_loss_service import (
    LinkLossService,
    LinkLossAlertLevelCharacteristic,
)
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService,  HeartRateMeasurementCharacterstic,   HeartRateControlPointCharacteristic

from utf.interfaces.bluetooth.bluez.gatt_application.blood_pressure_service import \
    BloodPressureMeasurementCharacteristic, BloodPressureService
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    HealthThermometerMeasurementCharacteristic, HealthThermometerService
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI



def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Enable the wlan and bt power save mode in dut after the connection
        3. Initiates ble in DUT 
        4. Connect to the remote device/connect to the dut

    Author: Jyothi Nagireddy
"""
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
        self.ble_dut_address = self.ble_dut.interfaces.wifi.ble_gatt_start(set_smp=set_smp)
        logger().info(f"DUT BLE Address :{self.ble_dut_address}")
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

    def advertising_dut(self):
        logger().info("***** Advertising from DUT *****")
        self.ble_dut.interfaces.wifi.ble_start_advertising()
        dut_state = int(self.ble_dut.interfaces.wifi.ble_get_device_state())
        logger().info(f"DUT Advertising Status :{dut_state}")
        assert dut_state == 1
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
        time.sleep(30)

        events = self.ble_dut.interfaces.bluetooth.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                    scan_result = event.event_data

        logger().info("Verifying client address is available in scan list...")
        assert str(self.ble_client_address) in str(scan_result), "Failed to find client BT address in scan list...."
        logger().info(f"Found BLE client address: {self.ble_client_address}")
        logger().info("Remote device found in scan results, BLE scanning is successful")

        time.sleep(2)
        self.ble_dut.interfaces.bluetooth.ble_stop_scanning()

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
                bt_dut_address=self.ble_dut_address, service_classes=[service]
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
                self.ble_client.interfaces.bluetooth.pair_and_connect(self.ble_dut_address)
                time.sleep(30)

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

    @staticmethod
    def validate_write_with_response(bt_mon_log_file=None, write_handle=None, data=None,
                                     write_data_count=None, request=None):
        logger().info(" ***** Validating Write With Response Start *****")
        flag = False
        write_validate_count = 0
        with open(bt_mon_log_file, "r") as file_p:
            lines = file_p.readlines()

        acl_data_flag = att_flag = handle_flag = acl_tx_flag = False
        for line in lines:
            if "> ACL Data RX: Handle" in line:
                acl_data_flag = True
                continue
            if request in line and acl_data_flag is True:
                att_flag = True
                continue
            if "Handle:" in line:
                if f"0x{write_handle:04X}" in line and att_flag is True:
                    handle_flag = True
                continue
            if "Data:" in line and acl_data_flag and att_flag and handle_flag:
                data_match = re.search(r'Data:(.*)', line)
                hex_string = data_match.group(1) if data_match else ""
                byte_array = bytes.fromhex(hex_string)
                text = byte_array.decode('unicode_escape')
                logger().info(f"Actual data :{data}  Expected data:{text}")
                try:
                    assert data in str(text), "Actual data is not found"
                except:
                    assert data[:237] in str(text), "Actual data is not found"
                flag = True
                continue
            if "< ACL Data TX:" in line and flag is True:
                acl_tx_flag = True
                continue
            if "ATT: Prepare Write Response" in line and acl_tx_flag is True:
                logger().info(" ATT : Write Response Success")
                write_validate_count = write_validate_count + 1
                acl_data_flag = att_flag = handle_flag = False
                continue
            if "ATT: Error Response" in line and acl_tx_flag is True:
                logger().info("ATT : Error Response Getting")
                write_validate_count = write_validate_count + 1
                acl_data_flag = att_flag = handle_flag = False
                continue

        logger().info(f"write_data_count:{write_data_count} : write_validate_count:{write_validate_count}")
        assert write_data_count == write_validate_count, "Write Response validation not matching"
        logger().info(" ***** Validating Write With Response Success *****")

    def gatt_write_with_resp(self, write_handle, data=None, write_time=100, write_count=None, data_length=None):
        logger().info(f"*******Write With Response Start****************")
        write_data_count = 0

        def write():
            nonlocal write_data_count
            time.sleep(2)
            self.ble_dut.interfaces.bluetooth.ble_set_att_value_async(
                ble_remote_dev_address=self.ble_client_address,
                char_property=write_handle, data=data, data_length=data_length)
            time.sleep(5)
            write_data_count += 1

        if write_count:
            for i in range(write_count):
                write()
                i += 1
        else:
            sw = Stopwatch()
            while sw.elapsed_sec <= write_time:
                write()

        logger().info(f"*******Write With Response End****************")
        return write_data_count

    def disconnect_form_dut(self):
        logger().info("\n\n\n ***** Disconnect from DUT ***** \n\n\n")
        state = self.ble_dut.interfaces.bluetooth.ble_get_device_state()
        if state == 0:
            logger().info(f"Already device disconnection status in remote' {self.ble_client.name}' is:{state}")
        else:
            time.sleep(2)
            self.ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
            time.sleep(2)
            state = self.ble_dut.interfaces.bluetooth.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            logger().info(f"DisConnection status in remote device '{self.ble_client.name}' is:{state}")
        time.sleep(5)

    def disconnect_from_remote(self):
        logger().info("\n\n\n ***** Disconnect from Remote(raspi) ***** \n\n\n")
        status = self.ble_client.interfaces.bluetooth.get_connection_status(self.ble_dut_address)
        if status == 0:
            logger().info(f"Already DisConnection status in remote device '{self.ble_client.name}' is:{status}")
        else:
            self.ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)
            status = self.ble_client.interfaces.bluetooth.get_connection_status(self.ble_dut_address)
            self.ble_client.interfaces.bluetooth.close()
            logger().info(f"DisConnection status in remote device '{self.ble_client.name}' is:{status}")

    def clear_dut(self, role=None):
        logger().info(f"*************DUT Clearing Started With {role}*******************")
        logger().info("Checking connection status of BLE")
        if role == "master":
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
        else:
            state = self.ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            if state_int == 1:
                logger().info("Device is advertising status try to stop advertising")
                self.ble_dut.interfaces.wifi.ble_stop_advertising()

            elif state_int == 8:
                logger().info("Device is connected status try to disconnect")
                self.disconnect_form_dut()

        self.ble_client.interfaces.bluetooth.close()
        logger().info(" *************DUT Clearing Stop Success *******************")


class BleFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_start=True, bt_dut_address=None, thermometer=None, powersave=False, battery_service=False, HeartRate=False, ht=False, battery_heartrate=False, pair=False, link_loss=False, glucose=False, ble_scan_interval=160, ble_scan_window=80, ble_conn_interval_min=160, ble_supervision_timeout=2000, ble_conn_interval_max=160):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.bt_dut_address = bt_dut_address
        self.ble_scan_interval = ble_scan_interval
        self.ble_scan_window = ble_scan_window
        self.ble_conn_interval_min = ble_conn_interval_min
        self.ble_supervision_timeout = ble_supervision_timeout
        self.ble_conn_interval_max = ble_conn_interval_max
        self.powersave = powersave
        self.battery_service = battery_service
        self.HeartRate = HeartRate
        self.ht = ht
        self.battery_heartrate = battery_heartrate
        self.link_loss = link_loss
        self.pair = pair
        self.ble_start = ble_start
        self.thermometer = thermometer
        self.glucose = glucose


    def ble_adv(self):
        # Advertise data from DUT
        logger().info("start ble advertising....")
        self.wifi_dut.interfaces.wifi.ble_start_advertising()
        if self.powersave:
            enable_wifi_ps = self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            assert enable_wifi_ps == 0, 'failed to enable wlan power save'
            enable_bt_ps = self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            assert enable_bt_ps == 0, 'failed to enable bt power save'
        self.ble_client.interfaces.bluetooth.close()
        if self.battery_service:
            logger().info("scanning for ble client.. ")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.bt_dut_address, service_classes=["BatteryService"])
        elif self.battery_heartrate:
            logger().info(f"Adding battery and heartrate services on remote side")
            logger().info("scanning for ble client.. ")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.bt_dut_address,
                                                                                    service_classes=["BatteryService", "HeartRateService"])
        elif self.link_loss:
            logger().info("scanning for ble client.. ")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.bt_dut_address,
                                                                                    service_classes=["LinkLossService"])
        else:
            logger().info("scanning for ble client.. ")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.bt_dut_address)
        assert bt_client_address, "The client address is not found"
        time.sleep(5)
        self.ble_client.interfaces.bluetooth.stop_scanning()

        logger().info("verifying device in scan list...")
        found_devices = self.ble_client.interfaces.bluetooth.get_devices()

        assert self.wifi_dut.interfaces.wifi.ble_address in found_devices, "failed to find dut address in scan list..."
        assert (found_devices[
                    self.wifi_dut.interfaces.wifi.ble_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data), \
            "failed to find dut in scan list..."
        if self.pair:
            logger().info("connecting to dut....")
            self.ble_client.interfaces.bluetooth.pair_and_connect(self.bt_dut_address)
        else:
            try:
                logger().info("connecting to dut....")
                self.ble_client.interfaces.bluetooth.connect(self.bt_dut_address)
            except Exception:
                self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        return bt_client_address

    def ble_gatt_scan(self):
        # Start DUT
        bt_dut_address = ""
        if self.ble_start:
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start()
            assert bt_dut_address is not None, "gatt init failed in DUT"

        retries = 3  # Maximum number of retries
        timeout = 120

        for retry in range(retries):
            try:
                self.ble_client.interfaces.bluetooth.close()
                logger().info(f"Attempt {retry + 1}: Starting SMP Advertising...")
                # Start SMP Advertising
                if self.HeartRate:
                    self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                        bt_dut_address=bt_dut_address, service_classes=["HeartRateService"]
                    )
                elif self.battery_service:
                    self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                        bt_dut_address=bt_dut_address, service_classes=["BatteryService"]
                    )
                elif self.thermometer:
                    self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                        bt_dut_address=bt_dut_address, service_classes=["HealthThermometerService"]
                    )
                elif self.glucose:
                    self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                        bt_dut_address=bt_dut_address, service_classes=["GlucoseService"]
                    )
                elif self.ht:
                    self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                        bt_dut_address=bt_dut_address, service_classes=["HeartRateService", "HealthThermometerService"]
                    )
                else:
                    self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                        bt_dut_address=bt_dut_address, service_classes=["LinkLossService"]
                    )
                assert self.bt_client_address is not None, "Failed to start SMP Advertising"
                logger().info("SMP Advertising started successfully.")

                # Start Scanning
                logger().info(f"Attempt {retry + 1}: Starting BLE Scanning...")
                self.wifi_dut.interfaces.wifi.ble_start_scanning(
                    ble_client_address=self.bt_client_address, timeout=30
                )
                logger().info("BLE Scanning started successfully.")

                # Enable Power Save
                enable_wifi_ps = self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                assert enable_wifi_ps == 0, 'Failed to enable WLAN power save'
                enable_bt_ps = self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                    psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                    psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave
                )
                assert enable_bt_ps == 0, 'Failed to enable BT power save'

                # Stop Scanning
                logger().info(f"Attempt {retry + 1}: Stopping BLE Scanning...")
                self.wifi_dut.interfaces.wifi.ble_stop_scanning()
                logger().info("BLE Scanning stopped successfully.")
                time.sleep(5)

                # Initiate BLE Connection
                logger().info(f"Attempt {retry + 1}: Initiating BLE connection (timeout: {timeout} seconds)...")
                self.wifi_dut.interfaces.wifi.ble_connect(
                    ble_remote_dev_address=self.bt_client_address, ble_scan_interval=self.ble_scan_interval, ble_scan_window=self.ble_scan_window, ble_conn_interval_min= self.ble_conn_interval_min, ble_conn_interval_max=self.ble_conn_interval_min,ble_supervision_timeout=self.ble_supervision_timeout,
                    timeout=timeout,
                )
                time.sleep(60)

                # Check DUT State
                dut_state = int(self.wifi_dut.interfaces.wifi.ble_get_device_state())
                logger().info(f"DUT Connection Status: {dut_state}")

                if dut_state == BLEDeviceState.Connected:
                    logger().info("BLE Connection successful.")
                    break  # Exit retry loop if connection is successful
                elif dut_state == 0 or dut_state == 4:
                    logger().warning(f"DUT state is {dut_state}. Cancelling connection and retrying...")
                    #self.wifi_dut.interfaces.wifi.ble_connect_cancel(device_address=self.bt_client_address)
                    time.sleep(5)  # Wait before retrying
                    raise Exception(f"DUT state is {dut_state}. Retrying BLE connection...")
                else:
                    raise Exception(f"Unexpected DUT state: {dut_state}")

            except Exception as e:
                logger().error(f"Error during BLE operation on attempt {retry + 1}: {e}")
                if retry == retries - 1:
                    logger().error("Maximum retries reached. BLE operations failed.")
                    raise

        return self.bt_client_address

    def add_services_on_dut(self, uuid=None, Charc_serv=None):
        index = 1
        logger().info(f"adding services on dut")
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=uuid)
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=Charc_serv, service_handler_num=index,
                                                       permissions=0x10,
                                                       value_handler_num=index + 1)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=Charc_serv, value_handler_num=index + 1,
                                                      permissions=0x10)

    def resolving_services_on_remote(self, service_uuid=None, char_uuid=None):
        servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"

        char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                    service_uid=service_uuid,
                                                                                                    char_uid=char_uuid)
        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
        return char_path

    def tx_on_dut_custom(self, bt_client_address=None, char_path=None, char_uid=None):
        logger().info(f' *********************** subscribe to notifications ***********************')
        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=bt_client_address,
                                                                 buffer_mode=0,
                                                                 buffer_count=2)
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                     char_uid=char_uid)
        sw = Stopwatch()
        count = 0
        while sw.elapsed_sec < 600:
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(ble_remote_dev_address=self.ble_client_address, data=data)
            time.sleep(15)
            logger().info("******************** Validate Data ********************")
            notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
            logger().info(f' *********************** Notification is {notifications} ***********************')
            assert len(notifications) > 0, "received data is empty"
            assert notifications[count] == data, "Data Mismatched"
            count += 1

        logger().info(f' *********************** unsubscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)

    def tx_on_dut(self, char_path=None, char_uuid=None, data=None):
        sw = Stopwatch()
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                     char_uid=char_uuid)
        while sw.elapsed_sec <= 60:
            self.wifi_dut.interfaces.wifi.ble_set_local_att_value(notify_data=data, val_handle=12)
            time.sleep(3)
            logger().info("\n\n\n ***** validating Received notifications on Remote *****\n\n")
            notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uuid]
            logger().info(f"Notifications received on remote: {notifications}")
            # unsubscribe to notifications
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uuid)
        time.sleep(1)
        assert len(notifications) > 0, "received data is empty"
        assert data in notifications[0], "failed to fetch data"


    def check_device_state_on_dut(self):
        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

    def check_device_state_on_rasp(self):
        status = self.ble_client.interfaces.bluetooth.get_connection_status(self.bt_dut_address)
        logger().info(f"Connection status in remote device '{self.ble_client.name}' is:{status}")
        assert status, f"Remote device '{self.ble_client.name}' is not connected to DUT"

    def fetch_profiles(self, service=None, characterstic=None):
        logger().info(f"******************** get all profiles ********************")
        uuids = self.wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=self.bt_client_address)
        assert service.UUID.lower() in uuids is not None, "Could not fetch the profile"

        logger().info(" ******************** Resolving Profile ********************")
        start_handle, end_handle, data = self.wifi_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=self.bt_client_address, uuid=int(service.UUID, 16))
        assert start_handle is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch end handle.."

        char_uuids, write_handles, char_properties = self.wifi_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=self.bt_client_address,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
            async_timeout=60)
        logger().info(
            f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
            f"{char_properties}")

        assert characterstic in char_uuids, "Unable to find {} uuid"
        index = char_uuids.index(characterstic)
        logger().info(f"UUID's are:{char_uuids}")
        logger().info(f"write_handles:{write_handles}")
        logger().info(f"index:{index}")
        assert char_properties[index].isdigit(), "Character property found is not an integer"
        write_handle = int(write_handles[index], 16)
        logger().info(f"write_handle:{write_handle}")
        assert write_handle > 0, "Unable to get write handle for configured service"
        return write_handle

    def events_on_dut(self):
        tw = Stopwatch()
        Data_received_on_dut = []
        while tw.elapsed_sec < 10:
            events = self.wifi_dut.interfaces.wifi.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                    received_data = re.findall(r"att_length: 1, att_value: (.*)", event.event_data)
                    Data_received_on_dut = received_data + Data_received_on_dut
                    if len(Data_received_on_dut) >= 5:
                        break
        return Data_received_on_dut

    def btmon_validation_for_remote_tx(self, bt_mon_log_file=None, Data_received_on_dut=None):
        service_notifcations = []
        for data in Data_received_on_dut:
            service_data = ord(data)
            service_notifcations.append(service_data)
        with open(bt_mon_log_file, "r") as file_p:
            lines = file_p.readlines()
        acl_data_flag = att_flag = handle_flag = False
        data_on_remote = []
        flag = 0
        for line in lines:
            if "< ACL Data TX: Handle" in line:
                acl_data_flag = True
                continue
            elif "ATT: Handle Value" in line and acl_data_flag is True:
                att_flag = True
                continue
            elif "Handle:" in line:
                if "0x0010" in line and att_flag is True:
                    handle_flag = True
                continue

            elif "Data:" in line and "Data: 0000" not in line and acl_data_flag is True and att_flag is True and handle_flag is True:
                data_match = re.findall(r'Data:(.*)', line)
                data_on_remote = data_on_remote + data_match
                if len(data_on_remote) == len(service_notifcations):
                    for data in data_on_remote:
                        flag = 0
                        data_to_compare = int(data, 16)
                        if data_to_compare in service_notifcations:
                            flag = True
            else:
                pass
        assert flag, f"sent data is not matching with receiving data"
        return service_notifcations

    def disconnection_on_dut(self):
        logger().info(f"**********Disconnecting from dut**************")
        self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.bt_client_address)





def wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE, tcp_feat_bit=0,  wifi_stack_len=2048,
                    ble_stack_len=2048):
    config = {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
                                 | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | ext_custom_bit,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST ,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": wifi_stack_len, "priority": 8},
                "ble": {"count": 1, "stack_len": ble_stack_len, "priority": 8},
        },

        }

    return pytest.mark.config("wifi_dut", wifi=config)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
def test_ble_sdk_fetch_profiles_from_RD1_C19860(wifi_dut, ble_client, sl_collections):
    """verify slave connection and master connection from dut"""
    try:
        ble_obj = BleFunctionality(wifi_dut, ble_client, battery_service=True)
        bt_client_address = ble_obj.ble_gatt_scan()
        logger().info(f"Fetching all profiles...")

        retries = 3  # Maximum number of retries
        for retry in range(retries):
            uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
            if uuids:
                logger().info(f"Profiles fetched successfully: {uuids}")
                break
            else:
                logger().warning(f"Attempt {retry + 1}: Failed to fetch profiles. Retrying...")
                time.sleep(5)  # Wait before retrying
        else:
            assert False, "Failed to fetch profiles after maximum retries."
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        logger().info(" Issued BLE disconnect ")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        # logger().info(f"Removing services on dut")
        # wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=ble_obj.bt_dut_address)



@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
def test_ble_sdk_fetch_a_particular_profiles_from_RD1_C19861(wifi_dut, ble_client, sl_collections, utf_constants):
    try:
        ble_obj = BleFunctionality(wifi_dut, ble_client, battery_service=True)
        bt_client_address = ble_obj.ble_gatt_scan()
        ble_obj.check_device_state_on_dut()
        logger().info(f"Fetching all profiles...")

        retries = 3  # Maximum number of retries
        for retry in range(retries):
            uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
            if uuids:
                logger().info(f"Profiles fetched successfully: {uuids}")
                break
            else:
                logger().warning(f"Attempt {retry + 1}: Failed to fetch profiles. Retrying...")
                time.sleep(5)  # Wait before retrying
        else:
            assert False, "Failed to fetch profiles after maximum retries."
        assert BatteryService.UUID in uuids is not None, "Could not fetch the battery profile"
        logger().info(" Resolving Battery profile from RD1")
        start_handle, end_handle, data = wifi_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address,
            uuid=int(BatteryService.UUID, 16))
        assert start_handle is not None, "failed to fetch the RD1 address.."
        assert end_handle is not None, "failed to fetch the UUID.."
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        logger().info(" Issued BLE disconnect ")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        # logger().info(f"Removing services on dut")
        # wifi_dut.interfaces.wifi.ble_remove_service()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=ble_obj.bt_dut_address)

@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_disconnect"])
def test_ble_sdk_fetch_a_particular_value_of_descriptor_from_RD1_C19866(wifi_dut, ble_client, sl_collections, utf_constants):
    """To fetch particular values of descriptor"""
    try:
        logger().info(" ******* Start BLE GATT service ******* ")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=0)
        assert bt_dut_address, "Failed to load bt address..."
        ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, powersave=True, battery_service=True)
        bt_client_address = ble_obj.ble_adv()
        time.sleep(60)
        ble_obj.check_device_state_on_rasp()
        logger().info(f"get all profiles")
        uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
        assert BatteryService.UUID in uuids is not None, "Could not fetch the battery service profile"
        logger().info(" Resolving Battery profile from Dut")
        start_handle, end_handle, data = wifi_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address,
            uuid=int(BatteryService.UUID, 16))
        assert start_handle is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch the end handle.."
        uuids, write_handles, char_properties = wifi_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=bt_client_address,
            start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))
        logger().info(
            f"*********uuids, write_handles, char_properties: {uuids}, {write_handles}, {char_properties} ************")
        assert BatteryLevelCharacteristic.BLEVEL_UUID in uuids
        index = uuids.index(BatteryLevelCharacteristic.BLEVEL_UUID)
        assert char_properties[index].isdigit()
        assert BatteryLevelCharacteristic.prop_int == int(char_properties[index])
        write_handle = int(write_handles[index], 16)
        assert write_handle > 0
        logger().info(f"To fetch value of descriptor")
        wifi_dut.interfaces.wifi.ble_get_att_value_async(ble_remote_dev_address=bt_client_address, char_property=write_handle)
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        logger().info(" Issued BLE disconnect ")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
def test_ble_sdk_fetch_desc_from_RD1_C19864(wifi_dut, ble_client, sl_collections):
    try:
        ble_obj = BleFunctionality(wifi_dut, ble_client, HeartRate=True)
        bt_client_address = ble_obj.ble_gatt_scan()
        ble_obj.check_device_state_on_dut()
        logger().info(f"get all profiles")
        uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
        assert HeartRateService.UUID.lower() in uuids is not None, "Could not fetch the heartrate profile"
        logger().info(" Resolving Heartrate profile from RD1")
        start_handle, end_handle, data = wifi_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address,
            uuid=int(HeartRateService.UUID, 16))
        assert start_handle is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch end handle.."
        logger().info(f"********fetching descriptor*************")
        wifi_dut.interfaces.wifi.ble_get_att_descriptor(ble_devices_address=bt_client_address, start_handle=start_handle,
                                                       end_handle=end_handle)
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        logger().info(" Issued BLE disconnect ")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=ble_obj.bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_disconnect"])
def test_ble_sdk_read_value_of_descriptor_from_RD1_C19867(wifi_dut, ble_client, sl_collections, utf_constants):
    try:
        logger().info(" ******* Start BLE GATT service ******* ")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1)
        assert bt_dut_address, "Failed to load bt address..."
        ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, powersave=True, battery_heartrate=True, pair=True)
        bt_client_address = ble_obj.ble_adv()
        time.sleep(60)
        ble_obj.check_device_state_on_rasp()
        logger().info(f"get all profiles")
        uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
        assert BatteryService.UUID in uuids is not None, "Could not fetch the battery service profile"
        logger().info(" Resolving Battery profile from Dut")
        start_handle, end_handle, data = wifi_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address,
            uuid=int(BatteryService.UUID, 16))
        assert start_handle is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch the end handle.."
        logger().info(" Resolving heartrate profile from Dut")
        start_handle_1, end_handle_1, data = wifi_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address,
            uuid=int(HeartRateService.UUID, 16))
        assert start_handle_1 is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch the end handle.."
        logger().info(f"To fetch value of descriptor")
        att_values = wifi_dut.interfaces.wifi.ble_get_multiple_att(ble_remote_dev_address=bt_client_address,no_of_handles=2, handle_1=start_handle, handle_2=start_handle_1)
        logger().info(f"*********{att_values}*********")
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        logger().info(" Issued BLE disconnect ")
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
def test_ble_sdk_fetch_desc_that_are_not_supported_C19865(wifi_dut, ble_client, utf_constants, sl_collections):
    try:
        logger().info(" ******* Start BLE GATT Service ******* ")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
        assert bt_dut_address, "Failed to load bt address..."
        index = 1
        logger().info("********Adding Heartrate Service to the dut..UUID VALUE : 0x180D************")
        wifi_dut.interfaces.wifi.ble_add_service(uid=0x180D)
        # ble_add_char_serv_att 10807 26 1 2 -> Heart rate measurement(0x2A37)
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A37, service_handler_num=index, permissions=0x2,
                                                           value_handler_num=index + 1)
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A37, value_handler_num=index + 1, permissions=0x2)

        # ble_add_char_serv_att 10808 26 1 2 -> Body sensor location(0x2A38)
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A38, service_handler_num=index + 2,
                                                           value_handler_num=index + 3, permissions=0x2)
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A38, value_handler_num=index + 3, permissions=0x2)

        # ble_add_char_serv_att 10809 26 1 2 -> Heart rate control point(0x2A39)
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A39, service_handler_num=index + 4,
                                                           value_handler_num=index + 5, permissions=0x2)
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A39, value_handler_num=index + 5, permissions=0x2)
        logger().info("start ble advertising....")
        wifi_dut.interfaces.wifi.ble_start_advertising()

        enable_wifi_ps = wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps = wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'

        logger().info("scanning for ble client.. ")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                           service_classes=[HeartRateService])
        assert bt_client_address, "The client address is not found"
        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            if (
                    bt_dut_address in found_devices
                    and found_devices[bt_dut_address]
                    == wifi_dut.interfaces.wifi.ble_advertising_data
            ):
                device_found = True
                break

        ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found
        logger().info("connecting to dut....")
        ble_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        time.sleep(60)
        logger().info("verifying dut state after the conn......")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "Device isn't in connected state"
        logger().info(f"get all profiles")
        uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
        assert HeartRateService.UUID.lower() in uuids is not None, "Could not fetch the heartrate profile"
        logger().info(" Resolving Heartrate profile from RD1")
        start_handle, end_handle, data = wifi_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address,
            uuid=int(HeartRateService.UUID, 16))
        assert start_handle is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch end handle.."
        logger().info(f"********fetching descriptor*************")
        try:
            wifi_dut.interfaces.wifi.ble_get_att_descriptor(ble_devices_address=bt_client_address, start_handle=0x20,
                                                           end_handle=0x21)
        except Exception as Err:
            if "0x4a0a" in str(Err):
                logger().info(f"stop ap failed with : {Err} after giving it for 2nd time")
            else:
                raise Err
        logger().info(f"Ble disconnect from remote")
        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(1)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=bt_client_address,
                                   ble_dut_address=bt_dut_address)




@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_fetch_profiles_from_RD1_C19862(wifi_dut, ble_client, sl_collections):
    try:
        ble_obj = BleFunctionality(wifi_dut, ble_client)
        bt_client_address = ble_obj.ble_gatt_scan()
        ble_obj.check_device_state_on_dut()
        logger().info(f"Fetching all profiles...")
        retries = 3  # Maximum number of retries
        for retry in range(retries):
            uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
            if uuids:
                logger().info(f"Profiles fetched successfully: {uuids}")
                break
            else:
                logger().warning(f"Attempt {retry + 1}: Failed to fetch profiles. Retrying...")
                time.sleep(5)  # Wait before retrying
        else:
            assert False, "Failed to fetch profiles after maximum retries."
        logger().info(" Resolving Battery profile from RD1")
        try:
            wifi_dut.interfaces.wifi.ble_get_profile_async(
                    ble_remote_dev_address=bt_client_address,
                    uuid=int(BatteryService.UUID, 16))
        except Exception as Err:
            if "0x4a0a" in str(Err):
                logger().info(f"stop ap failed with : {Err} after giving it for 2nd time")
            else:
                raise Err
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        logger().info(" Issued BLE disconnect ")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.bt_dut_address)
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=ble_obj.bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_gatt_primary_services_C667632(wifi_dut, ble_client, sl_collections):
    """
    1.initialize the ble in dut
    2.Advertise on remote
    3.Scan and advertise from dut
    4.Connect and check stability for 60secs
    5.fetch the profiles from dut
    6.Disconnect the dut

    """
    try:
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
        assert bt_dut_address is not None, "gatt init failed in DUT"
        wifi_dut.interfaces.wifi.bt_set_local_name("BLE_AUTOMATION")
        status = wifi_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f" ======= Getting the local name : {status}")
        ble_client.interfaces.bluetooth.close()
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
        )
        assert bt_client_address is not None, "init failed for rpi"
        # Start scanning and connect to ble client
        wifi_dut.interfaces.wifi.ble_start_scanning(
            ble_client_address=bt_client_address, timeout=30
        )
        logger().info("Set DUT in advertise mode")
        wifi_dut.interfaces.wifi.ble_start_advertising()
        enable_wifi_ps = wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps = wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        timeout = 120
        logger().info(f"Initiating connection this can take upto {timeout} seconds....")
        wifi_dut.interfaces.wifi.ble_connect(
            ble_remote_dev_address=bt_client_address, ble_scan_interval=160, ble_scan_window=80,
            timeout=timeout,
        )
        time.sleep(60)
        logger().info("verifying dut state after the conn......")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == 9, "Device isn't in connected & advertising state "
        logger().info(f"get all profiles")
        uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
        logger().info(f"*****primary uuids: {uuids}**********")
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        logger().info(" Issued BLE disconnect ")
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)



@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_gatt_secondary_services_C667633(wifi_dut, ble_client, sl_collections):
    """
       1.initialize the ble in dut
       2.Advertise on remote and add the service on remote
       3.Scan and advertise from dut
       4.Connect and check stability for 60secs
       5.fetch the profiles from dut
       6.Disconnect the dut

       """
    try:
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
        assert bt_dut_address is not None, "gatt init failed in DUT"
        wifi_dut.interfaces.wifi.bt_set_local_name("BLE_AUTOMATION")
        status = wifi_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f" ======= Getting the local name : {status}")
        ble_client.interfaces.bluetooth.close()
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address, service_classes=["HeartRateService"]
        )
        assert bt_client_address is not None, "init failed for rpi"
        wifi_dut.interfaces.wifi.ble_start_scanning(
            ble_client_address=bt_client_address, timeout=30
        )
        logger().info("Set DUT in advertise mode")
        wifi_dut.interfaces.wifi.ble_start_advertising()
        enable_wifi_ps = wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps = wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'
        time.sleep(10)
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        timeout = 120
        logger().info(f"Initiating connection this can take upto {timeout} seconds....")
        wifi_dut.interfaces.wifi.ble_connect(
            ble_remote_dev_address=bt_client_address, ble_scan_interval=160, ble_scan_window=80,
            timeout=timeout,
        )
        time.sleep(60)
        logger().info("verifying dut state after the conn......")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == 9, "Device isn't in connected state"
        logger().info(f"get all profiles")
        uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
        assert HeartRateService.UUID.lower() in uuids is not None, "Could not fetch the heartrate profile"
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        logger().info(" Issued BLE disconnect ")
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=bt_client_address,
                                   ble_dut_address=bt_dut_address)





@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
def test_ble_sdk_fetch_charecteristics_from_RD1_C19863(wifi_dut, ble_client, sl_collections):
    """Verify characterstics values from Dut"""
    try:
        ble_obj = BleFunctionality(wifi_dut, ble_client, ht=True)
        bt_client_address = ble_obj.ble_gatt_scan()
        ble_obj.check_device_state_on_dut()
        logger().info(f"get all profiles")
        uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
        assert HeartRateService.UUID.lower() in uuids is not None, "Could not fetch the heart rate profile"
        logger().info(" Resolving Battery profile from RD1")
        start_handle, end_handle, data = wifi_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address,
            uuid=int(HeartRateService.UUID, 16))
        assert start_handle is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch end handle.."
        uuids, write_handles, char_properties = wifi_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=bt_client_address,
            start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))
        logger().info(f"*********uuids, write_handles, char_properties: {uuids}, {write_handles}, {char_properties} ************")
        assert HeartRateMeasurementCharacterstic.HR_Measure_UUID in uuids
        index = uuids.index(HeartRateMeasurementCharacterstic.HR_Measure_UUID)
        assert char_properties[index].isdigit()
        assert HeartRateMeasurementCharacterstic.prop_int == int(char_properties[index])
        write_handle = int(write_handles[index], 16)
        assert write_handle > 0
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        logger().info(" Issued BLE disconnect ")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=bt_client_address,
                                   ble_dut_address=ble_obj.bt_dut_address)



@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_ble_dut_as_slave_to_set_attribute_value_to_descriptors_C19869(ble_dut, ble_client,
                                                                                        sl_collections):
    bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_master_with_30_bytes_write_with_response_buffer_1_"
                            f"C19869_{int(time.time())}.log")
    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name):
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj.ble_gatt_init()

            ble_obj.set_local_get_local_name_validation()
            # Set DUT To Advertising
            ble_obj.advertising_dut()
            # Power Save Mode WLAN And BLE
            ble_obj.power_save()
            # Scan and Connect From Remote Device
            ble_client_address = ble_obj.scan_conn_from_remote_device("HeartRateService")

            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data),
                                                     write_content=data)

            logger().info(".... checking for ble connectivity stability ....")
            time.sleep(60)
            # get remote device profile
            write_handle = ble_obj.service_discovery_on_remote(HeartRateService.UUID,
                                                               HeartRateControlPointCharacteristic.UUID,
                                                               HeartRateControlPointCharacteristic)
            # Configure buffer mode
            ble_obj.configure_buffer_mode(mode=1, count=2)
            # Write and send BLE 30 bytes of write with response data using the below API
            write_data_count = ble_obj.gatt_write_with_resp(write_handle=write_handle, data=data, write_time=300,
                                                            data_length=30)

        # Validating Write With Response Data
        ble_obj.validate_write_with_response(bt_mon_log_file=bt_mon_log_file_name, write_handle=write_handle,
                                             data=data, write_data_count=write_data_count, request="ATT: Write Request")

        ble_obj.check_device_state_on_dut()
        # Disconnect From Remote Device
        ble_obj.disconnect_from_remote()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client,
                                   ble_client_address=ble_client_address,
                                   ble_dut_address=ble_dut_address)




@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_ble_dut_as_slave_to_set_different_attribute_value_to_descriptors_C19870(ble_dut, ble_client,
                                                                                        sl_collections):
    bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_master_with_30_bytes_write_with_response_buffer_1_"
                            f"C19870_{int(time.time())}.log")
    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name):
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj.ble_gatt_init()

            ble_obj.set_local_get_local_name_validation()
            # Set DUT To Advertising
            ble_obj.advertising_dut()
            # Power Save Mode WLAN And BLE
            ble_obj.power_save()
            # Scan and Connect From Remote Device
            ble_client_address = ble_obj.scan_conn_from_remote_device("HeartRateService")

            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data),
                                                     write_content=data)

            logger().info(".... checking for ble connectivity stability ....")
            time.sleep(60)
            # get remote device profile
            write_handle = ble_obj.service_discovery_on_remote(HeartRateService.UUID,
                                                               HeartRateControlPointCharacteristic.UUID,
                                                               HeartRateControlPointCharacteristic)
            # Configure buffer mode
            ble_obj.configure_buffer_mode(mode=1, count=2)
            # Write and send BLE 232 bytes of write with response data using the below API
            write_data_count = ble_obj.gatt_write_with_resp(write_handle=write_handle, data=data, write_time=300,
                                                            data_length=50)

        # Validating Write With Response Data
        ble_obj.validate_write_with_response(bt_mon_log_file=bt_mon_log_file_name, write_handle=write_handle,
                                             data=data, write_data_count=write_data_count, request="ATT: Write Request")

        ble_obj.check_device_state_on_dut()
        # Disconnect From Remote Device
        ble_obj.disconnect_from_remote()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client,
                                   ble_client_address=ble_client_address,
                                   ble_dut_address=ble_dut_address)




@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_ble_dut_as_slave_prepare_execute_C19871(ble_dut, ble_client,
                                                                                       sl_collections):
    bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_slave_"
                            f"C19871_{int(time.time())}.log")
    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name):
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj.ble_gatt_init(set_smp=1)
            # Set DUT Local name
            logger().info("Creating new custom gatt service in DUT")
            ble_obj.set_local_get_local_name_validation()
            # Set DUT To Advertising
            ble_obj.advertising_dut()
            # Power Save Mode WLAN And BLE
            ble_obj.power_save()
            # Scan and Connect From Remote Device
            ble_client_address = ble_obj.scan_conn_from_remote_device("HeartRateService")

            time.sleep(60)
            logger().info(".... checking for ble connectivity stability ....")
            ble_obj.check_device_state_on_dut()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
            allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
            logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
            ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data),
                                                     write_content=data)
            #get remote device profile
            write_handle = ble_obj.service_discovery_on_remote(HeartRateService.UUID,
                                                               HeartRateControlPointCharacteristic.UUID,
                                                               HeartRateControlPointCharacteristic)
            ble_dut.interfaces.bluetooth.ble_prepare_write_async(ble_remote_dev_address=ble_client_address, handle=write_handle, offset=1, data_len=10, data=data)
            ble_dut.interfaces.bluetooth.ble_execute_write_async(ble_remote_dev_address=ble_client_address, exe_flag=1)
            time.sleep(30)
        ble_obj.validate_write_with_response(bt_mon_log_file=bt_mon_log_file_name, write_handle=write_handle,
                                             data=data, write_data_count=2, request="ATT: Prepare Write Request")
        ble_obj.check_device_state_on_dut()
        # Disconnect from dut
        ble_obj.disconnect_form_dut()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client,
                                   ble_client_address=ble_client_address,
                                   ble_dut_address=ble_dut_address)



@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_properties_of_a_characterstic_C667635(wifi_dut, ble_client, sl_collections, utf_constants):
    """ Validate BLE Tx and Rx as slave by configuring data length with 100bytes with Duty cycling"""
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path="./reports/test_ble_slave_tx_rx_100_bytes_C19928.log"):
            iter_count = utf_constants.get("iter_count")
            logger().info(f"iter_count:{iter_count}")
            for count in range(iter_count):
                logger().info("*********************** Start BLE in DUT ***********************")
                ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=0)
                assert ble_dut_address, "failed to initialize ble in dut"
                wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)
                wifi_dut.interfaces.wifi.ble_start_advertising()
                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                wifi_dut.interfaces.wifi.enable_bt_power_save()
                ble_client_address= sl_collections.scan_from_remote_device(wifi_dut=wifi_dut, ble_client=ble_client,
                                                                           ble_dut_address=ble_dut_address,
                                                                           services=["HealthThermometerService"])
                logger().info("*********************** connect to ble dut ***********************")
                ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_address)
                logger().info(".... checking for ble connectivity stability ....")
                time.sleep(60)
                logger().info("******************** get connection state")
                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "********************* device is in disconnection state"
                services = ble_client.interfaces.bluetooth.gatt_adapter.get_resolved_services_and_characteristics()
                logger().info(f"services: {services}")
                # Fetch flags for the given UUID
                uuid_to_fetch = '00001aa1-0000-1000-8000-00805f9b34fb'
                flags = []
                for service_uuid, service_data in services.items():
                   if service_uuid == uuid_to_fetch:
                       for char_data in service_data['characteristics'].values():
                           flags.extend(char_data['flags'])
                logger().info(f"properties of a characterstic: {flags}")
                logger().info("*********************** Disconnecting from DUT ***********************")
                ble_client.interfaces.bluetooth.disconnect(ble_dut_address)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        # wifi_dut.interfaces.wifi.memory_free(address=allocated_mem_addr)
        ble_client.interfaces.bluetooth.close()
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_client_address,
                                   ble_dut_address=ble_dut_address)

@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_enable_heartrate_service_in_client_role_C19880(wifi_dut, ble_client, sl_collections):
    """ENABLE HEART RATE SERVICE IN CLIENT ROLE"""
    bt_mon_log_file = "reports/test_ble_sdk_C19880"
    try:
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
        assert bt_dut_address is not None, "gatt init failed in DUT"
        ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, ble_start=False, HeartRate=True)
        bt_client_address = ble_obj.ble_gatt_scan()
        ble_obj.check_device_state_on_dut()
        write_handle = ble_obj.fetch_profiles(service=HeartRateService, characterstic=HeartRateMeasurementCharacterstic.HR_Measure_UUID)
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file):
            logger().info(f"Enabling notification on dut")
            wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=bt_client_address,
                                                            handle=(write_handle + 1), enable_notify=1)
            time.sleep(10)
            wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=bt_client_address,
                                                            handle=(write_handle + 1), enable_notify=0)
        Data_received_on_dut = ble_obj.events_on_dut()
        heartrate_notifcations = ble_obj.btmon_validation_for_remote_tx(bt_mon_log_file=bt_mon_log_file, Data_received_on_dut=Data_received_on_dut)
        for data in heartrate_notifcations:
            notification = "bpm:" + str(data)
            logger().info(f"Notifications received on dut: {notification}")
        ble_obj.disconnection_on_dut()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)



@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_enable_battery_service_in_client_role_C19882(wifi_dut, ble_client, sl_collections):
    """ENABLE Battery SERVICE IN CLIENT ROLE"""
    bt_mon_log_file = "reports/test_ble_sdk_C19882"
    try:
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=0)
        assert bt_dut_address is not None, "gatt init failed in DUT"
        ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, ble_start=False, battery_service=True)
        bt_client_address = ble_obj.ble_gatt_scan()
        ble_obj.check_device_state_on_dut()
        write_handle = ble_obj.fetch_profiles(service=BatteryService, characterstic=BatteryLevelCharacteristic.BLEVEL_UUID)
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file):
            wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=bt_client_address,
                                                            handle=(write_handle + 1), enable_notify=1)
            time.sleep(10)
            wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=bt_client_address,
                                                            handle=(write_handle + 1), enable_notify=0)
        data = ble_obj.events_on_dut()
        battery_notifcations = ble_obj.btmon_validation_for_remote_tx(bt_mon_log_file=bt_mon_log_file, Data_received_on_dut=data)
        for data in battery_notifcations:
            Notification = str(data) + "%"
            logger().info(f"Notifications received on dut: {Notification}")
        ble_obj.disconnection_on_dut()


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)



@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_enable_health_thermomter_service_in_client_role_C19886(wifi_dut, ble_client,  sl_collections):
    """ENABLE Blood pressure SERVICE IN CLIENT ROLE"""
    bt_mon_log_file = "reports/test_wifi_sdk_C19886"
    try:
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=0)
        assert bt_dut_address is not None, "gatt init failed in DUT"
        ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, ble_start=False, thermometer=True)
        bt_client_address = ble_obj.ble_gatt_scan()
        ble_obj.check_device_state_on_dut()
        write_handle = ble_obj.fetch_profiles(service=HealthThermometerService, characterstic=HealthThermometerMeasurementCharacteristic.Thermo_Level_UUID)
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file):
            wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=bt_client_address,
                                                            handle=(write_handle + 1), enable_notify=1)
            time.sleep(10)
            wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=bt_client_address,
                                                            handle=(write_handle + 1), enable_notify=0)

        Data= ble_obj.events_on_dut()
        health_thermomter_notifcations = ble_obj.btmon_validation_for_remote_tx(bt_mon_log_file=bt_mon_log_file, Data_received_on_dut=Data)
        for data in health_thermomter_notifcations:
            notification = str(data) + "'C"
            logger().info(f"Notifications received on dut: {notification}")
        ble_obj.disconnection_on_dut()


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)



@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan"])
def test_ble_sdk_enable_glucose_service_in_client_role_C19888(wifi_dut, ble_client, sl_collections):
    """ENABLE Glucose SERVICE IN CLIENT ROLE"""
    bt_mon_log_file = "reports/test_wifi_sdk_C19888"
    try:
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=0)
        assert bt_dut_address is not None, "gatt init failed in DUT"
        ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, ble_start=False, glucose=True)
        bt_client_address = ble_obj.ble_gatt_scan()
        ble_obj.check_device_state_on_dut()
        write_handle = ble_obj.fetch_profiles(service=GlucoseService, characterstic=GlucoseMeasurementCharacteristic.Measure_UUID.lower())
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file):
            wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=bt_client_address,
                                                            handle=(write_handle + 1), enable_notify=1)
            time.sleep(10)
            wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=bt_client_address,
                                                            handle=(write_handle + 1), enable_notify=0)

        Data= ble_obj.events_on_dut()
        glucose_notifcations = ble_obj.btmon_validation_for_remote_tx(bt_mon_log_file=bt_mon_log_file, Data_received_on_dut=Data)
        for data in glucose_notifcations:
            logger().info(f"******************")
            Notification = str(data) + "mg/L"
            logger().info(f"Notifications received on dut: {Notification}")
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)


@wifi_dut_marker(ext_custom_bit=0)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_hogp_smp_slave_mode_C703319(ble_dut, ble_client, sl_collections):
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_hogp_smp_slave_mode_C703319.log_{int(time.time())}",
    ) as bt_logs:
        try:
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            ble_dut_addr = ble_dut.interfaces.wifi.ble_gatt_start()
            assert ble_dut_addr, "FAILED TO LOAD BT ADDRESS..."
            logger().info("....ADDING HID SERVICE....")
            ble_dut.interfaces.wifi.ble_add_hid_service()
            ble_obj.advertising_dut()
            # Power Save Mode WLAN And BLE
            ble_obj.power_save()
            # Scan and Connect From Remote Device
            ble_client_address = sl_collections.scan_from_remote_device(wifi_dut=ble_dut, ble_client=ble_client, ble_dut_address=ble_dut_addr)

            logger().info("Connecting to the DUT with MAC address...")
            ble_client.interfaces.bluetooth.pair_and_connect(ble_dut_addr, timeout=30)
            time.sleep(60)
            ble_obj.check_device_state_on_dut()
            test_data = ["0xb", "0x0", "0x12", "0x0", "0xa", "0x0"]
            test_data_expected_from_raspi = [
                "11,00,00,0b,00,00,00,00,00,00,00,00",
                "11,00,00,00,00,00,00,00,00,00,00,00",
                "11,00,00,12,00,00,00,00,00,00,00,00",
                "11,00,00,00,00,00,00,00,00,00,00,00",
                "11,00,00,0a,00,00,00,00,00,00,00,00",
                "11,00,00,00,00,00,00,00,00,00,00,00",
            ]
            with HidRecorder() as hid_recorder:
                for item in test_data:
                    ble_dut.interfaces.wifi.ble_hid_send_interrupt(item)
                    time.sleep(0.5)
                hid_logs = hid_recorder.logs()

            assert len(hid_logs) == len(test_data), "LENGTH OF HID DATA DOESN'T MATCH..."
            for i in range(len(test_data)):
                assert hid_logs[i] == test_data_expected_from_raspi[i], f"HID DATA {hid_logs[i]} DOESN'T MATCH WITH " \
                                                                        f"EXPECTED DATA {test_data_expected_from_raspi[i]}..."
            time.sleep(2)
        except Exception as Ex:
            sl_collections.exception_handling(wifi_dut=ble_dut, exception=Ex)
        finally:
            ble_client.interfaces.bluetooth.disconnect(ble_dut_addr)
            time.sleep(2)
            ble_client.interfaces.bluetooth.remove_device(ble_dut_addr)
            sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client,
                                       ble_client_address=ble_client_address,
                                       ble_dut_address=ble_dut_addr)

@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
def test_ble_sdk_connect_disconnect_multiple_times_from_RD1_C19875(wifi_dut, ble_client, sl_collections):
    """verify gatt connection and disconnection multiple times"""
    try:
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(bond_info=1)
        assert bt_dut_address is not None, "gatt init failed in DUT"
        timeout = 120
        for i in range(0, 5):
            wifi_dut.interfaces.wifi.ble_set_smp(set_smp=1)
            ble_client.interfaces.bluetooth.close()
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address, service_classes=["BatteryService"]
            )
            assert bt_client_address is not None, "init failed for rpi"
            logger().info(f"Start scanning")
            wifi_dut.interfaces.wifi.ble_start_scanning(
                ble_client_address=bt_client_address, timeout=30
            )
            if i == 0:
                logger().info(f"Enabling powersave")
                enable_wifi_ps = wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                assert enable_wifi_ps == 0, 'failed to enable wlan power save'
                enable_bt_ps = wifi_dut.interfaces.wifi.enable_bt_power_save(
                    psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                    psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
                assert enable_bt_ps == 0, 'failed to enable bt power save'
            wifi_dut.interfaces.wifi.ble_stop_scanning()
            time.sleep(5)
            logger().info(f"Initiating connection this can take upto {timeout} seconds....")
            wifi_dut.interfaces.wifi.ble_connect(
                ble_remote_dev_address=bt_client_address, ble_scan_interval=160, ble_scan_window=80,
                timeout=timeout,
            )
            time.sleep(60)
            logger().info("Checking connection status of BLE")
            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            logger().info(f"get all profiles")
            uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
            assert BatteryService.UUID in uuids is not None, "Could not fetch the battery profile"
            wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
            logger().info(" Issued BLE disconnect ")
            time.sleep(5)
            ble_client.interfaces.bluetooth.remove_device(bt_dut_address=bt_dut_address)
            logger().info(f"*******iteration: {i+1}***********")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        ble_client.interfaces.bluetooth.close()


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_link_loss_profiles_from_rd1_c19874(wifi_dut, ble_client, sl_collections):
    try:
        service_uid = "00001803-0000-1000-8000-00805f9b34fb"
        char_uid = "00002a06-0000-1000-8000-00805f9b34fb"
        # BLE DUT initialization
        logger().info(" ******* Start BLE GATT service ******* ")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address, "Failed to load bt address..."
        # adding services, attributes and values
        wifi_dut.interfaces.wifi.ble_add_service(uid=0x1803)
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A06)
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A06)
        ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, powersave=True)
        bt_client_address = ble_obj.ble_adv()
        time.sleep(60)
        ble_obj.check_device_state_on_rasp()
        servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"
        char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                    service_uid=service_uid,
                                                                                                    char_uid=char_uid)

        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
        for i in range(0, 3):
            data = str(i)
            logger().info(f"The data being sent is {data}")
            ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(char_path=char_path, data=data)
            time.sleep(1)
            result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            received = re.search(r"\d+(\.\d+)?", result)
            logger().info(f"The data received is {received.group(0)}")
            assert received.group(0) == data, "Data isn't matching"

        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(1)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)

@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_enable_heartrate_service_in_server_role_C19879(wifi_dut, ble_client, utf_constants,
                                                                sl_collections):
    """ENABLE HEART RATE SERVICE IN SERVER ROLE"""
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_C19879_{int(time.time())}") as bt_logs:
            service_uuid = "0000180d-0000-1000-8000-00805f9b34fb"
            char_uuid = "00002a37-0000-1000-8000-00805f9b34fb"
            data = "74bpm"
            logger().info(" ******* Start BLE Service ******* ")
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=0)
            assert bt_dut_address, "Failed to load bt address..."
            ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, powersave=True)
            logger().info(f"Adding heartrate service on dut")
            ble_obj.add_services_on_dut(uuid=0x180D, Charc_serv=0x2A37)
            bt_client_address = ble_obj.ble_adv()
            time.sleep(60)
            ble_obj.check_device_state_on_rasp()
            char_path = ble_obj.resolving_services_on_remote(service_uuid=service_uuid, char_uuid=char_uuid)
            ble_obj.tx_on_dut(char_path=char_path, char_uuid=char_uuid, data=data)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        # if char_path:
        #     logger().info(f'*********************** disabling and unsubscribe to notifications ***********************')
        #     ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        #     ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uuid)
        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(2)
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)

@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_enable_blood_pressure_in_server_role_C19883(wifi_dut, ble_client, utf_constants, sl_collections):
    """ENABLE BLOOD PRESSURE IN SERVER ROLE"""
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_C19883_{int(time.time())}") as bt_logs:
            service_uuid = "00001810-0000-1000-8000-00805f9b34fb"  # BloodPressureService
            char_uuid = "00002a35-0000-1000-8000-00805f9b34fb"  # BatteryLevelCharacteristic
            data = "83.0"
            logger().info(" ******* Start BLE Service ******* ")
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=0)
            assert bt_dut_address, "Failed to load bt address..."
            ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, powersave=True)
            logger().info(f"Adding blood pressure on dut")
            ble_obj.add_services_on_dut(uuid=0x1810, Charc_serv=0x2A35)
            bt_client_address = ble_obj.ble_adv()
            time.sleep(60)
            ble_obj.check_device_state_on_rasp()
            char_path = ble_obj.resolving_services_on_remote(service_uuid=service_uuid, char_uuid=char_uuid)
            ble_obj.tx_on_dut(char_path=char_path, char_uuid=char_uuid, data=data)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        # if char_path:
        #     logger().info(f'*********************** disabling and unsubscribe to notifications ***********************')
        #     ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        #     ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uuid)
        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(2)
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)

@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_enable_health_thermometer_in_server_role_C19885(wifi_dut, ble_client, sl_collections):
    """ENABLE health thermometer IN SERVER ROLE"""
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_C19885_{int(time.time())}") as bt_logs:
            service_uuid = "00001809-0000-1000-8000-00805f9b34fb"  # health_thermometer_service
            char_uuid = "00002a1c-0000-1000-8000-00805f9b34fb"
            data = "38.0'c"
            logger().info(" ******* Start BLE Service ******* ")
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=0, set_smp=0)
            assert bt_dut_address, "Failed to load bt address..."
            ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, powersave=True)
            logger().info(f"Adding health thermometer on dut")
            ble_obj.add_services_on_dut(uuid=0x1809, Charc_serv=0x2A1C)
            bt_client_address = ble_obj.ble_adv()
            time.sleep(60)
            ble_obj.check_device_state_on_rasp()
            char_path = ble_obj.resolving_services_on_remote(service_uuid=service_uuid, char_uuid=char_uuid)
            ble_obj.tx_on_dut(char_path=char_path, char_uuid=char_uuid, data=data)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        # if char_path:
        #     logger().info(f'*********************** disabling and unsubscribe to notifications ***********************')
        #     ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        #     ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uuid)
        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(2)
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)

@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_enable_battery_service_in_server_role_C19881(wifi_dut, ble_client, sl_collections):
    """ENABLE BATTERY SERVICE IN SERVER ROLE"""
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_C19879_{int(time.time())}") as bt_logs:
            service_uuid = "0000180f-0000-1000-8000-00805f9b34fb"
            char_uuid = "00002a19-0000-1000-8000-00805f9b34fb"
            data = "20%"
            logger().info(" ******* Start BLE Service ******* ")
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=0)
            assert bt_dut_address, "Failed to load bt address..."
            ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, powersave=True)
            logger().info(f"Adding battery service on dut")
            ble_obj.add_services_on_dut(uuid=0x180f, Charc_serv=0x2A19)
            bt_client_address = ble_obj.ble_adv()
            time.sleep(60)
            ble_obj.check_device_state_on_rasp()
            char_path = ble_obj.resolving_services_on_remote(service_uuid=service_uuid, char_uuid=char_uuid)
            ble_obj.tx_on_dut(char_path=char_path, char_uuid=char_uuid, data=data)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(2)
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)

@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_enable_enable_notify_C667636(wifi_dut, ble_client, utf_constants, sl_collections):
    """ENABLE HEART RATE SERVICE IN SERVER ROLE"""
    logger().info(" ******* Start BLE Service ******* ")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=0)
    assert bt_dut_address, "Failed to load bt address..."
    try:
        service_uuid = "0000180d-0000-1000-8000-00805f9b34fb"
        char_uuid = "00002a37-0000-1000-8000-00805f9b34fb"
        data = "74bpm"
        ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, powersave=True)
        logger().info(f"Adding heartrate service on dut")
        ble_obj.add_services_on_dut(uuid=0x180D, Charc_serv=0x2A37)
        ble_client_address = ble_obj.ble_adv()
        time.sleep(60)
        servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"

        char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                    service_uid=service_uuid,
                                                                                                    char_uid=char_uuid)
        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
        logger().info(f"*******Enabling notifications on remote")
        ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                char_uid=char_uuid)
        wifi_dut.interfaces.wifi.ble_set_local_att_value(notify_data=data, val_handle=12)
        time.sleep(3)
        logger().info("\n\n\n ***** validating Received notifications on Remote *****\n\n")
        notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uuid]
        logger().info(f"Notifications received on remote: {notifications}")
        # unsubscribe to notifications
        logger().info(f"*******Disabling notifications on remote")
        ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uuid)
        time.sleep(1)

        ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                char_uid=char_uuid)
        wifi_dut.interfaces.wifi.ble_set_local_att_value(notify_data=data, val_handle=12)
        time.sleep(3)
        logger().info("\n\n\n ***** validating Received notifications on Remote *****\n\n")
        notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uuid]
        logger().info(f"Notifications received on remote: {notifications}")
        # unsubscribe to notifications
        ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uuid)
        time.sleep(1)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(2)
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_client_address,
                                   ble_dut_address=bt_dut_address)

@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_enable_enable_disable_indication_C667637(wifi_dut, ble_client, sl_collections):
    """ENABLE HEART RATE SERVICE IN SERVER ROLE"""
    logger().info(" ******* Start BLE Service ******* ")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=0)
    assert bt_dut_address, "Failed to load bt address..."
    try:
        service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, powersave=True)
        logger().info(f"Adding heartrate service on dut")
        ble_obj.add_services_on_dut(uuid=0x1AA1, Charc_serv=0x1BB1)
        ble_client_address = ble_obj.ble_adv()
        time.sleep(60)
        servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"

        char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                    service_uid=service_uid,
                                                                                                    char_uid=char_uid)
        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
        logger().info(f"*******Enabling notifications on remote")
        ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                char_uid=char_uid)
        wifi_dut.interfaces.wifi.ble_indicate_value(ble_remote_dev_address=ble_client_address,
                                                    handle=12, data=data, data_length=20)
        time.sleep(3)
        logger().info("\n\n\n ***** validating Received notifications on Remote *****\n\n")
        notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
        logger().info(f"Notifications received on remote: {notifications}")
        # unsubscribe to notifications
        logger().info(f"*******Disabling notifications on remote")
        ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        time.sleep(1)

        ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                char_uid=char_uid)
        wifi_dut.interfaces.wifi.ble_indicate_value(ble_remote_dev_address=ble_client_address,
                                                    handle=12, data=data, data_length=20)
        time.sleep(3)
        logger().info("\n\n\n ***** validating Received notifications on Remote *****\n\n")
        notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
        logger().info(f"Notifications received on remote: {notifications}")
        # unsubscribe to notifications
        ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        time.sleep(1)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(2)
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_client_address,
                                   ble_dut_address=bt_dut_address)

@wifi_dut_marker(ext_custom_bit=0)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_enable_heartrate_service_in_server_role_C703320(wifi_dut, ble_client, sl_collections):
    """ENABLE HEART RATE SERVICE IN SERVER ROLE"""
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_C703320_{int(time.time())}") as bt_logs:
            service_uuid = "0000180d-0000-1000-8000-00805f9b34fb"
            char_uuid = "00002a37-0000-1000-8000-00805f9b34fb"
            data = "74bpm"
            logger().info(" ******* Start BLE Service ******* ")
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=0)
            assert bt_dut_address, "Failed to load bt address..."
            ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, powersave=True)
            logger().info(f"Adding heartrate service on dut")
            ble_obj.add_services_on_dut(uuid=0x180D, Charc_serv=0x2A37)
            ble_client_address = ble_obj.ble_adv()
            time.sleep(60)
            ble_obj.check_device_state_on_rasp()
            char_path = ble_obj.resolving_services_on_remote(service_uuid=service_uuid, char_uuid=char_uuid)
            ble_obj.tx_on_dut(char_path=char_path, char_uuid=char_uuid, data=data)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(2)
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_client_address,
                                   ble_dut_address=bt_dut_address)

@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_validate_adding_service_in_slave_role_C19878(ble_dut, ble_client, sl_collections):
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_C19878_{int(time.time())}.log") as bt_logs:
            service_uid = "0000180d-0000-1000-8000-00805f9b34fb"
            char_uid1 = "00002a37-0000-1000-8000-00805f9b34fb"
            char_uid2 = "00002a38-0000-1000-8000-00805f9b34fb"
            char_uid3 = "00002a39-0000-1000-8000-00805f9b34fb"
            logger().info(" ******* Start BLE GATT Service ******* ")
            bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            assert bt_dut_address, "Failed to load bt address..."
            index = 1
            logger().info("********Adding Heartrate Service to the dut..UUID VALUE : 0x180D************")
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x180D)
            # ble_add_char_serv_att 10807 26 1 2 -> Heart rate measurement(0x2A37)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A37, service_handler_num=index,
                                                               permissions=0x2,
                                                               value_handler_num=index + 1)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A37, value_handler_num=index + 1,
                                                              permissions=0x2)

            # ble_add_char_serv_att 10808 26 1 2 -> Body sensor location(0x2A38)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A38, service_handler_num=index + 2,
                                                               value_handler_num=index + 3, permissions=0x2)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A38, value_handler_num=index + 3,
                                                              permissions=0x2)

            # ble_add_char_serv_att 10809 26 1 2 -> Heart rate control point(0x2A39)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A39, service_handler_num=index + 4,
                                                               value_handler_num=index + 5, permissions=0x2)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A39, value_handler_num=index + 5,
                                                              permissions=0x2)
            logger().info("start ble advertising....")
            ble_dut.interfaces.bluetooth.ble_start_advertising()

            enable_wifi_ps = ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')
            assert enable_wifi_ps == 0, 'failed to enable wlan power save'
            enable_bt_ps = ble_dut.interfaces.bluetooth.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            assert enable_bt_ps == 0, 'failed to enable bt power save'
            ble_client.interfaces.bluetooth.close()

            logger().info("scanning for ble client.. ")
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                               service_classes=[HeartRateService])
            assert bt_client_address, "The client address is not found"
            time.sleep(5)
            ble_client.interfaces.bluetooth.stop_scanning()

            logger().info("verifying device in scan list...")
            found_devices = ble_client.interfaces.bluetooth.get_devices()

            assert ble_dut.interfaces.bluetooth.ble_address in found_devices, "failed to find dut address in scan list..."
            assert (found_devices[
                        ble_dut.interfaces.bluetooth.ble_address] == ble_dut.interfaces.bluetooth.ble_advertising_data), \
                "failed to find dut in scan list..."

            logger().info("connecting to dut....")
            ble_client.interfaces.bluetooth.connect(bt_dut_address)
            # stability for 60sec and then disconnection
            time.sleep(60)

            logger().info("verifying dut state after the conn......")
            state = ble_dut.interfaces.bluetooth.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "Device isn't in connected state"

            logger().info(f"******fetching services and characterstics from remote")
            servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            assert len(servs) > 0, "no services fetched"
            assert len(chars) > 0, "fetched characters are empty"
            logger().info(f"****** resolve characterstics from remote--> char uid1")

            char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid,
                char_uid=char_uid1)
            logger().info(f"char_path is {char_path}")
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"
            logger().info(f"****** resolve characterstics from remote--> char uid2")

            char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid,
                char_uid=char_uid2)
            logger().info(f"char_path is {char_path}")
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"

            logger().info(f"****** resolve characterstics from remote--> char uid3")

            char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid,
                char_uid=char_uid3)
            logger().info(f"char_path is {char_path}")
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"

            # Disconnection
            logger().info("Disconnecting from dut...")
            ble_client.interfaces.bluetooth.disconnect(bt_dut_address)

    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)

    finally:
        logger().info(f"Removing services on dut")
        ble_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client,
                                   ble_client_address=bt_client_address,
                                   ble_dut_address=bt_dut_address)