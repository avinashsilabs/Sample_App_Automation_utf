import time
import pytest
import re
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
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(917-SDK)
        2. EFR32
        3. Raspberry PI4


    Author: Gopinatha N
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

    def ble_start_init(self):
        self.ble_dut_address = self.ble_dut.interfaces.wifi.ble_start(capability=0, set_smp=1)
        logger().info(f"DUT BLE Address :{self.ble_dut_address}")
        assert self.ble_dut_address, "Unable to find ble_dut_address"

    def ble_gatt_init(self):
        # Initializing DUT BLE Device
        logger().info("start ble GATT service in DUT")
        self.ble_dut_address = self.ble_dut.interfaces.wifi.ble_gatt_start(set_smp=1)
        logger().info(f"DUT BLE Address :{self.ble_dut_address}")
        assert self.ble_dut_address, "Unable to find ble_dut_address"

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
        logger().info("Checking connection status of BLE")
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
                time.sleep(2)

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

    def gatt_write_without_resp(self, write_handle, data_length=None, data=None, write_time=None, write_count=None,
                                bt_mon_log_file_name=None):
        logger().info(f"*******Write Without Response Start****************")

        def write():
            bt_mon_log_file = bt_mon_log_file_name
            time.sleep(2)
            with BleLogs(start_collecting_logs=True,
                         bt_log_path=bt_mon_log_file):
                self.ble_dut.interfaces.wifi.ble_set_att_cmd(ble_remote_dev_address=self.ble_client_address,
                                                             handle=write_handle, data_length=data_length, data=data)
            time.sleep(2)
            flag = False
            logger().info(" ***** Validating Write Without Response Start *****")
            with open(bt_mon_log_file, "r") as file_p:
                lines = file_p.readlines()

            acl_data_flag = att_flag = handle_flag = False
            for line in lines:
                if "> ACL Data RX: Handle" in line:
                    acl_data_flag = True
                    continue
                if "ATT: Write Command" in line and acl_data_flag is True:
                    att_flag = True
                    continue
                if "Handle:" in line:
                    if f"0x{write_handle:04X}" in line and att_flag is True:
                        handle_flag = True
                    continue
                if "Data:" in line and acl_data_flag is True and att_flag is True and handle_flag is True:
                    data_match = re.search(r'Data:(.*)', line)
                    hex_string = data_match.group(1) if data_match else ""
                    byte_array = bytes.fromhex(hex_string)
                    text = byte_array.decode('utf-8')
                    logger().info(f"Actual data :{data}  Expected data:{text}")
                    assert data == text, "Actual data is not found"
                    flag = True
                    break

            assert flag, "data is not found"
            logger().info(" ***** Validating Write Without Response Success *****")

        if write_count:
            for i in range(write_count):
                write()
        else:
            sw = Stopwatch()
            while sw.elapsed_sec <= write_time:
                write()

        logger().info(f"*******Write Without Response End****************")

    @staticmethod
    def validate_write_with_response(bt_mon_log_file=None, write_handle=None, data=None,
                                     write_data_count=None):
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
            if "ATT: Write Request" in line and acl_data_flag is True:
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
                text = byte_array.decode('utf-8')
                logger().info(f"Actual data :{data}  Expected data:{text}")
                assert data == str(text), "Actual data is not found"
                flag = True
                continue
            if "< ACL Data TX:" in line and flag is True:
                acl_tx_flag = True
                continue
            if "ATT: Write Response" in line and acl_tx_flag is True:
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

    @staticmethod
    def validate_rx_notification(bt_mon_log_file_name=None, write_handle=None,
                                 rx_notification_receiving_count=None, data_length=None):
        logger().info(" ***** Validating Rx Notification Start *****")
        rx_notification_validate_count = 0
        with open(bt_mon_log_file_name, "r") as file_p:
            lines = file_p.readlines()

        acl_data_flag = att_flag = handle_flag = False
        for line in lines:
            if "< ACL Data TX: Handle " in line:
                acl_data_flag = True
                continue
            if "ATT: Handle Value Notification" in line and acl_data_flag is True:
                att_flag = True
                continue
            if "Handle:" in line:
                if f"0x{write_handle:04x}" in line and att_flag is True:
                    handle_flag = True
                continue
            if "Data:" in line and acl_data_flag and att_flag and handle_flag:
                data_match = re.search(r'Data:(.*)', line)
                hex_string = data_match.group(1) if data_match else ""
                byte_array = bytes.fromhex(hex_string)
                logger().info(f"Expected data:{byte_array} :length {len(byte_array)}")
                assert len(byte_array) == data_length, "Actual data length  is not found"
                acl_data_flag = att_flag = handle_flag = False
                rx_notification_validate_count = rx_notification_validate_count + 1
                continue

        logger().info(f"rx_notification_count:{rx_notification_receiving_count} and rx_notification_validate_count:"
                      f" {rx_notification_validate_count}")
        assert rx_notification_receiving_count == rx_notification_validate_count, ("Rx notification and Rx notification"
                                                                                   " validation data not matching")
        logger().info(" ***** Validating Rx Notification End *****")

    def gatt_notify_rx(self, write_handle, enable_notify=None, data=None, notify_time=100, svc=None,
                       charc=None):
        # enable notifications
        self.ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=self.ble_client_address,
                                                            handle=(write_handle + 1), enable_notify=enable_notify)

        sw = Stopwatch()
        while sw.elapsed_sec < notify_time:
            since_time = time.perf_counter_ns()
            self.ble_client.interfaces.bluetooth.send_gatt_charc_notification(svc, charc, data)
            time.sleep(0.3)
            found = False
            tw = Stopwatch()
            while tw.elapsed_sec < 10:
                events = self.ble_dut.interfaces.wifi.get_async_events(since_time=since_time)
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                        logger().info(f"************** BLE EVENT DATA IS : {event.event_data} **************")
                        received_data = re.findall(r"att_value:\s*([^\s]+)", event.event_data)
                        logger().info(f"******* Received Data on DUT : {received_data} ********")
                        assert received_data[0] == data, "data mismatched"
                        if data in event.event_data:
                            found = True
                            break
                assert found, "No data received on DUT"
                if found:
                    break

        time.sleep(1)

        # disable notifications
        self.ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=self.ble_client_address,
                                                            handle=(write_handle + 1), enable_notify=0)
   

    def gatt_indication(self, char_path, char_uuid, indication_time=100, data=None, data_length=None):
        logger().info(f"****** Indication Start****************")
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                     char_uid=char_uuid)
        indication_count = 0
        sw = Stopwatch()
        while sw.elapsed_sec < indication_time:
            self.ble_dut.interfaces.bluetooth.ble_indicate_value(ble_remote_dev_address=self.ble_client_address,
                                                                 handle=12, data=data, data_length=data_length)
            indication_count += 1

            time.sleep(5)

        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uuid]
        assert len(notifications) == indication_count
        logger().info(f"Received Notifications : : {notifications}")

        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uuid)

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
            assert state_int == 0
        time.sleep(5)

    def disconnect_from_remote(self):
        logger().info("\n\n\n ***** Disconnect  from Remote (raspi) ***** \n\n\n")
        status = self.ble_client.interfaces.bluetooth.get_connection_status(self.ble_dut_address)
        if status == 0:
            logger().info(f"Already DisConnection status in remote device '{self.ble_client.name}' is:{status}")
        else:
            self.ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)
            status = self.ble_client.interfaces.bluetooth.get_connection_status(self.ble_dut_address)
            self.ble_client.interfaces.bluetooth.close()
            logger().info(f"DisConnection status in remote device '{self.ble_client.name}' is:{status}")
            assert status == 0, f"Remote device '{self.ble_client.name}' is not Disconnected to DUT"

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


# ######################################################################################################################
#                                   Write Without Respons
########################################################################################################################
def test_wifi_sdk_ble_dut_as_slave_with_20_bytes_write_without_respons_buffer_0_c193309(ble_dut,
                                                                                        ble_client,
                                                                                        sl_collections):
    bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_slave_with_20_bytes_write_without_respons_buffer_0_"
                            f"c193309_{int(time.time())}.log")
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file_name):
            # Initializing DUT BLE Device
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            ble_obj.ble_gatt_init()
            # Set DUT Local name
            ble_obj.set_local_get_local_name_validation()
            # Set DUT To Advertising
            ble_obj.advertising_dut()
            # Power Save Mode WLAN And BLE
            ble_obj.power_save()
            # Scan and Connect From Remote Device
            ble_obj.scan_conn_from_remote_device("ImmediateAlertService")
            time.sleep(4)
            # get remote device profile
            write_handle = ble_obj.service_discovery_on_remote(service_uuid=ImmediateAlertService.UUID,
                                                               char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
                                                               characteristic=ImmediateAlertLevelCharacteristic)
            # Configure Buffer Mode
            ble_obj.configure_buffer_mode(mode=0, count=2)
            data = "hundredbytesofdatarx"
            # Write and send BLE 20 bytes of write with response data
            ble_obj.gatt_write_without_resp(write_handle=write_handle, data_length=20, data=data, write_time=600,
                                            bt_mon_log_file_name=bt_mon_log_file_name)
            # Disconnect From Remote Device
            ble_obj.check_device_state_on_dut()
            ble_obj.disconnect_from_remote()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise

    finally:
        ble_obj.clear_dut()


def test_wifi_sdk_ble_dut_as_slave_with_232_bytes_write_without_respons_buffer_1_c193310(ble_dut, ble_client,
                                                                                         sl_collections):
    bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_slave_with_232_bytes_write_without_respons_"
                            f"buffer_1_C193310_{int(time.time())}.log")
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file_name):
            # Initializing DUT BLE Device
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            ble_obj.ble_gatt_init()
            # Set DUT Local name
            ble_obj.set_local_get_local_name_validation()
            # Set DUT To Advertising
            ble_obj.advertising_dut()
            # Power Save Mode WLAN And BLE
            ble_obj.power_save()
            # Scan and Connect From Remote Device
            ble_obj.scan_conn_from_remote_device("ImmediateAlertService")
            # get remote device profile
            write_handle = ble_obj.service_discovery_on_remote(service_uuid=ImmediateAlertService.UUID,
                                                               char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
                                                               characteristic=ImmediateAlertLevelCharacteristic)

            # Configure Buffer Mode
            ble_obj.configure_buffer_mode(mode=1, count=2)

            # Write and send BLE 232 bytes of write with response data
            data = ("hundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdat"
                    "arxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesof"
                    "datarx")
            ble_obj.gatt_write_without_resp(write_handle=write_handle, data_length=232, data=data, write_time=600,
                                            bt_mon_log_file_name=bt_mon_log_file_name)

            ble_obj.check_device_state_on_dut()

            # Disconnect From Remote Device
            ble_obj.disconnect_from_remote()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise

    finally:
        ble_obj.clear_dut()


def test_wifi_sdk_ble_dut_as_master_with_20_bytes_write_without_respons_buffer_0_c193311(ble_dut,
                                                                                         ble_client,
                                                                                         sl_collections):
    bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_master_with_20_bytes_write_without_respons_"
                            f"buffer_0_C193311_{int(time.time())}.log")
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file_name):
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            # Initializing DUT BLE Device
            ble_obj.ble_gatt_init()
            # Advertising Remote device
            ble_obj.advertising_remote("ImmediateAlertService")
            # Scan and Connect From Dut
            ble_obj.scan_conn_from_dut_device()
            # get remote device profile
            write_handle = ble_obj.service_discovery_on_remote(service_uuid=ImmediateAlertService.UUID,
                                                               char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
                                                               characteristic=ImmediateAlertLevelCharacteristic)
            # Configure buffer modes
            ble_obj.configure_buffer_mode(mode=0, count=2)
            data = "hundredbytesofdatarx"
            # Write and send BLE 20 bytes of write with response data using the below API
            ble_obj.gatt_write_without_resp(write_handle=write_handle, data_length=20, data=data, write_time=600,
                                            bt_mon_log_file_name=bt_mon_log_file_name)
            ble_obj.check_device_state_on_dut()
            # Disconnect from dut
            ble_obj.disconnect_form_dut()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise

    finally:
        ble_obj.clear_dut(role="master")


def test_wifi_sdk_ble_dut_as_master_with_232_bytes_write_without_respons_buffer_1_c193312(ble_dut,
                                                                                          ble_client,
                                                                                          sl_collections):
    bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_master_with_232_bytes_write_without_respons_buffer_1"
                            f"_C193312_{int(time.time())}.log")
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file_name):
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            # Initializing DUT BLE Device
            ble_obj.ble_gatt_init()
            # Adv Remote device
            ble_obj.advertising_remote("ImmediateAlertService")
            # Start scan and connect from dut
            ble_obj.scan_conn_from_dut_device()
            # get remote device profile
            write_handle = ble_obj.service_discovery_on_remote(service_uuid=ImmediateAlertService.UUID,
                                                               char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
                                                               characteristic=ImmediateAlertLevelCharacteristic)
            # Configure buffer mode
            ble_obj.configure_buffer_mode(mode=1, count=2)
            data = ("hundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdat"
                    "arxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesof"
                    "datarx")
            # Write and send BLE 232 bytes of write with response data using the below API
            ble_obj.gatt_write_without_resp(write_handle=write_handle, data_length=232, data=data, write_time=600,
                                            bt_mon_log_file_name=bt_mon_log_file_name)
            ble_obj.check_device_state_on_dut()
            # Disconnect from dut
            ble_obj.disconnect_form_dut()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise

    finally:
        ble_obj.clear_dut(role="master")


# ######################################################################################################################
#                                   Write With Respons
########################################################################################################################

def test_wifi_sdk_ble_dut_as_master_with_20_bytes_write_respons_buffer_1_c193313(ble_dut,
                                                                                 ble_client,
                                                                                 sl_collections):
    # Initializing DUT BLE Device
    bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_master_with_20_bytes_write_respons_buffer_1_"
                            f"c193313_{int(time.time())}.log")
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file_name):
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            ble_obj.ble_gatt_init()
            # Adv Remote device
            ble_obj.advertising_remote("HeartRateService")
            # Start scan and connect from dut
            ble_obj.scan_conn_from_dut_device()
            # get remote device profile
            write_handle = ble_obj.service_discovery_on_remote(HeartRateService.UUID,
                                                               HeartRateControlPointCharacteristic.UUID,
                                                               HeartRateControlPointCharacteristic)
            # Configure buffer mode
            ble_obj.configure_buffer_mode(mode=0, count=2)
            data = "hundredbytesofdatarx"

            # Write and send BLE 20 bytes of write with response data using the below API
            write_data_count = ble_obj.gatt_write_with_resp(write_handle=write_handle, data=data, write_time=600,
                                                            data_length=20)

        # Validating Write With Response
        ble_obj.validate_write_with_response(bt_mon_log_file=bt_mon_log_file_name, write_handle=write_handle,
                                             data=data, write_data_count=write_data_count)
        # time.sleep(120)
        ble_obj.check_device_state_on_dut()
        # Disconnect from dut
        ble_obj.disconnect_form_dut()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise

    finally:
        ble_obj.clear_dut(role="master")


def test_wifi_sdk_ble_dut_as_master_with_232_bytes_write_with_respons_buffer_1_c193314(ble_dut,
                                                                                       ble_client,
                                                                                       sl_collections):
    bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_master_with_232_bytes_write_with_respons_"
                            f"buffer_1_c193314_{int(time.time())}.log")
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file_name):

            # Initializing DUT BLE Device
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            ble_obj.ble_gatt_init()
            # Adv Remote device
            ble_obj.advertising_remote("HeartRateService")
            # Start scan and connect from dut
            ble_obj.scan_conn_from_dut_device()
            # # get remote device profile
            write_handle = ble_obj.service_discovery_on_remote(HeartRateService.UUID,
                                                               HeartRateControlPointCharacteristic.UUID,
                                                               HeartRateControlPointCharacteristic)
            # # Configure buffer mode
            ble_obj.configure_buffer_mode(mode=1, count=2)
            data = ("hundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdat"
                    "arxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesof"
                    "datarx")
            # Write and send BLE 232 bytes of write with response data using the below API
            write_data_count = ble_obj.gatt_write_with_resp(write_handle=write_handle, data=data, write_time=600,
                                                            data_length=232)

        # Validating Write With Response
        ble_obj.validate_write_with_response(bt_mon_log_file=bt_mon_log_file_name, write_handle=write_handle,
                                             data=data, write_data_count=write_data_count)
        ble_obj.check_device_state_on_dut()
        # Disconnect from dut
        ble_obj.disconnect_form_dut()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise

    finally:
        ble_obj.clear_dut(role="master")


def test_wifi_sdk_ble_dut_as_slave_with_20_bytes_write_with_respons_buffer_0_c193315(ble_dut,
                                                                                     ble_client,
                                                                                     sl_collections):
    bt_mon_log_file_name = (
        f"reports/test_wifi_sdk_ble_dut_as_slave_with_20_bytes_write_with_respons_buffer_0_"
        f"c193315_{int(time.time())}.log")
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file_name):
            # Initializing DUT BLE Device
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            ble_obj.ble_gatt_init()
            # Set DUT Local name
            ble_obj.set_local_get_local_name_validation()
            # Set DUT To Advertising
            ble_obj.advertising_dut()
            # Power Save Mode WLAN And BLE
            ble_obj.power_save()
            # Scan and Connect From Remote Device
            ble_obj.scan_conn_from_remote_device("HeartRateService")
            # get remote device profile
            write_handle = ble_obj.service_discovery_on_remote(HeartRateService.UUID,
                                                               HeartRateControlPointCharacteristic.UUID,
                                                               HeartRateControlPointCharacteristic)
            # Configure Buffer Mode
            ble_obj.configure_buffer_mode(mode=0, count=2)
            data = "hundredbytesofdatarx"
            # Write and send BLE 20 bytes of write with response data using the below API
            write_data_count = ble_obj.gatt_write_with_resp(write_handle=write_handle, data=data, write_time=600,
                                                            data_length=20)

        # Validating Write With Response Data
        ble_obj.validate_write_with_response(bt_mon_log_file=bt_mon_log_file_name, write_handle=write_handle,
                                             data=data, write_data_count=write_data_count)
        ble_obj.check_device_state_on_dut()
        # Disconnect from dut
        ble_obj.disconnect_form_dut()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise

    finally:
        ble_obj.clear_dut()


def test_wifi_sdk_ble_dut_as_slave_with_232_bytes_write_with_respons_buffer_1_c193316(ble_dut,
                                                                                      ble_client,
                                                                                      sl_collections):
    bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_slave_with_232_bytes_write_with_respons_buffer_1"
                            f"_c193316_{int(time.time())}.log")
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file_name):
            # Initializing DUT BLE Device
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            ble_obj.ble_gatt_init()
            # Set DUT Local name
            ble_obj.set_local_get_local_name_validation()
            # Set DUT To Advertising
            ble_obj.advertising_dut()
            # Power Save Mode WLAN And BLE
            ble_obj.power_save()
            # Scan and Connect From Remote Device
            ble_obj.scan_conn_from_remote_device("HeartRateService")
            # get remote device profile
            write_handle = ble_obj.service_discovery_on_remote(HeartRateService.UUID,
                                                               HeartRateControlPointCharacteristic.UUID,
                                                               HeartRateControlPointCharacteristic)
            # Configure Buffer Mode
            ble_obj.configure_buffer_mode(mode=1, count=2)
            data = ("hundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdat"
                    "arxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesof"
                    "datarx")

            # Write and send BLE 232 bytes of write with response data using the below API
            write_data_count = ble_obj.gatt_write_with_resp(write_handle=write_handle, data=data, write_time=600,
                                                            data_length=232)

        # Validating Write With Response Data
        ble_obj.validate_write_with_response(bt_mon_log_file=bt_mon_log_file_name, write_handle=write_handle,
                                             data=data, write_data_count=write_data_count)
        ble_obj.check_device_state_on_dut()
        # Disconnect from dut
        ble_obj.disconnect_form_dut()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise

    finally:
        ble_obj.clear_dut()


# ####################################################################################################################
#                                   TX Indication
# ####################################################################################################################
def test_wifi_sdk_ble_dut_as_slave_with_20_bytes_tx_indication_buffer_0_c193317(ble_dut, ble_client,
                                                                                sl_collections):
    try:
        bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_slave_with_20_bytes_tx_indication_buffer_0_"
                                f"C193317_{int(time.time())}.log")
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name):
            # Initializing DUT BLE Device
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            # Initializing DUT BLE Device
            ble_obj.ble_gatt_init()
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
            data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data

            # Create Custom services on DUT
            # Create Custom services, attributes, values
            logger().info("Creating new custom gatt service in DUT")
            ble_obj.add_service(service_uuid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1,
                                                          permissions=34)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data=data)

            # Set Local name
            ble_obj.set_local_get_local_name_validation()

            # Start advertising from dut
            ble_obj.advertising_dut()
            time.sleep(2)

            # Power save mode
            ble_obj.power_save()

            # Scan connect from remote device
            ble_obj.scan_conn_from_remote_device()

            # Get All Profiles
            char_path, char_props = ble_obj.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)

            # Configure Buffer Mode
            ble_obj.configure_buffer_mode(mode=0, count=2)

            # Enable indication property in 1BB1 characteristic service in custom
            # DUT will start sending indication data once the indication property is enabled.
            ble_obj.gatt_indication(char_path=char_path, char_uuid=char_uid, indication_time=600, data=data,
                                    data_length=20)

            # disconnect from remote.
            ble_obj.disconnect_from_remote()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise

    finally:
        ble_dut.interfaces.wifi.ble_remove_service()
        ble_obj.clear_dut()


def test_wifi_sdk_ble_dut_as_slave_with_230_bytes_tx_indication_buffer_1_c193318(ble_dut, ble_client, sl_collections):
    try:
        bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_slave_with_230_bytes_tx_indication_buffer_1"
                                f"_c193318_{int(time.time())}.log")
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file_name):
            # Initializing DUT BLE Device
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            # Initializing DUT BLE Device
            ble_obj.ble_gatt_init()
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
            # 230 Bytes of data
            data = ("hundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdat"
                    "arxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesof"
                    "datarx")

            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_obj.add_service(service_uuid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1,
                                                          permissions=34)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data=data)

            # Set Local name
            ble_obj.set_local_get_local_name_validation()

            # Start advertising from dut
            ble_obj.advertising_dut()

            # Power save mode
            ble_obj.power_save()

            # Scan connect from remote device
            ble_obj.scan_conn_from_remote_device()

            # Get All Profiles
            char_path, char_props = ble_obj.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)

            # # Configure Buffer Mode
            ble_obj.configure_buffer_mode(mode=1, count=2)

            # Enable indication property in 1BB1 characteristic service in custom
            # DUT will start sending indication data once the indication property is enabled.
            ble_obj.gatt_indication(char_path=char_path, char_uuid=char_uid, indication_time=600, data=data,
                                    data_length=230)

            # disconnect from remote.
            ble_obj.disconnect_from_remote()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise

    finally:
        ble_dut.interfaces.wifi.ble_remove_service()
        ble_obj.clear_dut()


def test_wifi_sdk_ble_dut_as_master_with_20_bytes_tx_indication_buffer_0_c193320(ble_dut, ble_client,
                                                                                 sl_collections):
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_ble_dut_as_master_with_20_bytes_tx_indication_buffer_0_"
                                 f"c193320_{int(time.time())}.log"):
            # Initializing DUT BLE Device
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            # Initializing DUT BLE Device
            ble_obj.ble_gatt_init()
            # Adv Remote device
            ble_obj.advertising_remote()
            # create custom services
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
            data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data

            # Create Custom services on DUT
            logger().info("Creating new custom gatt service in DUT")
            ble_obj.add_service(service_uuid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1,
                                                          permissions=34)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data=data)

            # Start scan and connect from dut
            ble_obj.scan_conn_from_dut_device()

            # Get All Profiles
            char_path, char_props = ble_obj.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)

            # Configure Buffer Mode
            ble_obj.configure_buffer_mode(mode=0, count=2)

            # Enable indication property in 1BB1 characteristic service in custom
            # DUT will start sending indication data once the indication property is enabled.
            ble_obj.gatt_indication(char_path=char_path, char_uuid=char_uid, indication_time=600, data=data,
                                    data_length=20)

            # disconnect from remote.
            ble_obj.disconnect_from_remote()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise

    finally:
        ble_dut.interfaces.wifi.ble_remove_service()
        ble_obj.clear_dut("master")


def test_wifi_sdk_ble_dut_as_master_with_230_bytes_tx_indication_buffer_1_c193321(ble_dut, ble_client, sl_collections):
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_ble_dut_as_master_with_230_bytes_tx_indication_buffer_1"
                                 f"_c193321_{int(time.time())}.log"):
            # Initializing DUT BLE Device
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            # Initializing DUT BLE Device
            ble_obj.ble_gatt_init()
            # create custom services
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
            data = ("hundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdat"
                    "arxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesof"
                    "datarx")
            logger().info("Creating new custom gatt service in DUT")
            ble_obj.add_service(service_uuid=0x1AA1)
            logger().info("Adding custom characteristic declaration to the custom service")
            ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=34)
            logger().info("Adding characteristic value attribute to the service")
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data=data)
            # Set Local Name
            ble_obj.set_local_get_local_name_validation()
            # Adv dut device
            ble_obj.advertising_dut()
            # Start scan and connect from remote
            ble_obj.scan_conn_from_remote_device()
            # Get All Profiles
            char_path, char_props = ble_obj.service_discovery_on_dut(service_uid=service_uid, char_uid=char_uid)
            # Configure Buffer Mode
            ble_obj.configure_buffer_mode(mode=1, count=2)

            # Enable indication property in 1BB1 characteristic service in custom
            # DUT will start sending indication data once the indication property is enabled.
            ble_obj.gatt_indication(char_path=char_path, char_uuid=char_uid, indication_time=600, data=data,
                                    data_length=232)

            # disconnect from remote.
            ble_obj.disconnect_from_remote()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise

    finally:
        ble_dut.interfaces.wifi.ble_remove_service()
        ble_obj.clear_dut("master")


# ######################################################################################################################
#                                   RX Notification
########################################################################################################################
def test_wifi_sdk_ble_dut_as_master_with_20_bytes_rx_notifications_buffer_0_c193319(ble_dut, ble_client,
                                                                                    sl_collections):
    try:
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
        bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_master_with_20_bytes_rx_notifications_buffer_0_"
                                f"c193319_{int(time.time())}.log")
        with (BleLogs(start_collecting_logs=True,
                      bt_log_path=bt_mon_log_file_name)):
            # Initializing DUT BLE Device
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            # Initializing DUT BLE Device
            ble_obj.ble_gatt_init()
            # Create Service on DUT
            ble_obj.add_service(service_uuid=0xAABB)  # adding Service
            ble_obj.add_characteristic(characteristic_uuid=0x1AA1)
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, data=data)

            ble_obj.advertising_remote(svc)
            # Scan and connect from dut
            ble_obj.scan_conn_from_dut_device()
            # # resolving characteristic
            write_handle = ble_obj.service_discovery_on_remote(HealthThermometerService.UUID,
                                                               CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                               CustomNotifyCharacteristic)
            # # Configure Buffer Mode
            ble_obj.configure_buffer_mode(mode=0, count=2)

            # subscribe to notifications
            ble_obj.gatt_notify_rx(write_handle=write_handle, enable_notify=1, data=data, notify_time=600, svc=svc,
                                   charc=charc)
            # disconnect from remote
            ble_obj.disconnect_from_remote()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise

    finally:
        ble_dut.interfaces.wifi.ble_remove_service()
        ble_obj.clear_dut("master")


def test_wifi_sdk_ble_dut_as_slave_with_20_bytes_rx_notification_buffer_0_c193322(ble_dut, ble_client, sl_collections):
    svc = 'HealthThermometerService'
    charc = 'CustomNotifyCharacteristic'
    data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
    try:
        bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_slave_with_20_bytes_rx_notification_buffer_0_"
                                f"c193322_{int(time.time())}.log")
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file_name):
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            # Initializing DUT BLE Device
            ble_obj.ble_gatt_init()
            # Create Service on DUT
            ble_obj.add_service(service_uuid=0xAABB)  # adding Service
            ble_obj.add_characteristic(characteristic_uuid=0x1AA1)
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, data=data)

            # Advertising dut
            ble_obj.advertising_dut()
            # power save
            ble_obj.power_save()
            # Scan and connect from remote
            ble_obj.scan_conn_from_remote_device(svc)
            # resolving characteristic
            write_handle = ble_obj.service_discovery_on_remote(HealthThermometerService.UUID,
                                                               CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                               CustomNotifyCharacteristic)
            # Configure Buffer Mode
            ble_obj.configure_buffer_mode(mode=0, count=2)

            # subscribe to notifications
            ble_obj.gatt_notify_rx(write_handle=write_handle, enable_notify=1, data=data, notify_time=600, svc=svc,
                                   charc=charc)

            # disconnect from remote.
            ble_obj.disconnect_from_remote()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise

    finally:
        ble_dut.interfaces.wifi.ble_remove_service()
        ble_obj.clear_dut()
