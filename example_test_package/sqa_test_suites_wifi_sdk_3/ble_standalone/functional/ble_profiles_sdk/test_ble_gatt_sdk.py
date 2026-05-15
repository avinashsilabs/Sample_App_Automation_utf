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
import os
from utf.interfaces.bluetooth.bluetooth_interface import (
    BluetoothInterface,
    BTRole,
    BTProfile,
    BTEvents,
    BLEPermissions,
    )
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


def logger():
    return get_logger(__name__)


def wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE, tcp_feat_bit=0,
                    wifi_stack_len=2048, ble_stack_len=2048):
    """
    Reusable BLE GATT config marker for test cases.
    Use as decorator: @wifi_dut_marker()
    """
    config = {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | ext_custom_bit,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": wifi_stack_len, "priority": 8},
            "ble": {"count": 1, "stack_len": ble_stack_len, "priority": 8},
        },
    }
    return pytest.mark.config("wifi_dut", wifi=config)



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
                # Remove any stale device pairing from previous tests
                if self.bt_dut_address:
                    try:
                        logger().info(f"Removing stale device pairing for {self.bt_dut_address}")
                        self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.bt_dut_address)
                    except Exception:
                        pass
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
                elif self.battery_heartrate:
                    self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                        bt_dut_address=bt_dut_address, service_classes=["BatteryService", "HeartRateService"]
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
        assert service.UUID.lower() in uuids, "Could not fetch the profile"

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




@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                        Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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

@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
@pytest.mark.test_src_map_id('C19860')
def test_ble_sdk_fetch_profiles_from_RD1_C19860(ble_dut, ble_client, sl_collections):
    """verify slave connection and master connection from dut"""
    try:
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        bt_mon_log_file_name = (f"reports/test_ble_sdk_fetch_profiles_from_RD1_C19860_{int(time.time())}.log")
        with (BleLogs(start_collecting_logs=True,
                      bt_log_path=bt_mon_log_file_name)):
            # Initializing DUT BLE Device
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj.ble_gatt_init()
            # Create Service on DUT
            ble_obj.add_service(service_uuid=0xAABB)  # adding Service
            ble_obj.add_characteristic(characteristic_uuid=0x1AA1)
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, data=data)

            ble_obj.advertising_remote(svc)
            # Scan and connect from dut
            ble_obj.scan_conn_from_dut_device()
            # # resolving characteristic
            uuids = ble_obj.ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_obj.ble_client_address,
                                                                    async_timeout=60)
            logger().info(f"UUIds {uuids}")
            assert len(uuids) > 0, "uuids are empty"
            ble_obj.check_device_state_on_dut()
            # disconnect from remote
            ble_obj.disconnect_from_remote()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        ble_obj.clear_dut(role="master")

@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                        Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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

@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
@pytest.mark.test_src_map_id('C19866')
def test_ble_sdk_fetch_a_particular_value_of_descriptor_from_RD1_C19866(ble_dut, ble_client, sl_collections, utf_constants):
    """To fetch particular values of descriptor"""
    ble_obj = None
    ble_dut_address = None
    try:
        svc = 'BatteryService'
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        bt_mon_log_file_name = (f"reports/test_ble_sdk_fetch_a_particular_value_of_descriptor_from_RD1_C19866_"
                                f"{int(time.time())}.log")
        with (BleLogs(start_collecting_logs=True,
                      bt_log_path=bt_mon_log_file_name)):
            # Initializing DUT BLE Device
            ble_obj = Ble_Data_Transfer(ble_dut, ble_client, sl_collections)
            # Initializing DUT BLE Device
            ble_dut_address = ble_obj.ble_gatt_init()
            # Create Service on DUT
            ble_obj.add_service(service_uuid=0xAABB)  # adding Service
            ble_obj.add_characteristic(characteristic_uuid=0x1AA1)
            ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, data=data)

            # Advertising remote with BatteryService
            ble_obj.advertising_remote(svc)
            # Scan and connect from dut
            ble_obj.scan_conn_from_dut_device()

            # Core functionality - fetch descriptor values from remote
            logger().info(f"get all profiles")
            uuids = ble_obj.ble_dut.interfaces.wifi.ble_get_profiles_async(
                ble_remote_dev_address=ble_obj.ble_client_address, async_timeout=60)
            logger().info(f"UUIDs: {uuids}")
            assert len(uuids) > 0, "uuids are empty"
            assert BatteryService.UUID in uuids, "Could not fetch the battery service profile"

            logger().info(" Resolving Battery profile from Remote")
            start_handle, end_handle, profile_data = ble_obj.ble_dut.interfaces.wifi.ble_get_profile_async(
                ble_remote_dev_address=ble_obj.ble_client_address,
                uuid=int(BatteryService.UUID, 16), async_timeout=60)
            assert start_handle, "failed to fetch the start handle.."
            assert end_handle, "failed to fetch the end handle.."

            char_uuids, write_handles, char_properties = ble_obj.ble_dut.interfaces.wifi.ble_get_char_services_async(
                ble_remote_dev_address=ble_obj.ble_client_address,
                start_handle=int(start_handle, 16), end_handle=int(end_handle, 16), async_timeout=60)
            logger().info(
                f"*********uuids, write_handles, char_properties: {char_uuids}, {write_handles}, {char_properties} ************")
            assert BatteryLevelCharacteristic.BLEVEL_UUID in char_uuids
            index = char_uuids.index(BatteryLevelCharacteristic.BLEVEL_UUID)
            assert char_properties[index].isdigit()
            assert BatteryLevelCharacteristic.prop_int == int(char_properties[index])
            write_handle = int(write_handles[index], 16)
            assert write_handle > 0

            logger().info(f"To fetch value of descriptor")
            ble_obj.ble_dut.interfaces.wifi.ble_get_att_value_async(
                ble_remote_dev_address=ble_obj.ble_client_address, char_property=write_handle)

            ble_obj.check_device_state_on_dut()
            # disconnect from remote
            ble_obj.disconnect_from_remote()

    except Exception as error:
        logger().info(f"error message :{error}")
        raise
    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_obj.clear_dut(role="master")

@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])

@pytest.mark.test_src_map_id('C19865')
def test_ble_sdk_fetch_desc_that_are_not_supported_C19865(ble_dut, ble_client, utf_constants, sl_collections):
    """Test fetching descriptors with unsupported/invalid handles - expects error 0x4a0a"""
    ble_obj = None
    bt_client_address = None
    try:
        # Use BleFunctionality with HeartRate service on remote (DUT as master)
        ble_obj = BleFunctionality(ble_dut, ble_client, HeartRate=True)
        bt_client_address = ble_obj.ble_gatt_scan()
        ble_obj.check_device_state_on_dut()

        logger().info(f"get all profiles")
        uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
        assert HeartRateService.UUID.lower() in uuids, "Could not fetch the heartrate profile"

        logger().info(" Resolving Heartrate profile from RD1")
        start_handle, end_handle, data = ble_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address,
            uuid=int(HeartRateService.UUID, 16))
        assert start_handle is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch end handle.."

        logger().info(f"********fetching descriptor with unsupported handles*************")
        try:
            # Try to fetch descriptors with handles outside valid range (unsupported)
            ble_dut.interfaces.wifi.ble_get_att_descriptor(ble_devices_address=bt_client_address,
                                                           start_handle=0x20,
                                                           end_handle=0x21)
        except Exception as Err:
            if "0x4a0a" in str(Err):
                logger().info(f"Expected error received: {Err} (attribute not found)")
            else:
                raise Err

        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        logger().info(" Issued BLE disconnect ")

    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=ble_obj.bt_dut_address)
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_disconnect"])
@pytest.mark.test_src_map_id('C19867')
def test_ble_sdk_read_value_of_descriptor_from_RD1_C19867(ble_dut, ble_client, sl_collections, utf_constants):
    """Read multiple attribute values from remote device"""
    ble_obj = None
    bt_client_address = None
    try:
       
        ble_obj = BleFunctionality(ble_dut, ble_client, battery_heartrate=True)
        bt_client_address = ble_obj.ble_gatt_scan()
        ble_obj.check_device_state_on_dut()

        logger().info(f"get all profiles")
        uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
        assert BatteryService.UUID in uuids, "Could not fetch the battery service profile"

        logger().info(" Resolving Battery profile from Remote")
        start_handle, end_handle, data = ble_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address,
            uuid=int(BatteryService.UUID, 16))
        assert start_handle , "failed to fetch the start handle.."
        assert end_handle , "failed to fetch the end handle.."

        logger().info(" Resolving heartrate profile from Remote")
        start_handle_1, end_handle_1, data = ble_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address,
            uuid=int(HeartRateService.UUID, 16))
        assert start_handle_1, "failed to fetch the start handle.."
        assert end_handle_1 , "failed to fetch the end handle.."

        logger().info(f"To fetch value of descriptor using multiple att read")
        att_values = ble_dut.interfaces.wifi.ble_get_multiple_att(
            ble_remote_dev_address=bt_client_address,
            no_of_handles=2,
            handle_1=start_handle,
            handle_2=start_handle_1)
        logger().info(f"*********{att_values}*********")

        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        logger().info(" Issued BLE disconnect ")
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=ble_obj.bt_dut_address)
            
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19869')
def test_wifi_sdk_ble_dut_as_slave_to_set_attribute_value_to_descriptors_C19869(ble_dut, ble_client, sl_collections):
    """DUT as slave - write 30 bytes with response"""
    bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_slave_C19869_{int(time.time())}.log")
    ble_obj = None
    ble_dut_address = None
    ble_client_address = None
    allocated_mem_addr = None
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
            # Write and send BLE 30 bytes of write with response data
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
        if allocated_mem_addr is not None:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)
        if ble_dut_address is not None:
            ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client,
                                       ble_client_address=ble_client_address,
                                       ble_dut_address=ble_dut_address)
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19870')
def test_wifi_sdk_ble_dut_as_slave_to_set_different_attribute_value_to_descriptors_C19870(ble_dut, ble_client, sl_collections):
    """DUT as slave - write 50 bytes with response"""
    bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_slave_C19870_{int(time.time())}.log")
    ble_obj = None
    ble_dut_address = None
    ble_client_address = None
    allocated_mem_addr = None
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
            # Write and send BLE 50 bytes of write with response data
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
        if allocated_mem_addr is not None:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)
        if ble_dut_address is not None:
            ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client,
                                       ble_client_address=ble_client_address,
                                       ble_dut_address=ble_dut_address)
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19871')
def test_wifi_sdk_ble_dut_as_slave_prepare_execute_C19871(ble_dut, ble_client, sl_collections):
    """DUT as slave - prepare and execute write"""
    bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_dut_as_slave_C19871_{int(time.time())}.log")
    ble_obj = None
    ble_dut_address = None
    ble_client_address = None
    allocated_mem_addr = None
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
            # get remote device profile
            write_handle = ble_obj.service_discovery_on_remote(HeartRateService.UUID,
                                                               HeartRateControlPointCharacteristic.UUID,
                                                               HeartRateControlPointCharacteristic)
            ble_dut.interfaces.bluetooth.ble_prepare_write_async(ble_remote_dev_address=ble_client_address,
                                                                  handle=write_handle, offset=1,
                                                                  data_len=10, data=data)
            ble_dut.interfaces.bluetooth.ble_execute_write_async(ble_remote_dev_address=ble_client_address,
                                                                  exe_flag=1)
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
        if allocated_mem_addr is not None:
            ble_dut.interfaces.bluetooth.memory_free(address=allocated_mem_addr)
        if ble_dut_address is not None:
            ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client,
                                       ble_client_address=ble_client_address,
                                       ble_dut_address=ble_dut_address)
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C667635')
def test_ble_slave_properties_of_a_characterstic_C667635(ble_dut, ble_client, sl_collections, utf_constants):
    """Validate characteristic properties in slave mode"""
    ble_dut_address = None
    ble_client_address = None
    service_added = False
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"./reports/test_ble_slave_properties_C667635_{int(time.time())}.log"):
            iter_count = utf_constants.get("iter_count") if utf_constants else 1
            if iter_count is None:
                iter_count = 1
            logger().info(f"iter_count:{iter_count}")
            for count in range(iter_count):
                logger().info("*********************** Start BLE in DUT ***********************")
                ble_dut_address = ble_dut.interfaces.wifi.ble_gatt_start(set_smp=0)
                assert ble_dut_address, "failed to initialize ble in dut"
                ble_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
                ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
                ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)
                service_added = True
                ble_dut.interfaces.wifi.ble_start_advertising()

                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                enable_wifi_ps = ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                assert enable_wifi_ps == 0, 'failed to enable wlan power save'
                enable_bt_ps = ble_dut.interfaces.wifi.enable_bt_power_save()
                assert enable_bt_ps == 0, 'failed to enable bt power save'
    
                ble_client.interfaces.bluetooth.close()
                ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                    bt_dut_address=ble_dut_address,
                    service_classes=["HealthThermometerService"])
                time.sleep(5)
                ble_client.interfaces.bluetooth.stop_scanning()

                logger().info("*********************** connect to ble dut ***********************")
                ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_address)
                logger().info(".... checking for ble connectivity stability ....")
                time.sleep(60)

                logger().info("******************** get connection state")
                state = ble_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "device is in disconnection state"

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
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=Ex)
    finally:
        if service_added:
            logger().info(f"Removing services on dut")
            try:
                ble_dut.interfaces.wifi.ble_remove_service()
            except Exception as e:
                logger().info(f"Failed to remove service: {e}")
        ble_client.interfaces.bluetooth.close()
        if ble_dut_address is not None:
            sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client,
                                       ble_client_address=ble_client_address,
                                       ble_dut_address=ble_dut_address)
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C667637')
def test_ble_sdk_enable_enable_disable_indication_C667637(ble_dut, ble_client, sl_collections):
    """Enable and disable indications in server role"""
    bt_dut_address = None
    ble_client_address = None
    ble_obj = None
    try:
        logger().info(" ******* Start BLE Service ******* ")
        bt_dut_address = ble_dut.interfaces.wifi.ble_start(capability=0)
        assert bt_dut_address, "Failed to load bt address..."

        service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))

        ble_obj = BleFunctionality(ble_dut, ble_client, bt_dut_address=bt_dut_address, powersave=True)
        logger().info(f"Adding custom service on dut")
        ble_obj.add_services_on_dut(uuid=0x1AA1, Charc_serv=0x1BB1)
        ble_client_address = ble_obj.ble_adv()
        time.sleep(60)

        servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"

        char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs,
            service_uid=service_uid,
            char_uid=char_uid)
        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"

        # First enable/indicate/disable cycle
        logger().info(f"*******Enabling notifications on remote")
        ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path, char_uid=char_uid)
        ble_dut.interfaces.wifi.ble_indicate_value(ble_remote_dev_address=ble_client_address,
                                                    handle=12, data=data, data_length=20)
        time.sleep(3)
        logger().info("\n\n\n ***** validating Received notifications on Remote *****\n\n")
        notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
        logger().info(f"Notifications received on remote: {notifications}")

        logger().info(f"*******Disabling notifications on remote")
        ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        time.sleep(1)

        # Second enable/indicate/disable cycle
        ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path, char_uid=char_uid)
        ble_dut.interfaces.wifi.ble_indicate_value(ble_remote_dev_address=ble_client_address,
                                                    handle=12, data=data, data_length=20)
        time.sleep(3)
        logger().info("\n\n\n ***** validating Received notifications on Remote *****\n\n")
        notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
        logger().info(f"Notifications received on remote: {notifications}")

        ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        time.sleep(1)

    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)

    finally:
        if bt_dut_address is not None:
            ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
            time.sleep(2)
        logger().info(f"Removing services on dut")
        ble_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        if bt_dut_address is not None:
            sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client,
                                       ble_client_address=ble_client_address,
                                       ble_dut_address=bt_dut_address)


# Helper functions for test_ble_sdk_read_long_descriptor_from_RD1_C19868
def ble_connection(ble_dut, remote_wiseconnect3, data=None):
    logger().info("======== start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
    assert bt_dut_address, "failed to initiate ble in dut"
    time.sleep(2)
    logger().info(" ======= start ble remote secondary DUT")
    address = remote_wiseconnect3.interfaces.sapi.ble_gatt_start(set_smp=0)
    ble_client_address = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', address).group(0)
    assert ble_client_address, "failed to initiate ble in remote dut"
    logger().info(f"address_is{ble_client_address}")
    ble_dut.interfaces.bluetooth.ble_add_service(uid=0x1234)
    ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x4567)
    ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x4567, data=data)
    time.sleep(2)
    logger().info(" ======= start ble adv in remote secondary DUT")
    remote_wiseconnect3.interfaces.sapi.ble_start_advertising()
    time.sleep(1)
    logger().info(" ======= start scanning in remote side")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=50)
    time.sleep(5)
    logger().info("======= enable wifi power save mode on DUT")
    remote_wiseconnect3.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
    logger().info("======= enable BT power save mode on DUT")
    remote_wiseconnect3.interfaces.wifi.enable_bt_power_save(
        psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
        psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
    time.sleep(10)
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=ble_client_address, timeout=120)
    time.sleep(60)
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"\nDevice state: {state_int}")
    return ble_client_address, bt_dut_address


def extract_link_key(ble_dut):
    link_key = ""
    tw = Stopwatch()
    while tw.elapsed_sec < 120:
        events = ble_dut.interfaces.wifi.get_async_events()
        for event in events:
            if "link_key" in event.event_data:
                event_data = event.event_data
                logger().info(event_data)
                link_key_data = re.findall("link_key::.*", event_data)
                link_key_data_str = re.split(":<", link_key_data[0])
                link_key_data_hex = re.split(":", link_key_data_str[0])
                link_key = "0x"
                for hex_data_part in link_key_data_hex:
                    hex_data_part = hex_data_part.replace(" ", "")
                    if len(hex_data_part) == 1:
                        hex_data_part = '0' + hex_data_part
                    link_key = link_key + hex_data_part
            else:
                continue
        if link_key:
            break
    link_key = link_key.replace(" ", "")
    link_key = link_key.replace("link_key", "")
    logger().info(f"Link Key Extracted:{link_key}")
    if len(link_key) > 34:
        link_key = link_key.split('$')[0]
        logger().info(f"Link Key Extracted:{link_key}")
    elif len(link_key) == 34:
        logger().info(f"**************Link Key Extracted: {link_key}***************")
    else:
        assert len(link_key) == 34, f"link key is not proper format"
    return link_key


def decimals_to_ascii(att_values):
    list1 = []
    logger().info(f"att_values:{att_values}")
    for i in range(len(att_values)):
        if att_values[i] == 2:
            logger().info("att-val found")
            att_values[i] = 52
            list1.append(att_values[i])
        elif att_values[i] != 0:
            list1.append(att_values[i])
    return ''.join(chr(v) for v in list1 if 0 <= v <= 255)


def extract_att_values(log_text: str):
    m = re.search(
        r'att_value:\s*(.*?)(?:\n\s*rsi_ble_on_read_resp_event_gatt|\Z)',
        log_text,
        flags=re.S
    )
    if not m:
        return []
    value = m.group(1)
    value = re.sub(r'F[0-9A-Fa-f]{3,8}(\d+)', r'\1', value)
    value = re.sub(r'F[0-9A-Fa-f]{3,8}', ' ', value)
    return list(map(int, re.findall(r'\d+', value)))


def service_discovery_on_remote_standalone(ble_dut, ble_client_address, service_uuid=None, char_uuid=None, characteristic=None):
    """Standalone version of service discovery for remote device"""
    logger().info("\n\n ***** Performing GATT profile discovery on Remote ***** \n\n\n")
    # get all profiles
    uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_client_address, async_timeout=60)
    logger().info(f"UUIds {uuids}")
    assert len(uuids) > 0, "uuids are empty"
    #  resolve profile
    start_handle, end_handle, data = ble_dut.interfaces.wifi.ble_get_profile_async(
        ble_remote_dev_address=ble_client_address,
        uuid=int(str(service_uuid), 16),
        async_timeout=60)
    logger().info(f"start_handle:{start_handle}, end_handle:{end_handle}")
    assert start_handle is not None
    assert end_handle is not None
    char_uuids, write_handles, char_properties = ble_dut.interfaces.wifi.ble_get_char_services_async(
        ble_remote_dev_address=ble_client_address,
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
    logger().info(f"characteristic:{characteristic}")
    logger().info(f"char_properties:{int(char_properties[index])}")
    logger().info("validating the characteristic property")
    assert char_properties[index].isdigit(), "Character property found is not an integer"
    assert characteristic == int(char_properties[index]), "Invalid character property found"
    write_handle = int(write_handles[index], 16)
    logger().info(f"write_handle:{write_handle}")
    assert write_handle > 0, "Unable to get write handle for configured service"
    return write_handle


@wifi_dut_marker()
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19868')
def test_ble_sdk_read_long_descriptor_from_RD1_C19868(ble_dut, remote_wiseconnect3, sl_collections):
    """Read long descriptor value from remote device"""
    ble_client_address = None
    ble_dut_address = None
    service_added = False
    try:
        logger().info("TESTCASE EXECUTION STARTED")
        data = "123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789"
        ble_client_address, ble_dut_address = ble_connection(ble_dut, remote_wiseconnect3, data)
        service_added = True
        link_key1 = extract_link_key(ble_dut)
        logger().info(f"link_key1:{link_key1}")
        write_handle_1 = service_discovery_on_remote_standalone(
            remote_wiseconnect3, ble_dut_address, "0x1234", "0x4567", BLEPermissions.DEFAULT)
        time.sleep(5)
        remote_wiseconnect3.interfaces.wifi.ble_get_long_att_value_async(ble_remote_dev_address=ble_dut_address,
                                                                         handle=write_handle_1, offset=0)
        time.sleep(10)
        dec_val = None
        tw = Stopwatch()
        while tw.elapsed_sec < 160:
            events = remote_wiseconnect3.interfaces.wifi.get_async_events()
            for event in events:
                if "rsi_ble_on_read_resp_event_gatt" in event.event_data:
                    att_values = extract_att_values(event.event_data)
                    dec_val = decimals_to_ascii(att_values)
                    logger().info("Decoded long descriptor value: {}".format(dec_val))
                    break
            if dec_val is not None:
                break
        assert dec_val == data, "failed to get long descriptor value"
        logger().info("Att-value read successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if service_added:
            try:
                ble_dut.interfaces.wifi.ble_remove_service()
            except Exception as e:
                logger().info(f"Failed to remove service: {e}")
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        if ble_client_address:
            try:
                ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
            except Exception as e:
                logger().info(f"Failed to disconnect: {e}")


@wifi_dut_marker(ext_custom_bit=0)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C703319')
def test_ble_hogp_smp_slave_mode_C703319(ble_dut, ble_client, sl_collections):
    """Test BLE HID over GATT Profile (HOGP) in slave mode with SMP"""
    ble_dut_address = None
    ble_client_address = None
    hid_service_added = False
    try:
        with BleLogs(
                start_collecting_logs=True,
                bt_log_path=f"reports/test_ble_hogp_smp_slave_mode_C703319_{int(time.time())}.log"
        ):
            logger().info("*********************** Start BLE in DUT ***********************")
            ble_dut_address = ble_dut.interfaces.wifi.ble_gatt_start()
            assert ble_dut_address, "FAILED TO LOAD BT ADDRESS..."

            logger().info("....ADDING HID SERVICE....")
            ble_dut.interfaces.wifi.ble_add_hid_service()
            hid_service_added = True

            logger().info("....START ADVERTISING....")
            ble_dut.interfaces.wifi.ble_start_advertising()

            logger().info("....APPLYING POWER SAVE MODE....")
            ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            ble_dut.interfaces.wifi.enable_bt_power_save()

            logger().info("....SCANNING FROM REMOTE DEVICE....")
            ble_client.interfaces.bluetooth.close()
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=ble_dut_address
            )
            assert ble_client_address, "The client address is not found"
            time.sleep(5)
            ble_client.interfaces.bluetooth.stop_scanning()

            logger().info("....VERIFYING DEVICE IN SCAN LIST....")
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            assert ble_dut.interfaces.wifi.ble_address in found_devices, "Failed to find DUT address in scan list"

            logger().info("....CONNECTING TO DUT....")
            ble_client.interfaces.bluetooth.pair_and_connect(ble_dut_address, timeout=30)
            time.sleep(60)

            logger().info("....CHECKING DEVICE STATE....")
            state = ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

            logger().info("....SENDING HID DATA....")
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
            logger().info("....HID DATA VALIDATION SUCCESSFUL....")
            time.sleep(2)

    except Exception as error:
        logger().info(f"error message: {error}")
        raise
    finally:
        if ble_dut_address is not None:
            try:
                ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
                time.sleep(2)
            except Exception as e:
                logger().info(f"Failed to disconnect: {e}")
            try:
                ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_dut_address)
            except Exception as e:
                logger().info(f"Failed to remove device: {e}")
        ble_client.interfaces.bluetooth.close()
        if ble_dut_address is not None:
            sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client,
                                       ble_client_address=ble_client_address,
                                       ble_dut_address=ble_dut_address)
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19885')
def test_ble_sdk_enable_health_thermometer_in_server_role_C19885(wifi_dut, ble_client, sl_collections):
    """ENABLE health thermometer IN SERVER ROLE"""
    bt_dut_address = None
    bt_client_address = None
    ble_obj = None
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
        try:
            if bt_dut_address:
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                time.sleep(2)
        except Exception:
            pass
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None and bt_client_address is not None and bt_dut_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)
            

@wifi_dut_marker(ext_custom_bit=0)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C703320')
def test_ble_sdk_enable_heartrate_service_in_server_role_C703320(wifi_dut, ble_client, sl_collections):
    """ENABLE HEART RATE SERVICE IN SERVER ROLE"""
    bt_dut_address = None
    ble_client_address = None
    ble_obj = None
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
        try:
            if bt_dut_address:
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                time.sleep(2)
        except Exception:
            pass
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None and ble_client_address is not None and bt_dut_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_client_address,
                                       ble_dut_address=bt_dut_address)
            
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
@pytest.mark.test_src_map_id('C19861')
def test_ble_sdk_fetch_a_particular_profiles_from_RD1_C19861(wifi_dut, ble_client, sl_collections, utf_constants):
    ble_obj = None
    bt_client_address = None
    try:
        ble_obj = BleFunctionality(wifi_dut, ble_client, battery_service=True)
        bt_client_address = ble_obj.ble_gatt_scan()
        ble_obj.check_device_state_on_dut()
        logger().info(f"Fetching all profiles...")

        retries = 3
        for retry in range(retries):
            uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
            if uuids:
                logger().info(f"Profiles fetched successfully: {uuids}")
                break
            else:
                logger().warning(f"Attempt {retry + 1}: Failed to fetch profiles. Retrying...")
                time.sleep(5)
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
        if ble_obj is not None and bt_client_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=ble_obj.bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
@pytest.mark.test_src_map_id('C19864')
def test_ble_sdk_fetch_desc_from_RD1_C19864(wifi_dut, ble_client, sl_collections):
    ble_obj = None
    bt_client_address = None
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
        if ble_obj is not None and bt_client_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=ble_obj.bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19862')
def test_ble_sdk_fetch_profiles_from_RD1_C19862(wifi_dut, ble_client, sl_collections):
    ble_obj = None
    bt_client_address = None
    try:
        ble_obj = BleFunctionality(wifi_dut, ble_client)
        bt_client_address = ble_obj.ble_gatt_scan()
        ble_obj.check_device_state_on_dut()
        logger().info(f"Fetching all profiles...")
        retries = 3
        for retry in range(retries):
            uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
            if uuids:
                logger().info(f"Profiles fetched successfully: {uuids}")
                break
            else:
                logger().warning(f"Attempt {retry + 1}: Failed to fetch profiles. Retrying...")
                time.sleep(5)
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
        if ble_obj is not None:
            try:
                ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.bt_dut_address)
            except Exception:
                pass
            if bt_client_address is not None:
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                           ble_client_address=bt_client_address,
                                           ble_dut_address=ble_obj.bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C667633')
def test_ble_sdk_gatt_secondary_services_C667633(wifi_dut, ble_client, sl_collections):
    """
       1.initialize the ble in dut
       2.Advertise on remote and add the service on remote
       3.Scan and advertise from dut
       4.Connect and check stability for 60secs
       5.fetch the profiles from dut
       6.Disconnect the dut
       """
    bt_dut_address = None
    bt_client_address = None
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
        if bt_dut_address is not None and bt_client_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
@pytest.mark.test_src_map_id('C19863')
def test_ble_sdk_fetch_charecteristics_from_RD1_C19863(wifi_dut, ble_client, sl_collections):
    """Verify characterstics values from Dut"""
    ble_obj = None
    bt_client_address = None
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
        if ble_obj is not None and bt_client_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=ble_obj.bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19880')
def test_ble_sdk_enable_heartrate_service_in_client_role_C19880(wifi_dut, ble_client, sl_collections):
    """ENABLE HEART RATE SERVICE IN CLIENT ROLE"""
    bt_mon_log_file = "reports/test_ble_sdk_C19880"
    bt_dut_address = None
    bt_client_address = None
    ble_obj = None
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
        if ble_obj is not None and bt_client_address is not None and bt_dut_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19882')
def test_ble_sdk_enable_battery_service_in_client_role_C19882(wifi_dut, ble_client, sl_collections):
    """ENABLE Battery SERVICE IN CLIENT ROLE"""
    bt_mon_log_file = "reports/test_ble_sdk_C19882"
    bt_dut_address = None
    bt_client_address = None
    ble_obj = None
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
        if ble_obj is not None and bt_client_address is not None and bt_dut_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19886')
def test_ble_sdk_enable_health_thermomter_service_in_client_role_C19886(wifi_dut, ble_client, sl_collections):
    """ENABLE Blood pressure SERVICE IN CLIENT ROLE"""
    bt_mon_log_file = "reports/test_wifi_sdk_C19886"
    bt_dut_address = None
    bt_client_address = None
    ble_obj = None
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

        Data = ble_obj.events_on_dut()
        health_thermomter_notifcations = ble_obj.btmon_validation_for_remote_tx(bt_mon_log_file=bt_mon_log_file, Data_received_on_dut=Data)
        for data in health_thermomter_notifcations:
            notification = str(data) + "'C"
            logger().info(f"Notifications received on dut: {notification}")
        ble_obj.disconnection_on_dut()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None and bt_client_address is not None and bt_dut_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan"])
@pytest.mark.test_src_map_id('C19888')
def test_ble_sdk_enable_glucose_service_in_client_role_C19888(wifi_dut, ble_client, sl_collections):
    """ENABLE Glucose SERVICE IN CLIENT ROLE"""
    bt_mon_log_file = "reports/test_wifi_sdk_C19888"
    bt_dut_address = None
    bt_client_address = None
    ble_obj = None
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

        Data = ble_obj.events_on_dut()
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
        if ble_obj is not None and bt_client_address is not None and bt_dut_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)


def add_glucose_service_on_dut(wifi_dut):
    glucose_measurement_handle = 12
    glucose_context_handle = 15
    glucose_feature_handle = 18
    racp_handle = 20

    logger().info("Adding Glucose service on DUT")
    wifi_dut.interfaces.wifi.ble_add_service(uid=0x1808)

    logger().info("Adding Glucose Measurement characteristic")
    wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A18,
                                                   permissions=0x10,
                                                   service_handler_num=1,
                                                   value_handler_num=2)
    
    data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
    wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A18,
                                                  permissions=0x10,
                                                  value_handler_num=2,
                                                  data=data)

    logger().info("Adding Glucose Measurement Context characteristic")
    wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A34,
                                                   permissions=0x10,
                                                   service_handler_num=4,
                                                   value_handler_num=5)


    wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A34,
                                                  permissions=0x10,
                                                  value_handler_num=5,
                                                  data=data)

    logger().info("Adding Glucose Feature characteristic")
    wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A51,
                                                   permissions=0x02,
                                                   service_handler_num=7,
                                                   value_handler_num=8)


    wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A51,
                                                  permissions=0x02,
                                                  value_handler_num=8,
                                                  data=data)

    logger().info("Adding Record Access Control Point characteristic")
    wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A52,
                                                   permissions=0x28,
                                                   service_handler_num=9,
                                                   value_handler_num=10)
    wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A52,
                                                  permissions=0x28,
                                                  value_handler_num=10,
                                                  data=data)
    return glucose_measurement_handle, glucose_context_handle, glucose_feature_handle, racp_handle


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19887')
def test_ble_sdk_glucose_service_notify_racp_stability_server_role_C19887(wifi_dut, ble_client, sl_collections):
    """Verify Glucose service notifications, RACP write, and 10 minute stability with  client."""
    bt_dut_address = None
    ble_client_address = None
    ble_obj = None
    measurement_char_path = None
    racp_char_path = None
    glucose_measurement_uuid = "00002a18-0000-1000-8000-00805f9b34fb"
    racp_uuid = "00002a52-0000-1000-8000-00805f9b34fb"
    glucose_service_uuid = "00001808-0000-1000-8000-00805f9b34fb"

    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_glucose_stability_{int(time.time())}") as bt_logs:
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=0)
            assert bt_dut_address, "Failed to load bt address..."
            glucose_measurement_handle, _, _, _ = add_glucose_service_on_dut(wifi_dut)

            ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, powersave=True)
            ble_client_address = ble_obj.ble_adv()
            time.sleep(60)
            ble_obj.check_device_state_on_rasp()

            measurement_char_path = ble_obj.resolving_services_on_remote(service_uuid=glucose_service_uuid,
                                                                         char_uuid=glucose_measurement_uuid)
            racp_char_path = ble_obj.resolving_services_on_remote(service_uuid=glucose_service_uuid,
                                                                  char_uuid=racp_uuid)

            logger().info("Enabling notifications for Glucose Measurement on remote device")
            ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=measurement_char_path)
            ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=measurement_char_path,
                                                                                    char_uid=glucose_measurement_uuid)

            for seq in range(1, 6):
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))

                logger().info(f"Notifying live glucose measurement seq={seq}")

                wifi_dut.interfaces.wifi.ble_set_local_att_value(
                    val_handle=glucose_measurement_handle,
                    notify_data=data
                )
                time.sleep(2)

            notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[glucose_measurement_uuid]
            logger().info(f"Glucose Measurement notifications received on Remote Device: {notifications}")
            assert len(notifications) > 0, "Glucose Measurement notifications are not received on Remote Device"
            notification_count_before_racp = len(notifications)

            logger().info("Writing Report Stored Records / All Records to RACP")
            ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(char_path=racp_char_path, data="\x01\x01")
            time.sleep(2)

            for index in range(5):
                record_data = f"REC{index}"
                logger().info(f"Sending glucose record after RACP write: {data}")
                wifi_dut.interfaces.wifi.ble_set_local_att_value(notify_data=data,
                                                                 val_handle=glucose_measurement_handle)
                time.sleep(3)

            notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[glucose_measurement_uuid]
            logger().info(f"Glucose records received on Remote Device: {notifications}")
            assert len(notifications) >= notification_count_before_racp + 5, "Glucose records are not received on Remote Device"

            logger().info("Checking connection stability for 10 mins")
            time.sleep(600)
            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            logger().info(f"\nDevice state: {state_int}")
            assert state_int == BLEDeviceState.Connected, "There is no connection stability"
            ble_obj.check_device_state_on_rasp()
            logger().info("Connection is stable after 10 mins")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        try:
            if measurement_char_path is not None:
                ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=measurement_char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=glucose_measurement_uuid)
        except Exception as e:
            logger().info(f"Failed to disable Glucose Measurement notifications: {e}")
        try:
            if bt_dut_address:
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                time.sleep(2)
        except Exception as e:
            logger().info(f"Disconnect from Remote Device failed: {e}")
        try:
            wifi_dut.interfaces.wifi.ble_remove_service()
        except Exception as e:
            logger().info(f"Failed to remove service: {e}")
        ble_client.interfaces.bluetooth.close()
        if bt_dut_address is not None and ble_client_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_client_address,
                                       ble_dut_address=bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
@pytest.mark.test_src_map_id('C19875')
def test_ble_sdk_connect_disconnect_multiple_times_from_RD1_C19875(wifi_dut, ble_client, sl_collections):
    """verify gatt connection and disconnection multiple times"""
    bt_dut_address = None
    bt_client_address = None
    try:
        for i in range(0, 5):
            bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(bond_info=0)
            assert bt_dut_address, "gatt init failed in DUT"
            timeout = 120
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
        if bt_dut_address is not None and bt_client_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19874')
def test_ble_sdk_link_loss_profiles_from_rd1_c19874(wifi_dut, ble_client, sl_collections):
    bt_dut_address = None
    bt_client_address = None
    ble_obj = None
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
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None and bt_client_address is not None and bt_dut_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19879')
def test_ble_sdk_enable_heartrate_service_in_server_role_C19879(wifi_dut, ble_client, utf_constants,
                                                                sl_collections):
    """ENABLE HEART RATE SERVICE IN SERVER ROLE"""
    bt_dut_address = None
    bt_client_address = None
    ble_obj = None
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
        try:
            if bt_dut_address:
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                time.sleep(2)
        except Exception:
            pass
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None and bt_client_address is not None and bt_dut_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19883')
def test_ble_sdk_enable_blood_pressure_in_server_role_C19883(wifi_dut, ble_client, utf_constants, sl_collections):
    """ENABLE BLOOD PRESSURE IN SERVER ROLE"""
    bt_dut_address = None
    bt_client_address = None
    ble_obj = None
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
        try:
            if bt_dut_address:
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                time.sleep(2)
        except Exception:
            pass
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None and bt_client_address is not None and bt_dut_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19881')
def test_ble_sdk_enable_battery_service_in_server_role_C19881(wifi_dut, ble_client, sl_collections):
    """ENABLE BATTERY SERVICE IN SERVER ROLE"""
    bt_dut_address = None
    bt_client_address = None
    ble_obj = None
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_C19881_{int(time.time())}") as bt_logs:
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
        try:
            if bt_dut_address:
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                time.sleep(2)
        except Exception:
            pass
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None and bt_client_address is not None and bt_dut_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C667636')
def test_ble_sdk_enable_enable_notify_C667636(wifi_dut, ble_client, utf_constants, sl_collections):
    """ENABLE HEART RATE SERVICE IN SERVER ROLE"""
    bt_dut_address = None
    ble_client_address = None
    ble_obj = None
    try:
        logger().info(" ******* Start BLE Service ******* ")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=0)
        assert bt_dut_address, "Failed to load bt address..."
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
        try:
            if bt_dut_address:
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                time.sleep(2)
        except Exception:
            pass
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()
        if bt_dut_address is not None and ble_client_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_client_address,
                                       ble_dut_address=bt_dut_address)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19878')
def test_ble_sdk_validate_adding_service_in_slave_role_C19878(ble_dut, ble_client, sl_collections):
    bt_dut_address = None
    bt_client_address = None
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
        if bt_dut_address is not None and bt_client_address is not None:
            sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)
            
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C667632')
def test_ble_sdk_gatt_primary_services_C667632(wifi_dut, ble_client, sl_collections):
    """
    1.initialize the ble in dut
    2.Advertise on remote
    3.Scan and advertise from dut
    4.Connect and check stability for 60secs
    5.fetch the profiles from dut
    6.Disconnect the dut
    """
    bt_dut_address = None
    bt_client_address = None
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
        ble_client.interfaces.bluetooth.close()
        if bt_dut_address is not None and bt_client_address is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                        Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
            "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC|
                            Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID|
                            Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX|
                            Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS|
                            Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE|
                            Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE| 1<<27 | 2<<12,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
]
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19873')
def test_ble_dut_as_master_and_master_get_profiles_C19873(ble_dut, ble_clients, sl_collections):
    """DUT as master with dual connections, get profiles from both remotes"""
    ble_obj = None
    ble_obj_1 = None
    bt_dut_address = None
    bt_client_address_1 = None
    bt_client_address_2 = None
    ble_client1 = None
    ble_client2 = None
    try:
        ble_client1 = ble_clients[0]
        ble_client2 = ble_clients[1]
        bt_dut_address = ble_dut.interfaces.wifi.ble_gatt_start(set_smp=0)
        logger().info("BLE-DUT-ADDRESS: {}".format(bt_dut_address))
        assert bt_dut_address is not None, "gatt init failed in DUT"
        ble_obj = BleFunctionality(ble_dut, ble_client1, bt_dut_address=bt_dut_address, ble_start=False, ht=True)
        bt_client_address_1 = ble_obj.ble_gatt_scan()
        logger().info("Ble Scan successful")
        ble_obj.check_device_state_on_dut()
        ble_obj_1 = BleFunctionality(ble_dut, ble_client2, bt_dut_address=bt_dut_address, ble_start=False, ht=True)
        bt_client_address_2 = ble_obj_1.ble_gatt_scan()
        ble_obj_1.check_device_state_on_dut()
        logger().info(f"******************** get all profiles ********************")
        uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address_1)
        logger().info(f"UUIDs fetched from DUT: {uuids}")
        assert HealthThermometerService.UUID.lower() and HeartRateService.UUID.lower() in uuids is not None, "Could not fetch the profile"
        logger().info(" ******************** Resolving Profile ********************")
        start_handle, end_handle, data = ble_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address_1, uuid=int(HealthThermometerService.UUID, 16))
        assert start_handle is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch end handle.."
        char_uuids, write_handles, char_properties = ble_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=bt_client_address_1,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
            async_timeout=60)
        logger().info(
            f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
            f"{char_properties}")
        assert HealthThermometerMeasurementCharacteristic.Thermo_Level_UUID.lower() in char_uuids, "Unable to find {} uuid"
        # Heart Rate Service
        logger().info(" ******************** Resolving Profile ********************")
        start_handle, end_handle, data = ble_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address_1, uuid=int(HeartRateService.UUID, 16))
        assert start_handle is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch end handle.."
        char_uuids, write_handles, char_properties = ble_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=bt_client_address_1,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
            async_timeout=60)
        logger().info(
            f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
            f"{char_properties}")
        assert HeartRateMeasurementCharacterstic.HR_Measure_UUID.lower() in char_uuids, "Unable to find {} uuid"
        logger().info("Fetched Profiles Successfully from DUT")
        logger().info(f"******************** get all profiles ********************")
        uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address_2)
        logger().info(f"UUIDs fetched from DUT: {uuids}")
        assert HealthThermometerService.UUID.lower() and HeartRateService.UUID.lower() in uuids is not None, "Could not fetch the profile"
        logger().info(" ******************** Resolving Profile ********************")
        start_handle, end_handle, data = ble_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address_2, uuid=int(HealthThermometerService.UUID, 16))
        assert start_handle is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch end handle.."
        char_uuids, write_handles, char_properties = ble_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=bt_client_address_2,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
            async_timeout=60)
        logger().info(
            f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
            f"{char_properties}")
        assert HealthThermometerMeasurementCharacteristic.Thermo_Level_UUID.lower() in char_uuids, "Unable to find {} uuid"
        # Heart Rate Service
        logger().info(" ******************** Resolving Profile ********************")
        start_handle, end_handle, data = ble_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address_2, uuid=int(HeartRateService.UUID, 16))
        assert start_handle is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch end handle.."
        char_uuids, write_handles, char_properties = ble_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=bt_client_address_2,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
            async_timeout=60)
        logger().info(
            f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
            f"{char_properties}")
        assert HeartRateMeasurementCharacterstic.HR_Measure_UUID.lower() in char_uuids, "Unable to find {} uuid"
        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address_1)
        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address_2)
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)

    finally:
        if ble_client1 is not None:
            ble_client1.interfaces.bluetooth.close()
        if ble_client2 is not None:
            ble_client2.interfaces.bluetooth.close()
        if ble_obj is not None and bt_dut_address is not None and bt_client_address_1 is not None:
            sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client1,
                                       ble_client_address=bt_client_address_1,
                                       ble_dut_address=bt_dut_address)


# Helper function for test_ble_sdk_enable_blood_pressure_service_in_client_role_C19884
def ble_master_for_blood_pressure(ble_dut, remote_wiseconnect3):
    logger().info("======== start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
    assert bt_dut_address, "failed to initiate ble in dut"
    time.sleep(2)
    logger().info(" ======= start ble remote secondary DUT")
    address = remote_wiseconnect3.interfaces.sapi.ble_gatt_start(set_smp=0)
    ble_client_address = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', address).group(0)
    assert ble_client_address, "failed to initiate ble in remote dut"
    logger().info(f"address_is{ble_client_address}")
    remote_wiseconnect3.interfaces.wifi.ble_add_service(uid=0x1810)
    remote_wiseconnect3.interfaces.wifi.ble_add_char_serv_att(uid=0x2a35)
    remote_wiseconnect3.interfaces.wifi.ble_add_char_val_att(uid=0x2a35)
    logger().info(" ======= start ble adv in remote secondary DUT")
    remote_wiseconnect3.interfaces.sapi.ble_start_advertising()
    time.sleep(1)
    logger().info(" ======= start scanning in remote side")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=50)
    time.sleep(5)
    logger().info("======= enable wifi power save mode on DUT")
    ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')
    logger().info("======= enable BT power save mode on DUT")
    ble_dut.interfaces.bluetooth.enable_bt_power_save(
        psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
        psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
    time.sleep(10)
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=ble_client_address, timeout=120)
    return ble_client_address, bt_dut_address


# Helper function for service discovery
def service_discovery_on_remote_for_blood_pressure(ble_dut, ble_client_address, service_uuid=None, char_uuid=None, characteristic=None):
    logger().info("\n\n ***** Performing GATT profile discovery on Remote (raspi)  ***** \n\n\n")
    # get all profiles
    uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_client_address, async_timeout=60)
    logger().info(f"UUIds {uuids}")
    assert len(uuids) > 0, "uuids are empty"
    #  resolve profile
    start_handle, end_handle, data = ble_dut.interfaces.wifi.ble_get_profile_async(
        ble_remote_dev_address=ble_client_address,
        uuid=int(str(service_uuid), 16),
        async_timeout=60)
    logger().info(f"start_handle:{start_handle}, end_handle:{end_handle}")
    assert start_handle is not None
    assert end_handle is not None
    char_uuids, write_handles, char_properties = ble_dut.interfaces.wifi.ble_get_char_services_async(
        ble_remote_dev_address=ble_client_address,
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
    logger().info(f"characteristic:{characteristic}")
    logger().info(f"char_properties:{int(char_properties[index])}")
    logger().info("validating the characteristic property")
    assert char_properties[index].isdigit(), "Character property found is not an integer"
    assert characteristic == int(char_properties[index]), "Invalid character property found"
    write_handle = int(write_handles[index], 16)
    logger().info(f"write_handle:{write_handle}")
    assert write_handle > 0, "Unable to get write handle for configured service"
    return write_handle


@wifi_dut_marker()
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                        Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                                   Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                               Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        },
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19884')
def test_ble_sdk_enable_blood_pressure_service_in_client_role_C19884(ble_dut, remote_wiseconnect3, sl_collections):
    """Verify the BLE blood pressure service in client role with connection stability"""
    ble_client_address = None
    ble_dut_address = None
    try:
        logger().info("TESTCASE EXECUTION STARTED")
        ble_client_address, ble_dut_address = ble_master_for_blood_pressure(ble_dut, remote_wiseconnect3)
        time.sleep(10)
        write_handle_1 = service_discovery_on_remote_for_blood_pressure(
            ble_dut, ble_client_address, "0x1810", "0x2a35", BLEPermissions.DEFAULT)

        bp_data = "BP1209"

        ble_dut.interfaces.wifi.ble_get_att_descriptor(ble_devices_address=ble_client_address,
                                                       start_handle=write_handle_1, end_handle=write_handle_1 + 2)


        ble_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_client_address,
                                                  handle=write_handle_1 + 1,
                                                  enable_notify=1)
        time.sleep(2)
        for i in range(10):
            remote_wiseconnect3.interfaces.wifi.ble_set_local_att_value(notify_data=bp_data,
                                                                        val_handle=write_handle_1)
            time.sleep(3)
        logger().info("checking connection stability for 10 mins")
        time.sleep(600)
        state = remote_wiseconnect3.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        assert state_int == 8, "There is no connection stability"
        logger().info("Connection is stable after 10 mins")

    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise

    finally:
        try:
            remote_wiseconnect3.interfaces.wifi.ble_remove_service()
        except Exception as e:
            logger().info(f"Failed to remove service: {e}")
        if ble_client_address is not None:
            state = ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            logger().info(f"\nDevice state: {state_int}")
            try:
                ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
                logger().info("Disconnected successfully")
            except Exception as e:
                logger().info(f"Disconnect failed: {e}")


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                        Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE| 80,#Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | 156 << 5 | #Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES
                                       Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
]
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
@pytest.mark.test_src_map_id('C537616')
def test_add_multiple_services_establish_connection_C537616(ble_dut, ble_client, sl_collections):
    """BLE Add 10 services, 80 attribute values and establish connections in slave mode"""
    bt_dut_address = None
    bt_client_address = None
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_add_multiple_services_C537616_{int(time.time())}.log") as bt_logs:
            service_uid_1 = "0000180d-0000-1000-8000-00805f9b34fb"
            service_uid_2 = "00001810-0000-1000-8000-00805f9b34fb"
            service_uid_3 = "00001802-0000-1000-8000-00805f9b34fb"
            service_uid_4 = "00001808-0000-1000-8000-00805f9b34fb"
            service_uid_5 = "0000180f-0000-1000-8000-00805f9b34fb"
            service_uid_6 = "00001809-0000-1000-8000-00805f9b34fb"
            service_uid_7 = "00001803-0000-1000-8000-00805f9b34fb"
            service_uid_8 = "0000181b-0000-1000-8000-00805f9b34fb"
            char_uid1 = "00002a37-0000-1000-8000-00805f9b34fb"
            char_uid2 = "00002a35-0000-1000-8000-00805f9b34fb"
            char_uid3 = "00002a06-0000-1000-8000-00805f9b34fb"
            char_uid4 = "00002a18-0000-1000-8000-00805f9b34fb"
            char_uid5 = "00002a19-0000-1000-8000-00805f9b34fb"
            char_uid6 = "00002a1c-0000-1000-8000-00805f9b34fb"
            char_uid7 = "00002a06-0000-1000-8000-00805f9b34fb"
            char_uid8 = "00002a9c-0000-1000-8000-00805f9b34fb"
            logger().info(" ******* Start BLE GATT Service ******* ")
            bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            logger().info(f"DUT-ADDRESS: {bt_dut_address}")
            assert bt_dut_address, "Failed to load bt address..."
            # Heart rate service
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x180D)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A37)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A37)
            time.sleep(2)
            # Blood Pressure Service
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x1810)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A35)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A35)
            time.sleep(2)
            # Immediate Alert Service
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x1802)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A06)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A06)
            time.sleep(2)
            # Glucose Service
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x1808)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A18)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A18)
            time.sleep(2)
            # Battery Service
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x180F)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A19)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A19)
            # Health Thermometer Service
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x1809)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A1C)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A1C)
            time.sleep(2)
            # Link Loss Service
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x1803)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A06)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A06)
            # Body Composition Service
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x181B)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A9C)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A9C)
            time.sleep(2)
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
            logger().info(f"CLIENT-ADDRESS:{bt_client_address}")
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
            time.sleep(20)
            logger().info("verifying dut state after the conn......")
            state = ble_dut.interfaces.bluetooth.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "Device isn't in connected state"
            logger().info(f"******fetching services and characterstics from remote")
            servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            logger().info(f"Services: {servs}")
            logger().info(f"Characteristics: {chars}")
            assert len(servs) > 0, "no services fetched"
            assert len(chars) > 0, "fetched characters are empty"
            logger().info(f"****** resolve characterstics from remote--> char uid1")
            char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid_1,
                char_uid=char_uid1)
            logger().info(f"char_path is {char_path}")
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"
            logger().info(f"****** resolve characteristics from remote--> char uid2")
            char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid_2,
                char_uid=char_uid2)
            logger().info(f"char_path is {char_path}")
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"
            logger().info(f"****** resolve characterstics from remote--> char uid3")
            char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid_3,
                char_uid=char_uid3)
            logger().info(f"char_path is {char_path}")
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"
            logger().info(f"****** resolve characterstics from remote--> char uid4")
            char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid_4,
                char_uid=char_uid4)
            logger().info(f"char_path is {char_path}")
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"
            logger().info(f"****** resolve characterstics from remote--> char uid5")
            char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid_5,
                char_uid=char_uid5)
            logger().info(f"char_path is {char_path}")
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"
            logger().info(f"****** resolve characterstics from remote--> char uid6")
            char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid_6,
                char_uid=char_uid6)
            logger().info(f"char_path is {char_path}")
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"
            logger().info(f"****** resolve characterstics from remote--> char uid7")
            char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid_7,
                char_uid=char_uid7)
            logger().info(f"char_path is {char_path}")
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"
            time.sleep(10)
            logger().info(f"****** resolve characterstics from remote--> char uid8")
            char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid_8,
                char_uid=char_uid8)
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
        try:
            ble_dut.interfaces.wifi.ble_remove_service()
        except Exception as e:
            logger().info(f"Failed to remove service: {e}")
        ble_client.interfaces.bluetooth.close()
        if bt_dut_address is not None and bt_client_address is not None:
            sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client,
                                       ble_client_address=bt_client_address,
                                       ble_dut_address=bt_dut_address)