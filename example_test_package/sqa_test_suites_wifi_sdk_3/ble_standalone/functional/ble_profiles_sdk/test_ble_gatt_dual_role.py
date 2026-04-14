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
class BleFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_start=True, bt_dut_address=None, thermometer=None, powersave=False, battery_service=False, HeartRate=False, ht=False, battery_heartrate=False, pair=False, link_loss=False, glucose=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.bt_dut_address = bt_dut_address
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
                    ble_remote_dev_address=self.bt_client_address, ble_scan_interval=160, ble_scan_window=80,
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
                    self.wifi_dut.interfaces.wifi.ble_connect_cancel(device_address=self.bt_client_address)
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
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(ble_remote_dev_address=bt_client_address, data=data)
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
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
]


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", ["ble_stop_adv"]])
@pytest.mark.test_src_map_id('C19876')
def test_ble_sdk_fetch_profiles_in_dual_role_from_RD1_C19876(ble_dut, ble_clients, sl_collections):
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_C19876.log_{int(time.time())}"):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            service_uid = "0000180d-0000-1000-8000-00805f9b34fb"
            char_uid1 = "00002a37-0000-1000-8000-00805f9b34fb"
            logger().info(" ******* Start BLE  Service ******* ")
            bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
            assert bt_dut_address, "Failed to load bt address..."

            # ble_dut.interfaces.bluetooth.ble_set_cap_data(remote_addr_type=1, smp_io_cap=0,
            #                                                smp_auth_req_bonding=1,
            #                                                smp_auth_req_mitm=1,
            #                                                smp_auth_req_sc=1, smp_max_enc_key_size=16,
            #                                                smp_local_oob_data_flag_not_present=0,
            #                                                smp_enc_key=1, smp_id_key=0,
            #                                                smp_sign_key=0)

            index = 1
            logger().info(f"adding custom_service to DUT")
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x180D)
            # ble_add_char_serv_att 10807 26 1 2 -> Heart rate measurement(0x2A37)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A37, service_handler_num=index, permissions=0x10,
                                                               value_handler_num=index + 1)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A37, value_handler_num=index + 1, permissions=0x10)

            logger().info("start ble advertising....")
            ble_dut.interfaces.bluetooth.ble_start_advertising()
            enable_wifi_ps = ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')
            assert enable_wifi_ps == 0, 'failed to enable wlan power save'
            enable_bt_ps = ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            assert enable_bt_ps == 0, 'failed to enable bt power save'
            ble_client1.interfaces.bluetooth.close()
            logger().info("scanning for ble client.. ")
            bt_client_address = ble_client1.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address, service_classes=["HeartRateService"])
            assert bt_client_address, "The client address is not found"
            time.sleep(5)
            logger().info(f"ble_client1 address {bt_client_address}")
            ble_client1.interfaces.bluetooth.stop_scanning()
            ble_dut.interfaces.bluetooth.ble_scanning = False
            ble_dut.interfaces.bluetooth.ble_advertising = False
            logger().info("verifying device in scan list...")
            found_devices = ble_client1.interfaces.bluetooth.get_devices()
            assert ble_dut.interfaces.bluetooth.ble_address in found_devices, "failed to find dut address in scan list..."
            assert (found_devices[
            ble_dut.interfaces.bluetooth.ble_address] == ble_dut.interfaces.bluetooth.ble_advertising_data), \
            "failed to find dut in scan list..."
            try:
                logger().info("connecting to dut....")
                ble_client1.interfaces.bluetooth.connect(bt_dut_address)
            except Exception:
                ble_client1.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(60)
            status = ble_client1.interfaces.bluetooth.get_connection_status(bt_dut_address)
            logger().info(f"Connection status in remote device '{ble_client1}' is:{status}")
            assert status, f"Remote device '{ble_client1.name}' is not connected to DUT"
            logger().info(f"get all profiles")
            servs, chars = ble_client1.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            assert len(servs) > 0, "no services fetched"
            assert len(chars) > 0, "fetched characters are empty"
            char_path, char_props = ble_client1.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                        service_uid=service_uid,
                                                                                                        char_uid=char_uid1)

            logger().info(f"char_path is {char_path}")
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"
            ble_dut.interfaces.bluetooth.ble_set_smp(set_smp=1)
            ble_client2.interfaces.bluetooth.close()
            assert bt_dut_address, "Failed to load bt address..."
            bt_client_address2 = ble_client2.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address, service_classes=["HeartRateService", "HealthThermometerService"]
            )
            assert bt_client_address2 is not None, "init failed for rpi"
            ble_dut.interfaces.bluetooth.ble_start_scanning(
            ble_client_address=bt_client_address2, timeout=120
            )
            ble_dut.interfaces.wifi.ble_stop_scanning()
            ble_dut.interfaces.wifi.ble_advertising = False
            time.sleep(5)
            try:
                logger().info(f"Initiating connection")
                ble_dut.interfaces.bluetooth.ble_connect(ble_scan_interval=50, ble_scan_window=50,
                ble_remote_dev_address=bt_client_address2,
                timeout=120
                )
            except Exception:
                ble_dut.interfaces.wifi.ble_stop_advertising()
            time.sleep(60)
            status = ble_client2.interfaces.bluetooth.get_connection_status(bt_dut_address)
            logger().info(f"Connection status in remote device_2 {ble_client2} is:{status}")
            assert status, f"Remote device '{ble_client2}' is not connected to DUT"
            logger().info(f"get all profiles")
            uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address2,
            timeout=20)
            assert HeartRateService.UUID.lower() in uuids
            assert HealthThermometerService.UUID in uuids

    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)

    finally:
        logger().info(f"Removing services on dut")
        ble_dut.interfaces.wifi.ble_remove_service()
        ble_client1.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(5)
        ble_client2.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(3)
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()
        sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client1,
                                   ble_client_address=bt_client_address,
                                   ble_dut_address=bt_dut_address)
        sl_collections.cleanup_ble(ble_dut=ble_dut, ble_client=ble_client2,
                                   ble_client_address=bt_client_address,
                                   ble_dut_address=bt_dut_address)


