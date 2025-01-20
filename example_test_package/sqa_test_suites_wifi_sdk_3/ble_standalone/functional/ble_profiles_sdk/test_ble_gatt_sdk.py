import time
import pytest
import re
import string
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
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService,  HeartRateMeasurementCharacterstic
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
        if self.HeartRate:
            self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address, service_classes=["HeartRateService"]
            )
            assert self.bt_client_address is not None, "init failed for rpi"
        elif self.battery_service:
            self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address, service_classes=["BatteryService"]
            )
            assert self.bt_client_address is not None, "init failed for rpi"
        elif self.thermometer:
            self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address, service_classes=["HealthThermometerService"]
            )
            assert self.bt_client_address is not None, "init failed for rpi"
        elif self.glucose:
            self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address, service_classes=["GlucoseService"]
            )
            assert self.bt_client_address is not None, "init failed for rpi"
        elif self.ht:
            self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address, service_classes=["HeartRateService", "HealthThermometerService"]
            )
            assert self.bt_client_address is not None, "init failed for rpi"
        else:
            self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address, service_classes=["LinkLossService"]
            )
            assert self.bt_client_address is not None, "init failed for rpi"
        # Start scanning and connect to ble client
        self.wifi_dut.interfaces.wifi.ble_start_scanning(
            ble_client_address=self.bt_client_address, timeout=30
        )
        enable_wifi_ps = self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps = self.wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        timeout = 60
        logger().info(f"Initiating connection this can take upto {timeout} seconds....")
        self.wifi_dut.interfaces.wifi.ble_connect(
            ble_remote_dev_address=self.bt_client_address,
            timeout=timeout,
        )
        time.sleep(60)
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





pytestmark = [
    pytest.mark.config(
        "wifi_dut",
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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST ,
        },
    )
]



@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_link_loss_profiles_from_rd1_c19874(wifi_dut, ble_client, sl_collections):
    try:
        service_uid = "00001803-0000-1000-8000-00805f9b34fb"
        char_uid = "00002a06-0000-1000-8000-00805f9b34fb"
        # BLE DUT initialization
        logger().info(" ******* Start BLE GATT service ******* ")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=0)
        assert bt_dut_address, "Failed to load bt address..."
        # adding services, attributes and values
        wifi_dut.interfaces.wifi.ble_add_service(uid=0x1803)
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A06)
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A06)
        ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, powersave=True)
        ble_obj.ble_adv()
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



@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
def test_ble_sdk_fetch_profiles_from_RD1_C19860(wifi_dut, ble_client, utf_constants, sl_collections):
    """verify slave connection and master connection from dut"""
    try:
        ble_obj = BleFunctionality(wifi_dut, ble_client, battery_service=True)
        bt_client_address = ble_obj.ble_gatt_scan()
        logger().info(f"get all profiles")
        uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
        assert BatteryService.UUID in uuids is not None, "Could not fetch the battery profile"
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        logger().info(" Issued BLE disconnect ")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()



@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
def test_ble_sdk_fetch_a_particular_profiles_from_RD1_C19861(wifi_dut, ble_client, sl_collections, utf_constants):
    try:
        ble_obj = BleFunctionality(wifi_dut, ble_client, battery_service=True)
        bt_client_address = ble_obj.ble_gatt_scan()
        ble_obj.check_device_state_on_dut()
        logger().info(f"get all profiles")
        uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
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


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_fetch_profiles_from_RD1_C19862(wifi_dut, ble_client, utf_constants, sl_collections):
    try:
        ble_obj = BleFunctionality(wifi_dut, ble_client)
        bt_client_address = ble_obj.ble_gatt_scan()
        ble_obj.check_device_state_on_dut()
        logger().info(f"get all profiles")
        wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
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



@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", ["ble_stop_adv"]])
def test_ble_sdk_fetch_profiles_in_dual_role_from_RD1_C19876(ble_dut, ble_clients, utf_constants, sl_collections):
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_C19876.log_{int(time.time())}"):
            assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            service_uid = "0000180d-0000-1000-8000-00805f9b34fb"
            char_uid1 = "00002a37-0000-1000-8000-00805f9b34fb"
            logger().info(" ******* Start BLE  Service ******* ")
            bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
            assert bt_dut_address, "Failed to load bt address..."
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
                ble_client1.interfaces.bluetooth.connect(bt_dut_address, min_conn_interval=128, max_conn_interval=128, conn_latency=0, supervision_timeout=3200)
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
            ble_client2.interfaces.bluetooth.close()
            assert bt_dut_address, "Failed to load bt address..."
            bt_client_address2 = ble_client2.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address, service_classes=["HeartRateService", "HealthThermometerService"]
            )
            assert bt_client_address2 is not None, "init failed for rpi"
            ble_dut.interfaces.bluetooth.ble_start_scanning(
            ble_client_address=bt_client_address2, timeout=30
            )
            ble_dut.interfaces.wifi.ble_stop_scanning()
            time.sleep(5)
            try:
                logger().info(f"Initiating connection")
                ble_dut.interfaces.bluetooth.ble_connect(
                ble_remote_dev_address=bt_client_address2, ble_conn_interval_min=160, ble_conn_interval_max=160,
                timeout=60, ble_supervision_timeout=3200,
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


@pytest.mark.skip()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_fetch_profiles_in_dual_role_from_RD1_C19877(ble_dut, ble_clients, utf_constants, sl_collections):
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_C19877_{int(time.time())}") as bt_logs:
            assert len(ble_clients) >= 3, f"Minimum 3 Raspi devices needed"
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            ble_client3 = ble_clients[2]
            service_uid = "0000180d-0000-1000-8000-00805f9b34fb"
            char_uid1 = "00002a37-0000-1000-8000-00805f9b34fb"

            logger().info(" ******* Start BLE GATT Service ******* ")
            bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
            assert bt_dut_address, "Failed to load bt address..."
            index = 1
            logger().info(f"adding heart_rate service")
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x180D)
            # ble_add_char_serv_att 10807 26 1 2 -> Heart rate measurement(0x2A37)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A37, service_handler_num=index,
                                                               permissions=0x2,
                                                               value_handler_num=index + 1)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A37, value_handler_num=index + 1,
                                                              permissions=0x2)
            # ble_add_char_serv_att 10808 26 1 2 -> Body sensor location(0x2A38)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A38, service_handler_num=index + 3,
                                                               value_handler_num=index + 4, permissions=0x2)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A38, value_handler_num=index + 4,
                                                              permissions=0x2)
            # ble_add_char_serv_att 10809 26 1 2 -> Heart rate control point(0x2A39)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A39, service_handler_num=index + 5,
                                                               value_handler_num=index + 6, permissions=0x2)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A39, value_handler_num=index + 6,
                                                              permissions=0x2)
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
            bt_client_address = ble_client1.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address, "The client address is not found"
            time.sleep(5)
            logger().info("ble_client1 address {bt_client_address}")
            ble_client1.interfaces.bluetooth.stop_scanning()
            ble_dut.interfaces.bluetooth.ble_scanning = False
            ble_dut.interfaces.bluetooth.ble_advertising = False
            logger().info("verifying device in scan list...")
            found_devices = ble_client1.interfaces.bluetooth.get_devices()
            assert ble_dut.interfaces.bluetooth.ble_address in found_devices, "failed to find dut address in scan list..."
            assert (found_devices[
                        ble_dut.interfaces.bluetooth.ble_address] == ble_dut.interfaces.bluetooth.ble_advertising_data), \
                "failed to find dut in scan list..."
            logger().info("connecting to d`ut....")
            ble_client1.interfaces.bluetooth.connect(bt_dut_address)
            time.sleep(60)
            status = ble_client1.interfaces.bluetooth.get_connection_status(bt_dut_address)
            logger().info(f"Connection status in remote device '{ble_client1}' is:{status}")
            assert status, f"Remote device '{ble_client1.name}' is not connected to DUT"
            servs, chars = ble_client1.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            assert len(servs) > 0, "no services fetched"
            assert len(chars) > 0, "fetched characters are empty"
            char_path, char_props = ble_client1.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                        service_uid=service_uid,
                                                                                                        char_uid=char_uid1)

            logger().info(f"char_path is {char_path}")
            ble_client2.interfaces.bluetooth.close()
            bt_client_address2 = ble_client2.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address, service_classes=["HeartRateService", "HealthThermometerService"]
            )
            assert bt_client_address2 is not None, "init failed for rpi"
            logger().info(f"Start scanning and connect to ble client")
            ble_dut.interfaces.bluetooth.ble_start_scanning(
                ble_client_address=bt_client_address2, timeout=30
            )
            ble_dut.interfaces.wifi.ble_stop_scanning()
            time.sleep(5)
            try:
                logger().info(f"Initiating connection...")
                ble_dut.interfaces.bluetooth.ble_connect(
                    ble_remote_dev_address=bt_client_address2, ble_conn_interval_min=128, ble_conn_interval_max=128,
                    timeout=60, ble_supervision_timeout=3200,
                )
            except Exception:
                ble_dut.interfaces.wifi.ble_stop_advertising()
            time.sleep(60)
            status = ble_client2.interfaces.bluetooth.get_connection_status(bt_dut_address)
            logger().info(f"Connection status in remote device_2 {ble_client2} is:{status}")
            assert status, f"Remote device '{ble_client2}' is not connected to DUT"
            uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address2,
                                                                   timeout=20)
            assert HeartRateService.UUID.lower() in uuids
            assert HealthThermometerService.UUID in uuids
            ble_client3.interfaces.bluetooth.close()
            bt_client_address3 = ble_client3.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address, service_classes=["HeartRateService", "HealthThermometerService"]
            )
            assert bt_client_address3 is not None, "init failed for rpi"
            logger().info(f"Start scanning and connect to ble client")
            ble_dut.interfaces.bluetooth.ble_start_scanning(
                ble_client_address=bt_client_address3, timeout=30
            )
            ble_dut.interfaces.wifi.ble_stop_scanning()
            time.sleep(5)
            try:
                logger().info(f"Initiating connection")
                ble_dut.interfaces.bluetooth.ble_connect(
                    ble_remote_dev_address=bt_client_address3, ble_conn_interval_min=128, ble_conn_interval_max=128,
                    timeout=60, ble_supervision_timeout=3200,
                )
            except Exception:
                ble_dut.interfaces.wifi.ble_stop_advertising()
            time.sleep(60)
            status = ble_client3.interfaces.bluetooth.get_connection_status(bt_dut_address)
            logger().info(f"Connection status in remote device_3 {ble_client3} is:{status}")
            assert status, f"Remote device '{ble_client3}' is not connected to DUT"
            logger().info(f"get all profiles")
            uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address3,
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
        time.sleep(5)
        ble_client3.interfaces.bluetooth.disconnect(bt_dut_address)

@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_validate_adding_service_in_slave_role_C19878(ble_dut, ble_client, utf_constants, sl_collections):
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_C19878_{int(time.time())}.log") as bt_logs:
            service_uid = "0000180d-0000-1000-8000-00805f9b34fb"
            char_uid1 = "00002a37-0000-1000-8000-00805f9b34fb"
            char_uid2 = "00002a38-0000-1000-8000-00805f9b34fb"
            char_uid3 = "00002a39-0000-1000-8000-00805f9b34fb"
            logger().info(" ******* Start BLE GATT Service ******* ")
            bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0)
            assert bt_dut_address, "Failed to load bt address..."
            index = 1
            logger().info("********Adding Heartrate Service to the dut..UUID VALUE : 0x180D************")
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x180D)
            # ble_add_char_serv_att 10807 26 1 2 -> Heart rate measurement(0x2A37)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A37, service_handler_num=index, permissions=0x2,
                                                               value_handler_num=index + 1)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A37, value_handler_num=index + 1, permissions=0x2)

            # ble_add_char_serv_att 10808 26 1 2 -> Body sensor location(0x2A38)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A38, service_handler_num=index + 2,
                                                               value_handler_num=index + 3, permissions=0x2)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A38, value_handler_num=index + 3, permissions=0x2)

            # ble_add_char_serv_att 10809 26 1 2 -> Heart rate control point(0x2A39)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x2A39, service_handler_num=index + 4,
                                                               value_handler_num=index + 5, permissions=0x2)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x2A39, value_handler_num=index + 5, permissions=0x2)
            logger().info("start ble advertising....")
            ble_dut.interfaces.bluetooth.ble_start_advertising()

            enable_wifi_ps = ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')
            assert enable_wifi_ps == 0, 'failed to enable wlan power save'
            enable_bt_ps = ble_dut.interfaces.bluetooth.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            assert enable_bt_ps == 0, 'failed to enable bt power save'

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

            char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                        service_uid=service_uid,
                                                                                                        char_uid=char_uid1)
            logger().info(f"char_path is {char_path}")
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"
            logger().info(f"****** resolve characterstics from remote--> char uid2")

            char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                        service_uid=service_uid,
                                                                                                        char_uid=char_uid2)
            logger().info(f"char_path is {char_path}")
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"

            logger().info(f"****** resolve characterstics from remote--> char uid3")

            char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
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



@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
def test_ble_sdk_connect_disconnect_multiple_times_from_RD1_C19875(wifi_dut, ble_client, utf_constants, sl_collections):
    """verify gatt connection and disconnection multiple times"""
    try:
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
        assert bt_dut_address is not None, "gatt init failed in DUT"
        timeout = 60
        for i in range(0, 5):
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
            logger().info(f"Initiating connection this can take upto {timeout} seconds....")
            wifi_dut.interfaces.wifi.ble_connect(
                ble_remote_dev_address=bt_client_address,
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
            logger().info(f"*******iteration: {i+1}***********")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_enable_heartrate_service_in_server_role_C19879(wifi_dut, ble_client, utf_constants, sl_collections):
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
            ble_obj.ble_adv()
            time.sleep(60)
            ble_obj.check_device_state_on_rasp()
            char_path =ble_obj.resolving_services_on_remote(service_uuid=service_uuid, char_uuid=char_uuid)
            ble_obj.tx_on_dut(char_path=char_path, char_uuid=char_uuid, data=data)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(2)
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()

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
            ble_obj.ble_adv()
            time.sleep(60)
            ble_obj.check_device_state_on_rasp()
            char_path =ble_obj.resolving_services_on_remote(service_uuid=service_uuid, char_uuid=char_uuid)
            ble_obj.tx_on_dut(char_path=char_path, char_uuid=char_uuid, data=data)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(2)
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_enable_health_thermometer_in_server_role_C19885(wifi_dut, ble_client, utf_constants, sl_collections):
    """ENABLE health thermometer IN SERVER ROLE"""
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_C19885_{int(time.time())}") as bt_logs:
            service_uuid = "00001809-0000-1000-8000-00805f9b34fb"  # health_thermometer_service
            char_uuid = "00002a1c-0000-1000-8000-00805f9b34fb"
            data = "38.0'c"
            logger().info(" ******* Start BLE Service ******* ")
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=0)
            assert bt_dut_address, "Failed to load bt address..."
            ble_obj = BleFunctionality(wifi_dut, ble_client, bt_dut_address=bt_dut_address, powersave=True)
            logger().info(f"Adding health thermometer on dut")
            ble_obj.add_services_on_dut(uuid=0x1809, Charc_serv=0x2A1C)
            ble_obj.ble_adv()
            time.sleep(60)
            ble_obj.check_device_state_on_rasp()
            char_path =ble_obj.resolving_services_on_remote(service_uuid=service_uuid, char_uuid=char_uuid)
            ble_obj.tx_on_dut(char_path=char_path, char_uuid=char_uuid, data=data)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(2)
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()


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


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
def test_ble_sdk_fetch_desc_from_RD1_C19864(wifi_dut, ble_client, utf_constants, sl_collections):
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



pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_enable_battery_service_in_server_role_C19881(wifi_dut, ble_client, utf_constants, sl_collections):
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
            ble_obj.ble_adv()
            time.sleep(60)
            ble_obj.check_device_state_on_rasp()
            char_path =ble_obj.resolving_services_on_remote(service_uuid=service_uuid, char_uuid=char_uuid)
            ble_obj.tx_on_dut(char_path=char_path, char_uuid=char_uuid, data=data)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(2)
        logger().info(f"Removing services on dut")
        wifi_dut.interfaces.wifi.ble_remove_service()
        ble_client.interfaces.bluetooth.close()

@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_validate_prepare_and_execute_att_values_C19871(ble_dut, ble_client, utf_constants, sl_collections):
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_C19871_{int(time.time())}.log") as bt_logs:
            logger().info(" ******* Start BLE GATT Service ******* ")
            bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
            assert bt_dut_address, "Failed to load bt address..."
            ble_obj = BleFunctionality(ble_dut, ble_client, bt_dut_address=bt_dut_address, powersave=True, link_loss=True)
            bt_client_address = ble_obj.ble_adv()
            time.sleep(60)
            ble_obj.check_device_state_on_rasp()
            logger().info(f"get all profiles")
            uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
            assert LinkLossService.UUID.lower() in uuids is not None, "Could not fetch the Link loss profile"
            logger().info(" Resolving Linkloss profile from RD1")
            start_handle, end_handle, data = ble_dut.interfaces.wifi.ble_get_profile_async(
                ble_remote_dev_address=bt_client_address,
                uuid=int(LinkLossService.UUID, 16))
            assert start_handle is not None, "failed to fetch the start handle.."
            assert end_handle is not None, "failed to fetch end handle.."
            char_uuid = LinkLossAlertLevelCharacteristic.LLA_UUID
            characteristic = LinkLossAlertLevelCharacteristic
            char_uuids, write_handles, char_properties = ble_dut.interfaces.bluetooth.ble_get_char_services_async(
                ble_remote_dev_address=bt_client_address,
                start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))
            assert char_uuid in char_uuids, "Unable to find {} uuid".format(char_uuid)
            index = char_uuids.index(char_uuid)
            logger().info(f"UUID's are:{char_uuids}")
            logger().info(f"write_handles:{write_handles}")
            logger().info(f"index:{index}")
            assert char_properties[index].isdigit(), "Character property found is not an integer"
            assert characteristic.prop_int == int(char_properties[index]), "Invalid character property found"
            write_handle = int(write_handles[index], 16)
            assert write_handle > 0
            ble_dut.interfaces.bluetooth.ble_prepare_write_async(ble_remote_dev_address=bt_client_address, handle=write_handles[0], offset=1, data_len=10, data="hjdhwjdjjd")
            ble_dut.interfaces.bluetooth.ble_execute_write_async(ble_remote_dev_address=bt_client_address, exe_flag=1)
            time.sleep(30)
            logger().info("Disconnecting from dut...")
            ble_client.interfaces.bluetooth.disconnect(bt_dut_address)

    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan"])
def test_ble_sdk_enable_heartrate_service_in_client_role_C19880(wifi_dut, ble_client, utf_constants, sl_collections):
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



@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan"])
def test_ble_sdk_enable_battery_service_in_client_role_C19882(wifi_dut, ble_client, utf_constants, sl_collections):
    """ENABLE Battery SERVICE IN CLIENT ROLE"""
    bt_mon_log_file = "reports/test_ble_sdk_C19882"
    try:
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
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



@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan"])
def test_ble_sdk_enable_health_thermomter_service_in_client_role_C19886(wifi_dut, ble_client, utf_constants, sl_collections):
    """ENABLE Blood pressure SERVICE IN CLIENT ROLE"""
    bt_mon_log_file = "reports/test_wifi_sdk_C19886"
    try:
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
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


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan"])
def test_ble_sdk_enable_glucose_service_in_client_role_C19888(wifi_dut, ble_client, sl_collections):
    """ENABLE Glucose SERVICE IN CLIENT ROLE"""
    bt_mon_log_file = "reports/test_wifi_sdk_C19888"
    try:
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
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



def test_ble_sdk_enable_slave_connection_in_client_role_C19877(wifi_dut, ble_clients, sl_collections):
    assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]
    try:
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start(set_smp=0)
        assert bt_dut_address is not None, "gatt init failed in DUT"
        wifi_dut.interfaces.wifi.bt_set_local_name("BLE_AUTOMATION")
        status = wifi_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f" ======= Getting the local name : {status}")
        ble_obj = BleFunctionality(wifi_dut, ble_client=ble_client1, bt_dut_address=bt_dut_address, ble_start=False, powersave=True)
        ble_obj.add_services_on_dut(uuid=0xAABB, Charc_serv=0x1AA1)
        ble_client_address = ble_obj.ble_adv()
        time.sleep(60)
        ble_obj.check_device_state_on_rasp()
        char_path = ble_obj.resolving_services_on_remote(service_uuid=service_uid, char_uuid=char_uid)
        ble_obj.tx_on_dut_custom(bt_client_address=ble_client_address, char_path=char_path, char_uid=char_uid)
        ble_obj = BleFunctionality(wifi_dut, ble_client=ble_client2, bt_dut_address=bt_dut_address, ble_start=False)
        ble_client_address = ble_obj.ble_adv()
        time.sleep(60)
        ble_obj.check_device_state_on_rasp()
        char_path = ble_obj.resolving_services_on_remote(service_uuid=service_uid, char_uuid=char_uid)
        ble_obj.tx_on_dut_custom(bt_client_address=ble_client_address, char_path=char_path, char_uid=char_uid)
        ble_obj.check_device_state_on_rasp()
        status = ble_client1.interfaces.bluetooth.get_connection_status(bt_dut_address)
        logger().info(f"Connection status in remote device '{ble_client1.name}' is:{status}")
        ble_client1.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(5)
        ble_client2.interfaces.bluetooth.disconnect(bt_dut_address)
        logger().info("******************** ble_remove_service ***********************")
        wifi_dut.interfaces.wifi.ble_remove_service()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client1.interfaces.bluetooth.close()
        ble_client2.interfaces.bluetooth.close()


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
        timeout = 60
        logger().info(f"Initiating connection this can take upto {timeout} seconds....")
        wifi_dut.interfaces.wifi.ble_connect(
            ble_remote_dev_address=bt_client_address,
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
        wifi_dut.interfaces.wifi.ble_stop_advertising()



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
        timeout = 60
        logger().info(f"Initiating connection this can take upto {timeout} seconds....")
        wifi_dut.interfaces.wifi.ble_connect(
            ble_remote_dev_address=bt_client_address,
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
        wifi_dut.interfaces.wifi.ble_stop_advertising()
