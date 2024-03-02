import time
import pytest
import re
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryService
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryLevelCharacteristic
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryService
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService
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
    def __init__(self, wifi_dut=None, ble_client=None, bt_dut_address=None, powersave=False, battery_service=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.bt_dut_address = bt_dut_address
        self.powersave = powersave
        self.battery_service = battery_service


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
        try:
            logger().info("connecting to dut....")
            self.ble_client.interfaces.bluetooth.connect(self.bt_dut_address)
        except Exception:
            self.wifi_dut.interfaces.wifi.ble_stop_advertising()

    def ble_gatt_scan(self):
        # Start DUT
        bt_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start()
        assert bt_dut_address is not None, "gatt init failed in DUT"
        if self.battery_service:
        # Start ble client
            self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address, service_classes=["BatteryService"]
            )
            assert self.bt_client_address is not None, "init failed for rpi"
        else:
            self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address
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

    def check_device_state_on_dut(self):
        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

    def check_device_state_on_rasp(self):
        status = self.ble_client.interfaces.bluetooth.get_connection_status(self.bt_dut_address)
        logger().info(f"Connection status in remote device '{self.ble_client.name}' is:{status}")
        assert status, f"Remote device '{self.ble_client.name}' is not connected to DUT"


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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
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
        start_handle, end_handle = wifi_dut.interfaces.wifi.ble_get_profile_async(
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


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
def test_ble_sdk_fetch_profiles_from_RD1_C19862(wifi_dut, ble_client, utf_constants, sl_collections):
    try:
        ble_obj = BleFunctionality(wifi_dut, ble_client)
        bt_client_address = ble_obj.ble_gatt_scan()
        ble_obj.check_device_state_on_dut()
        logger().info(f"get all profiles")
        uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
        assert not(BatteryService.UUID) in uuids, "able to fetch the battery profile"
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        logger().info(" Issued BLE disconnect ")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_scan",
                                         "ble_disconnect"])
def test_ble_sdk_fetch_profiles_in_dual_role_from_RD1_C19876(wifi_dut, ble_client, utf_constants, sl_collections):
    try:
        logger().info(" ******* Start BLE GATT Service ******* ")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address, "Failed to load bt address..."
        # adding service, attributes, values
        index = 1
        # ble_add_service 6157 -> Heart rate service(0x180D)
        wifi_dut.interfaces.wifi.ble_add_service(uid=0x180D)
        # ble_add_char_serv_att 10808 26 1 2 -> Body sensor location(0x2A38)
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A38, service_handler_num=index + 2,
                                                           value_handler_num=index + 3)
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A38, value_handler_num=index + 3)

        # ble_add_char_serv_att 10809 26 1 2 -> Heart rate control point(0x2A39)
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A39, service_handler_num=index + 4,
                                                           value_handler_num=index + 5)
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A39, value_handler_num=index + 5)

        ble_obj = BleFunctionality(wifi_dut, ble_client)
        ble_obj.ble_adv()
        ble_obj.check_device_state_on_rasp()
        servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"
        bt_client_address = ble_obj.ble_gatt_scan()
        ble_obj.check_device_state_on_dut()
        uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
        assert (BatteryService.UUID) in uuids, "able to fetch the battery profile"
        # # Disconnect
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        logger().info(" Issued BLE disconnect ")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
