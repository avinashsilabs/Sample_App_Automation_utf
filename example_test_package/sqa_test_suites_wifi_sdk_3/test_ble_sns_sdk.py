import pytest
import time
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xPowerSaveModes, \
    Si91xPowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
import string
import random
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService
import re


def logger():
    return get_logger(__name__)


"""
    Setup requirement:
        1. SoC board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Initiates the DUT in master Spp mode for the capability
        3. Initiates the client in slave spp with capability enables
        4. Opens Bt socket and connects to the remote client.
        5. Verifies ping after the connection.

    Author: Ayush Agarwal / Saurabh Sharma
"""


class BLEMasterSNS(ThreadBase):
    def __init__(self, wifi_dut=None, test_case=None, sl_collections=None, power_save=None, ble_client=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.power_save = power_save
        self.ble_client = ble_client
        self.ble_pairing = 0
        self.ble_client_address = None
        self.ble_dut_address = None

    def run(self):
        if self.test_case == '148508':
            with TimeMeasurer() as T:
                t_end = time.time() + 30 * 60
                while time.time() < t_end:
                    self.wifi_dut.interfaces.wifi.ble_start()
                    self.wifi_dut.interfaces.wifi.bt_stop()

            logger().info(f'\n*** Total execution time for init + deinit = {T.duration} ***\n')
            return

        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=self.ble_pairing)
        self.ble_client_address = self.sl_collections.ble_connection(wifi_dut=self.wifi_dut,
                                                                     ble_client=self.ble_client,
                                                                     ble_dut_address=self.ble_dut_address,
                                                                     mode="master", ble_pairing=self.ble_pairing)

        if self.test_case == '148509':
            with TimeMeasurer() as T:
                self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
                t_end = time.time() + 60 * 30
                self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.ble_client_address,
                                                                 timeout=60)
                while time.time() < t_end:
                    logger().info(f"Remote device found in scan results ,BLE scanning is successful")
                    self.wifi_dut.interfaces.wifi.ble_connect(self.ble_client_address)
            logger().info(f'\n*** Total execution time for scanning = {T.duration} ***\n')

        if self.test_case == '148510':
            with TimeMeasurer() as T:
                self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.ble_client_address,
                                                                 timeout=60)
                logger().info(f"Remote device found in scan results ,BLE scanning is successful")
                logger().info(' \n*** Wait for 30 minutes ***\n')
                time.sleep(1800)
                self.wifi_dut.interfaces.wifi.ble_stop_scanning()

            logger().info(f'\n*** Total execution time for scanning = {T.duration} ***\n')

        if self.test_case == '148511':
            with TimeMeasurer() as T:
                self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.ble_client_address,
                                                                 timeout=60)
                logger().info(f"Remote device found in scan results ,BLE scanning is successful")
                logger().info(' \n*** Wait for 30 minutes ***\n')
                time.sleep(1800)

            logger().info(f'\n*** Total execution time for scanning = {T.duration} ***\n')

        if self.test_case == '148512':
            with TimeMeasurer() as T:
                t_end = time.time() + 60 * 30
                while time.time() < t_end:
                    self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.ble_client_address,
                                                                     timeout=60)
                    logger().info(f"Remote device found in scan results ,BLE scanning is successful")
                    self.wifi_dut.interfaces.wifi.ble_stop_scanning()
            logger().info(f'\n*** Total execution time for start and stop scan = {T.duration} ***\n')


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
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
def test_wifi_sdk_ble_start_and_stop_scan_30_minutes_c148512(sl_collections, wifi_dut, ble_client):
    """This Test Case verifies BLE start scan and stop scan functionality for 30 minutes"""

    test_case = '148512'
    ble_obj = BLEMasterSNS(wifi_dut=wifi_dut, sl_collections=sl_collections, test_case=test_case, ble_client=ble_client)

    ble_obj.start()
    ble_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
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
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=['ble_stop_scan', "wifi_powersave_disable"])
def test_wifi_sdk_ble_scan_30_minutes_c148511(sl_collections, wifi_dut, ble_client):
    """This Test Case verifies BLE scan functionality for 30 minutes"""
    test_case = '148511'
    ble_obj = BLEMasterSNS(wifi_dut=wifi_dut, sl_collections=sl_collections, test_case=test_case, ble_client=ble_client)

    ble_obj.start()
    ble_obj.wait_for_exit()


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
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
def test_wifi_sdk_ble_connect_disconnect_30_minutes_c148509(sl_collections, wifi_dut, ble_client):
    """This Test Case verifies BLE device connection and device disconnection functionality for 30 minutes"""
    test_case = '148509'
    ble_obj = BLEMasterSNS(wifi_dut=wifi_dut, sl_collections=sl_collections, test_case=test_case, ble_client=ble_client)

    ble_obj.start()
    ble_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
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
def test_wifi_sdk_ble_radio_init_deinit_30_min_c148508(sl_collections, wifi_dut, ble_client):
    """This Test Case verifies BLE init radio and de-init radio functionality for 30 minutes"""
    test_case = '148508'
    ble_obj = BLEMasterSNS(wifi_dut=wifi_dut, sl_collections=sl_collections, test_case=test_case, ble_client=ble_client)

    ble_obj.start()
    ble_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_data_length_20_bytes_C148515(wifi_dut, ble_client, sl_collections, utf_constants):
    """Connect BLE as Slave mode and Run 20 bytes of TX data for 30 minutes"""
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path="./reports/test_ble_slave_data_length_20_bytes_C148515.log"):
            iter_count = utf_constants.get("iter_count")
            for count in range(iter_count):
                service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
                char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

                logger().info("*********************** Start BLE in DUT ***********************")
                bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
                assert bt_dut_address, "failed to initialize ble in dut"
                wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F)

                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.set_performance_profile()
                wifi_dut.interfaces.wifi.enable_bt_power_save()

                ble_client_address = sl_collections.check_ble_advertise_functionality(
                    wifi_dut=wifi_dut, ble_client=ble_client, ble_dut_address=bt_dut_address,
                    timeout=20)

                logger().info("*********************** connect to ble dut ***********************")
                ble_client.interfaces.bluetooth.connect(bt_dut_address)
                time.sleep(30)

                logger().info("******************** get connection state")
                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "********************* device is in disconnection state"

                servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                assert len(servs) > 0, "no services fetched"
                assert len(chars) > 0, "fetched characters are empty"

                char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                    services=servs,
                    service_uid=service_uid,
                    char_uid=char_uid)
                assert char_path, "characters are empty"
                assert len(char_props) > 0, "length of characters is 0"

                ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

                logger().info(f' *********************** subscribe to notifications ***********************')
                ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                        char_uid=char_uid)

                wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                                    buffer_mode=0, buffer_count=2)

                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
                sw = Stopwatch()
                while sw.elapsed_sec < 1800:
                    wifi_dut.interfaces.wifi.ble_notify_custom_value(data=data)
                    time.sleep(7)

                logger().info(f' *********************** unsubscribe to notifications ***********************')
                ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
                time.sleep(1)

                logger().info("******************** Validate Data ********************")
                notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
                logger().info(f' *********************** Notification is {notifications} ***********************')
                assert len(notifications) > 0, "received data is empty"
                assert notifications[0] == data, "failed to fetch data"

                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service()

                logger().info("*********************** Disconnecting from DUT ***********************")
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                ble_client.interfaces.bluetooth.close()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_data_length_230_bytes_C148516(wifi_dut, ble_client, sl_collections, utf_constants):
    """Connect BLE as Slave mode and Run 230 bytes of TX data for 30 minutes"""
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path="./reports/test_ble_slave_data_length_20_bytes_C148515.log"):
            iter_count = utf_constants.get("iter_count")
            for count in range(iter_count):
                service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
                char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

                logger().info("*********************** Start BLE in DUT ***********************")
                bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
                assert bt_dut_address, "failed to initialize ble in dut"
                wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F)

                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.set_performance_profile()
                wifi_dut.interfaces.wifi.enable_bt_power_save()

                ble_client_address = sl_collections.check_ble_advertise_functionality(
                    wifi_dut=wifi_dut, ble_client=ble_client, ble_dut_address=bt_dut_address,
                    timeout=20)

                logger().info("*********************** connect to ble dut ***********************")
                ble_client.interfaces.bluetooth.connect(bt_dut_address)
                time.sleep(30)

                logger().info("******************** get connection state")
                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "********************* device is in disconnection state"

                servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                assert len(servs) > 0, "no services fetched"
                assert len(chars) > 0, "fetched characters are empty"

                char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                    services=servs,
                    service_uid=service_uid,
                    char_uid=char_uid)
                assert char_path, "characters are empty"
                assert len(char_props) > 0, "length of characters is 0"

                ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

                logger().info(f' *********************** subscribe to notifications ***********************')
                ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                        char_uid=char_uid)

                wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                                    buffer_mode=1, buffer_count=2)

                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=230))
                sw = Stopwatch()
                while sw.elapsed_sec < 1800:
                    wifi_dut.interfaces.wifi.ble_notify_custom_value(data=data)
                    time.sleep(7)

                logger().info(f' *********************** unsubscribe to notifications ***********************')
                ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
                time.sleep(1)

                logger().info("******************** Validate Data ********************")
                notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
                logger().info(f' *********************** Notification is {notifications} ***********************')
                assert len(notifications) > 0, "received data is empty"
                assert notifications[0] == data, "failed to fetch data"

                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service()

                logger().info("*********************** Disconnecting from DUT ***********************")
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                ble_client.interfaces.bluetooth.close()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_master_data_length_20_bytes_C148513(ble_dut, ble_client, sl_collections, wifi_dut, utf_constants):

    """Connect BLE as Master mode and Run 20 bytes of RX data for 30 minutes"""

    bt_mon_log_file_name = (f"reports/test_ble_master_rx_230_bytes_C19921"
                            f"{int(time.time())}.log")

    svc = 'HealthThermometerService'
    charc = 'CustomNotifyCharacteristic'
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file_name):

            iter_count = utf_constants.get("iter_count")
            for count in range(iter_count):

                logger().info("******************** initializing ble in dut ********************")
                bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
                assert bt_dut_address, "failed to initialize ble in dut"

                logger().info("******************** initializing ble in remote device ********************")
                bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                                  service_classes=[svc])
                assert bt_client_address, "failed to initialize ble in remote device"

                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.set_performance_profile()
                wifi_dut.interfaces.wifi.enable_bt_power_save()

                logger().info("******************** start scanning in dut ********************")
                ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=100)
                ble_dut.interfaces.bluetooth.ble_stop_scanning()

                timeout = 30
                logger().info(f"Initiating connection this can take upto {timeout} seconds....")
                ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                                         expected="RSI_BLE_SECURITY_KEYS_EVENT")

                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

                logger().info(f"******************** get all profiles ********************")
                uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
                assert HealthThermometerService.UUID.lower() in uuids is not None, "Could not fetch health thermometer profile"

                logger().info(" ******************** Resolving Profile ********************")
                start_handle, end_handle, data = wifi_dut.interfaces.wifi.ble_get_profile_async(
                    ble_remote_dev_address=bt_client_address, uuid=int(HealthThermometerService.UUID, 16))
                assert start_handle is not None, "failed to fetch the start handle.."
                assert end_handle is not None, "failed to fetch end handle.."

                char_uuids, write_handles, char_properties = ble_dut.interfaces.wifi.ble_get_char_services_async(
                    ble_remote_dev_address=bt_client_address,
                    start_handle=int(start_handle, 16),
                    end_handle=int(end_handle, 16),
                    async_timeout=60)
                logger().info(
                    f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
                    f"{char_properties}")

                assert CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID in char_uuids, "Unable to find {} uuid".format(
                    CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID)
                index = char_uuids.index(CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID)
                logger().info(f"UUID's are:{char_uuids}")
                logger().info(f"write_handles:{write_handles}")
                logger().info(f"index:{index}")
                assert char_properties[index].isdigit(), "Character property found is not an integer"
                assert CustomNotifyCharacteristic.prop_int == int(
                    char_properties[index]), "Invalid character property found"

                write_handle = int(write_handles[index], 16)
                logger().info(f"write_handle:{write_handle}")
                assert write_handle > 0, "Unable to get write handle for configured service"

                ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=bt_client_address,
                                                               handle=(write_handle + 1), enable_notify=1)
                time.sleep(1)

                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
                sw = Stopwatch()

                while sw.elapsed_sec < 1800:
                    since_time = time.perf_counter_ns()
                    ble_client.interfaces.bluetooth.send_gatt_charc_notification(svc, charc, data)
                    time.sleep(0.5)
                    found = False
                    tw = Stopwatch()
                    while tw.elapsed_sec < 10:
                        events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
                        for event in events:
                            if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                                logger().info(f"************** BLE EVENT DATA IS : {event.event_data} **************")
                                received_data = re.findall(r"(\b[A-Z0-9]{20}\b)", event.event_data)
                                logger().info(f"******* Received Data on DUT : {received_data} ********")
                                assert received_data == [data], "data mismatched"
                                if data in event.event_data:
                                    found = True
                                    break
                        assert found, "No data received on DUT"
                        if found:
                            break

                time.sleep(1)

                ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=bt_client_address,
                                                               handle=(write_handle + 1), enable_notify=0)
                ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

                ble_client.interfaces.bluetooth.close()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_master_data_length_230_bytes_C148514(wifi_dut, ble_client, sl_collections, utf_constants):
    """Connect BLE as Master mode and Run 230 bytes of TX data for 30 minutes"""
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path="./reports/test_ble_master_data_length_230_bytes_C148514.log"):
            iter_count = utf_constants.get("iter_count")
            for count in range(iter_count):
                service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
                char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

                logger().info("*********************** Start BLE in DUT ***********************")
                bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
                assert bt_dut_address, "failed to initialize ble in dut"
                wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F)

                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.set_performance_profile()
                wifi_dut.interfaces.wifi.enable_bt_power_save()

                ble_client_address = sl_collections.ble_connection(
                    wifi_dut=wifi_dut, ble_client=ble_client, ble_dut_address=bt_dut_address, mode="master", timeout=20)

                time.sleep(30)
                logger().info("******************** get connection state")
                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "********************* device is in disconnection state"

                servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                assert len(servs) > 0, "no services fetched"
                assert len(chars) > 0, "fetched characters are empty"

                char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                    services=servs,
                    service_uid=service_uid,
                    char_uid=char_uid)
                assert char_path, "characters are empty"
                assert len(char_props) > 0, "length of characters is 0"

                ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

                logger().info(f' *********************** subscribe to notifications ***********************')
                ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                        char_uid=char_uid)

                wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                                    buffer_mode=1, buffer_count=2)

                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=230))
                sw = Stopwatch()
                while sw.elapsed_sec < 1800:
                    wifi_dut.interfaces.wifi.ble_notify_custom_value(data=data)
                    time.sleep(7)

                logger().info(f' *********************** unsubscribe to notifications ***********************')
                ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
                time.sleep(1)

                logger().info("******************** Validate Data ********************")
                notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
                logger().info(f' *********************** Notification is {notifications} ***********************')
                assert len(notifications) > 0, "received data is empty"
                assert notifications[0] == data, "failed to fetch data"

                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service()

                logger().info("*********************** Disconnecting from DUT ***********************")
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                ble_client.interfaces.bluetooth.close()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
