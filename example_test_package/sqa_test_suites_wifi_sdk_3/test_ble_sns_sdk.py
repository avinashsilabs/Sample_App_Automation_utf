import re
import pytest
import time
import datetime
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap,\
    Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xBTFeatureBitMap,\
    Si91xCustomFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer


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

    Author: Ayush Agarwal
"""

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
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0  | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    },
)
  ]


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
        try:
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
                    time.sleep(240)
                    # self.wifi_dut.interfaces.wifi.ble_stop_scanning()

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

        except Exception as Ex:
            logger().info(f"*** Got Exception in Test Case Thread = {Ex}***")


def test_wifi_sdk_ble_start_and_stop_scan_30_minutes_c148512(sl_collections, wifi_dut, ble_client):

    test_case = '148512'
    ble_obj = BLEMasterSNS(wifi_dut=wifi_dut, sl_collections=sl_collections, test_case=test_case, ble_client=ble_client)

    ble_obj.start()
    ble_obj.wait_for_exit()


@pytest.mark.end_state("wifi_dut", wifi=['ble_stop_scan', "wifi_powersave_disable"])
def test_wifi_sdk_ble_scan_30_minutes_c148511(sl_collections, wifi_dut, ble_client):
    test_case = '148511'
    ble_obj = BLEMasterSNS(wifi_dut=wifi_dut, sl_collections=sl_collections, test_case=test_case, ble_client=ble_client)

    ble_obj.start()
    ble_obj.wait_for_exit()


def test_wifi_sdk_ble_connect_disconnect_30_minutes_c148509(sl_collections, wifi_dut, ble_client):
    test_case = '148509'
    ble_obj = BLEMasterSNS(wifi_dut=wifi_dut, sl_collections=sl_collections, test_case=test_case, ble_client=ble_client)

    ble_obj.start()
    ble_obj.wait_for_exit()

