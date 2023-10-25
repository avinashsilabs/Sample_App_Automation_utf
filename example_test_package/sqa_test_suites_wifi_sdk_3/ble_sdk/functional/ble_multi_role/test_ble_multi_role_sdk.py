import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
import time
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs


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
    def __init__(self, wifi_dut=None, ble_client=None, ble_adv=None, adv_int_min=None, adv_int_max=None,
                 ble_start=True, bt_dut_address=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_adv = ble_adv
        self.adv_int_min = adv_int_min
        self.adv_int_max = adv_int_max
        self.ble_start = ble_start
        self.bt_dut_address = bt_dut_address
        if self.ble_start:
            logger().info("start ble in dut")
            self.bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert self.bt_dut_address, "ble initialization failed in dut"

    def run(self):
        if self.ble_adv == "ble_adv_powersave":
            logger().info(" ======= start adv in dut")
            self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_int_min=int(self.adv_int_min/0.625),
                                                                ble_adv_int_max=int(self.adv_int_max/0.625))
            time.sleep(5)
            enable_wifi_ps = self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            assert enable_wifi_ps == 0, 'failed to enable wlan power save'
            enable_bt_ps = self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            assert enable_bt_ps == 0, 'failed to enable bt power save'
            time.sleep(5)
            logger().info(" ======= start ble scan in remote device")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.bt_dut_address)
            assert bt_client_address, "failed to initiate ble in remote device"
            time.sleep(5)
            logger().info("stop scanning ....")
            self.ble_client.interfaces.bluetooth.stop_scanning()
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            logger().info(f"Check the dut is listed...{found_devices}")
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
            self.ble_client.interfaces.bluetooth.close()



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
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
  ]
@pytest.mark.end_state("wifi_dut",
                       wifi=["ble_stop_adv", "ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_dual_role_SI160ms_SW50ms_AImin160ms_AImax320ms_c19911(wifi_dut, ble_client, sl_collections):
    """1.verify ble slave connection with Advertising minimum interval 160ms and Advertising maximum interval 320ms
       2.verify ble master connection with scan interval 160ms and scan window 50ms"""
    try:
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, ble_adv="ble_adv_powersave",
                                   adv_int_min=160, adv_int_max=320, ble_start=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        sl_collections.check_ble_scan_functionality(wifi_dut=wifi_dut, ble_client=ble_client,
                                                    ble_address=ble_obj.bt_dut_address, timeout=120)
        time.sleep(2)
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        time.sleep(5)
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_advertising()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

@pytest.mark.end_state("wifi_dut",
                       wifi=["ble_stop_adv", "ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_dual_role_SI500ms_SW400ms_AImin200ms_AImax200ms_c19912(wifi_dut, ble_client, sl_collections):
    """1.verify ble slave connection with Advertising minimum interval 200ms and Advertising maximum interval 200ms
          2.verify ble master connection with scan interval 500ms and scan window 400ms"""
    try:
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, ble_adv="ble_adv_powersave",
                                   adv_int_min=200, adv_int_max=200, ble_start=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        sl_collections.check_ble_scan_functionality(wifi_dut=wifi_dut, ble_client=ble_client,
                                                    ble_address=ble_obj.bt_dut_address,
                                                    ble_scan_interval=int(500 / 0.625),
                                                    ble_scan_window=int(400 / 0.625),
                                                    timeout=120)

        time.sleep(2)
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        time.sleep(5)
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_advertising()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut",
                       wifi=["ble_stop_adv", "ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_dual_role_SI1000ms_SW500ms_AImin500ms_AImax500ms_c19913(wifi_dut, ble_client, sl_collections):
    """1.verify ble slave connection with Advertising minimum interval 500ms and Advertising maximum interval 500ms
          2.verify ble master connection with scan interval 1000ms and scan window 500ms"""
    try:
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, ble_adv="ble_adv_powersave",
                                   adv_int_min=500, adv_int_max=500, ble_start=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        sl_collections.check_ble_scan_functionality(wifi_dut=wifi_dut, ble_client=ble_client,
                                                    ble_address=ble_obj.bt_dut_address,
                                                    ble_scan_interval=int(1000 / 0.625),
                                                    ble_scan_window=int(500 / 0.625),
                                                    timeout=60)

        wifi_dut.interfaces.wifi.ble_stop_scanning()
        time.sleep(5)
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_advertising()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut",
                       wifi=["ble_stop_adv", "ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dual_role_SI5000ms_SW3000ms_AImin1000ms_AImax1000ms_c19914(wifi_dut, ble_client, sl_collections):
    """1.verify ble slave connection with Advertising minimum interval 1000ms and Advertising maximum interval 1000ms
          2.verify ble master connection with scan interval 5000ms and scan window 3000ms"""
    try:
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, ble_adv="ble_adv_powersave",
                                   adv_int_min=1000, adv_int_max=1000, ble_start=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        sl_collections.check_ble_scan_functionality(wifi_dut=wifi_dut, ble_client=ble_client,
                                                    ble_address=ble_obj.bt_dut_address,
                                                    ble_scan_interval=int(5000 / 0.625),
                                                    ble_scan_window=int(3000 / 0.625),
                                                    timeout=60)

        wifi_dut.interfaces.wifi.ble_stop_scanning()
        time.sleep(5)
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_advertising()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.end_state("wifi_dut",
                       wifi=["ble_stop_adv", "ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_dual_role_SI10240ms_SW5s_AImin10240ms_AImax10240ms_c19915(wifi_dut, ble_client, sl_collections):
    """1.verify ble slave connection with Advertising minimum interval 10240ms and Advertising maximum interval 10240ms
          2.verify ble master connection with scan interval 240ms and scan window 5000ms"""
    try:
        ble_obj = BleFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, ble_adv="ble_adv_powersave",
                                   adv_int_min=10240, adv_int_max=10240, ble_start=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        sl_collections.check_ble_scan_functionality(wifi_dut=wifi_dut, ble_client=ble_client,
                                                    ble_address=ble_obj.bt_dut_address,
                                                    ble_scan_interval=int(10240 / 0.625),
                                                    ble_scan_window=int(5000 / 0.625),
                                                    timeout=60)
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        time.sleep(5)
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_advertising()
        time.sleep(5)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)