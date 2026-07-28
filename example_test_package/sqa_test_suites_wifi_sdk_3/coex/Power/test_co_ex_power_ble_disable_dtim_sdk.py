"""
Verify WLAN DTIM-10 current restoration after disabling BLE
in WLAN(DTIM-10) + BLE Connected 200ms Coex app.

Flow (from test_co_ex_perf_with_ble_disable_sdk.py + power helpers from
test_co_ex_power_mcu_advanced_sdk.py):
  1. Coex: BLE connect @ 200ms + WLAN join DTIM-10 + powersave + M4 + power capture
  2. Disconnect BLE, ble_disable()
  3. Standalone: rejoin WLAN DTIM-10 + powersave + M4 + power capture
  4. Report both coex and standalone current numbers

Author: Benazeer K
"""

import os
import time

import pytest

from utf import TransformFileProperties
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utf_config import UtfConfig
from utf.utils import print_dict
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xBLECustomFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xCoexMode,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xJoinFeatureBitMap,
    Si91xOperatingMode,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xTCPIPFeatureBitMap,
)


def logger():
    return get_logger(__name__)


def _print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)


class device_scan_result:
    def check_for_devices_in_scanned_results(self, ble_client, bt_dut_address, adv_data):
        sw = Stopwatch()
        previously_found_devices = {}
        while sw.elapsed_sec < 30:
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            if previously_found_devices != found_devices:
                logger().info(f"BLE scan results :{found_devices}")
                previously_found_devices = found_devices

            if bt_dut_address in found_devices and found_devices[bt_dut_address] == adv_data:
                return True
        return False


class Power_Device:
    def __init__(self) -> None:
        pass

    def power_measurement(power_device=None, power_meter=None, dtim=None, capture_time=60):
        if power_device == "keysight_benchvue_power_analyzer_win_wcf":
            power_obj = power_number_output(power_meter=power_meter, dtim=dtim, capture_time=capture_time)
        elif power_device == "nrf_ppk2_device":
            power_obj = ppk_power_number_output(power_meter=power_meter)
        else:
            power_obj = power_number_output(power_meter=power_meter, dtim=dtim, capture_time=capture_time)
        power_obj.get_power_value()


class power_number_output:
    def __init__(self, power_meter=None, dtim=None, capture_time=60):
        self.power_meter = power_meter
        self.dtim = dtim
        self.capture_time = capture_time

    def _print(self, throughput: dict):
        _print_throughput(throughput)

    def get_power_value(self):
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")
        if self.dtim:
            self.power_meter.interfaces.power_meter.init_power_meter(
                data_log_file_name=f"UTF1_Data_Log_{self.dtim}",
                data_log_stop_after_elapsed_time=self.capture_time,
            )
        else:
            self.power_meter.interfaces.power_meter.init_power_meter(
                data_log_file_name="UTF1_Data_Log",
                data_log_stop_after_elapsed_time=self.capture_time,
            )
        self.power_meter.interfaces.power_meter.init_power_meter_module("data_logger")
        if dut == "si917_ncp_sl_wifi":
            self.power_meter.interfaces.power_meter.set_output_channels_settings(
                [
                    {
                        "channel": "1",
                        "emulation_mode": "Current Measure",
                        "trace_current": True,
                        "trace_voltage": False,
                        "trace_power": False,
                    }
                ]
            )
        else:
            self.power_meter.interfaces.power_meter.set_output_channels_settings(
                [
                    {
                        "channel": "1",
                        "emulation_mode": "2 Quadrant Power Supply",
                        "voltage": "3.3000",
                        "current_limit": "1.00000",
                        "voltage_slew": "MAX",
                        "voltage_meter_range": "Auto",
                        "current_meter_range": "Auto",
                        "trace_current": True,
                        "trace_power": True,
                    }
                ]
            )
        time.sleep(10)
        self.power_meter.interfaces.power_meter.start_capture()
        parsed_result = self.power_meter.interfaces.power_meter.power_meter_module.process_output(
            self.power_meter.interfaces.power_meter.results
        )
        self._print(parsed_result)
        assert parsed_result["Output"] is not None


class ppk_power_number_output:
    def __init__(self, power_meter=None):
        self.power_meter = power_meter

    def _print(self, throughput: dict):
        _print_throughput(throughput)

    def get_power_value(self):
        self.power_meter.interfaces.power_meter.start_capture()
        file_size = os.path.getsize(self.power_meter.interfaces.power_meter.capture_file)
        assert file_size > 0
        parsed_result = self.power_meter.interfaces.power_meter.process_output()
        self._print(parsed_result)
        assert parsed_result["Output"] is not None
        time.sleep(10)


class WlanThread(ThreadBase):
    """Coex-phase WLAN join (same as test_co_ex_power_mcu_advanced_sdk)."""

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, dtim=10, enable_bt_ps=True):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.dtim = dtim
        self.enable_bt_ps = enable_bt_ps
        self.device_ip = None

    def run(self):
        logger().info(f"Configuring Access Point with dtim : {self.dtim}")
        self.wifi_access_point.interfaces.wifi.start_ap(dtim=self.dtim)

        logger().info("Scanning and Connecting to Access Point")
        dictionary = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
            power_save=False,
            retry_count=3,
        )
        self.device_ip = dictionary["device_ip"]
        time.sleep(2)

        if self.enable_bt_ps:
            logger().info("Enabling BT power save (coex phase)")
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave,
            )
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")

    def getter(self):
        return self.device_ip


class M4_Sleep_Thread(ThreadBase):
    def __init__(self, wifi_dut=None, m4_sleep_time=100000, deep_sleep_without_ret=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.m4_sleep_time = m4_sleep_time
        self.deep_sleep_without_ret = deep_sleep_without_ret

    def run(self):
        logger().info("Enabling M4 power save")
        if self.deep_sleep_without_ret:
            self.wifi_dut.interfaces.wifi.m4_power_manager_deep_sleep(state=0, sleep_time=self.m4_sleep_time)
        else:
            self.wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=self.m4_sleep_time, timeout=150)
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.leave()
        logger().info("DUT is leaving the AP")


class Power_Measurement_Thread(ThreadBase, Power_Device):
    def __init__(self, power_meter=None, capture_time=60):
        super().__init__()
        Power_Device().__init__()
        self.power_meter = power_meter
        self.capture_time = capture_time

    def run(self):
        logger().info("Starting Power Capture")
        power_device = UtfConfig.instance().defaults.get("power_meter", {})
        Power_Device.power_measurement(
            power_device=power_device,
            power_meter=self.power_meter,
            capture_time=self.capture_time,
        )


class Dtim10BleDisableCurrentRestore(ThreadBase):
    """
    Phase-1 coex (WLAN DTIM-10 + BLE connected 200ms) + M4 + power,
    then ble_disable, then Phase-2 standalone WLAN DTIM-10 + M4 + power.
    """

    def __init__(
        self,
        dtim=10,
        wifi_dut=None,
        wifi_access_point=None,
        sl_collections=None,
        power_meter=None,
        ble_client=None,
        capture_time=60,
        m4_sleep_time=120000,
        bcast_filter=True,
        dtim_aligned_type=1,
    ):
        super().__init__()
        self.dtim = dtim
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.power_meter = power_meter
        self.ble_client = ble_client
        self.capture_time = capture_time
        self.m4_sleep_time = m4_sleep_time
        self.bcast_filter = bcast_filter
        self.dtim_aligned_type = dtim_aligned_type
        self.coex_power_result = None
        self.standalone_power_result = None

    def _ble_connect_200ms(self):
        """WLAN+BLE coex connected interval 200ms (0xa0), from coex power advanced."""
        with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_disable_dtim_restore_{int(time.time())}.log",
        ) as bt_logs:
            conn_params = {
                "min_conn_interval": 0xA0,
                "max_conn_interval": 0xA0,
                "conn_latency": 0,
                "supervision_timeout": 3200,
            }
            logger().info("***** PHASE-1: Initializing BLE (200ms connection) *****")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start(
                capability=3, bond_info=0, set_smp=1, timeout=10
            )
            self.wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name="Silabsautomation")
            self.wifi_dut.interfaces.wifi.bt_get_local_name()
            self.wifi_dut.interfaces.wifi.ble_start_advertising(
                ble_adv_type=128,
                ble_adv_int_min=2048,
                ble_adv_int_max=2048,
                ble_adv_channel_map=7,
            )

            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None, "Unable to fetch BD address from remote BLE device"

            scan_result = device_scan_result()
            device_found = scan_result.check_for_devices_in_scanned_results(
                ble_client=self.ble_client,
                bt_dut_address=bt_dut_address,
                adv_data=self.wifi_dut.interfaces.wifi.ble_advertising_data,
            )
            assert device_found, "DUT not found in scan results"
            self.ble_client.interfaces.bluetooth.stop_scanning()
            time.sleep(5)

            logger().info("Initiating BLE connection from remote device @ 200ms")
            self.ble_client.interfaces.bluetooth.connect(
                dev_addr=bt_dut_address,
                min_conn_interval=conn_params["min_conn_interval"],
                max_conn_interval=conn_params["max_conn_interval"],
                conn_latency=conn_params["conn_latency"],
                supervision_timeout=conn_params["supervision_timeout"],
            )
            time.sleep(60)

            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

            ble_conn_config = bt_logs.read_ble_connection_params(conn_params)
            logger().info(f"**********{ble_conn_config} values in btmon logs")
            assert ble_conn_config["Status"] == "Success"
            assert ble_conn_config["max_conn_interval"] == conn_params["max_conn_interval"]
            logger().info("found connection intervals of 200ms in btmon logs")
            time.sleep(2)
            return bt_dut_address

    def _apply_powersave(self, phase_name):
        if self.bcast_filter:
            logger().info(f"Setting filter broadcast command ({phase_name})")
            self.wifi_dut.interfaces.wifi.set_filter_broadcast()
        time.sleep(2)
        logger().info(f"Enabling TA power save ({phase_name})")
        self.wifi_dut.interfaces.wifi.set_performance_profile(
            mode="power_save", dtim_aligned_type=self.dtim_aligned_type
        )
        time.sleep(2)

    def _run_m4_and_power(self, dut, phase_name):
        """Run M4 sleep + power capture (same pattern as coex power advanced)."""
        logger().info(f"***** {phase_name}: starting M4 sleep + power capture *****")
        m4_obj = None
        if dut != "si917_ncp_sl_wifi":
            m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut, m4_sleep_time=self.m4_sleep_time)

        pm_obj = Power_Measurement_Thread(power_meter=self.power_meter, capture_time=self.capture_time)

        if m4_obj is not None:
            m4_obj.start()
            time.sleep(2)

        pm_obj.start()
        pm_obj.wait_for_exit()

        if m4_obj is not None:
            m4_obj.wait_for_exit()
        else:
            self.wifi_dut.interfaces.wifi.leave()
            logger().info(f"DUT leaving AP after {phase_name} power capture (NCP)")

        parsed_result = self.power_meter.interfaces.power_meter.power_meter_module.process_output(
            self.power_meter.interfaces.power_meter.results
        )
        _print_throughput(parsed_result)
        assert parsed_result["Output"] is not None, f"{phase_name} power Output is None"
        time.sleep(10)
        logger().info(f"***** {phase_name}: M4 + power capture completed *****")
        return parsed_result

    def run(self):
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")

        if dut != "si917_ncp_sl_wifi":
            logger().info("M4-TA secure handshake")
            self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
        time.sleep(2)

        self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface="client",
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default,
        )

        # ---------------- PHASE-1: Coex WLAN DTIM-10 + BLE connected 200ms + M4 + power ----------------
        try:
            bt_dut_address = self._ble_connect_200ms()
        except Exception as error:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=error)
            raise

        wlan_coex = WlanThread(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            sl_collections=self.sl_collections,
            dtim=self.dtim,
            enable_bt_ps=True,
        )
        wlan_coex.start()
        wlan_coex.wait_for_exit()
        time.sleep(2)

        self._apply_powersave("coex")
        logger().info("***** Coex settled (WLAN DTIM-10 + BLE 200ms connected) *****")
        self.coex_power_result = self._run_m4_and_power(dut, "COEX")

        # ---------------- Tear down coex, then ble_disable ----------------
        logger().info("Initiating BLE disconnection from remote device")
        self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(5)

        # M4_Sleep_Thread / NCP path already left WLAN during coex power capture
        logger().info("***** Calling ble_disable() *****")
        self.wifi_dut.interfaces.wifi.ble_disable()
        time.sleep(5)

        # ---------------- PHASE-2: Standalone WLAN DTIM-10 + M4 + power after ble_disable ----------------
        logger().info("***** PHASE-2: Standalone WLAN DTIM-10 after ble_disable *****")
        wlan_standalone = WlanThread(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            sl_collections=self.sl_collections,
            dtim=self.dtim,
            enable_bt_ps=False,
        )
        wlan_standalone.start()
        wlan_standalone.wait_for_exit()
        time.sleep(2)

        self._apply_powersave("standalone")
        self.standalone_power_result = self._run_m4_and_power(dut, "STANDALONE")
        logger().info("***** Coex + Standalone power captures completed *****")


pytestmark = [pytest.mark.firmware_app("test_352K_M4SS_320K")]


def _coex_wifi_config():
    return {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.WPSSupportDisabled
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.DNSClient
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
        | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints
        | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE
        | Si91xExtCustomFeatureBitMap.FeatureLowPower,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "enable_ble_power_index_params": 1,
        "power_index": 63,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
    }


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config("wifi_dut", wifi=_coex_wifi_config())
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wlan_dtim10_current_restore_after_ble_disable_C1888611(
    firmware_loader,
    power_meter,
    wifi_access_point,
    wifi_dut,
    sl_collections,
    dtim,
    ble_client,
    request,
    performance_data,
    custom_performance_fixture,
):
    """
    Verify WLAN DTIM-10 current restoration after disabling BLE in
    WLAN(DTIM-10) + BLE Connected 200ms Coex app.
    """
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = (
        obtained_test_name.split("[")[0]
        if obtained_test_name and "[" in obtained_test_name
        else obtained_test_name
    )
    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})

    try:
        stdby_obj = Dtim10BleDisableCurrentRestore(
            dtim=dtim,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            power_meter=power_meter,
            ble_client=ble_client,
        )
        stdby_obj.start()
        stdby_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise

    assert stdby_obj.coex_power_result is not None, "Coex power result missing"
    assert stdby_obj.standalone_power_result is not None, "Standalone power result missing"

    for phase_suffix, parsed_result in (
        ("_coex_ble_200ms", stdby_obj.coex_power_result),
        ("_standalone_after_ble_disable", stdby_obj.standalone_power_result),
    ):
        _print_throughput(parsed_result)
        assert parsed_result["Output"] is not None
        performance_data.interfaces.power_perf_data.generate_csv(
            test_name=f"{test_name}{phase_suffix}",
            opn=opn,
            build_number=build_number,
            memory_configuration="test_352K_M4SS_320K",
            parsed_result=parsed_result["Output"],
            file_path=performance_file_root_dir,
            file_name=perf_file_name,
        )
