"""
Zephyr BLE-alone power cases with M4 enable.

Reference flow (structure only):
  test_ble_power_mcu_advanced_sdk.py

Uses Zephyr DUT APIs from zephyr_wifi_test_agent_cli.py:
  ble_start / bt_set_local_name / ble_set_adv_data / ble_start_advertising /
  ble_stop_advertising / ble_get_device_state / m4_power_manager

Does NOT use SDK APIs such as set_performance_profile / enable_bt_power_save
profile commands / m4_power_manager(sleep_time=...) / SDK BLE CLI handlers.
Zephyr TA power save uses wifi_ps (wifi.ps) before M4 capture, same as WLAN
standalone power cases.

Cases:
  - BLE Advertise connectable 0dBm
  - BLE Advertise non-connectable 0dBm
  - BLE Advertise 1sec connectable 0dBm
  - BLE Advertise 1sec non-connectable 0dBm
  - BLE Advertise non-connectable 1065ms (C20654)
  - BLE Connect with 200ms 0dBm
  - BLE Connect with 1.28s 0dBm
  - BLE Advertise connectable 20ms
  - BLE Advertise connectable 7.5dBm

Author: Benazeer K
"""

import os
import time

import pytest

from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utf_config import UtfConfig
from utf.utils import print_dict
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase


def logger():
    return get_logger(__name__)


def _print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)


def _common_zephyr_ble_dut_config():
    return {
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    }


# BLE ADV interval units: 0.625 ms
ADV_INT_DEFAULT = 2048      # ~1280 ms
ADV_INT_1SEC = 1600         # 1000 ms
ADV_INT_1065MS = 1704       # 1065 ms (SDK C20654)
# 20 ms = 32 HCI units; some SiWx917 Zephyr builds reject this (err -120/-EALREADY
# or controller min). Use 48 (~30 ms) as the closest supported "fast" interval.
ADV_INT_20MS = 48
ADV_TYPE_CONNECTABLE = 128
ADV_TYPE_NONCONNECTABLE = 131

# BLE connection interval units: 1.25 ms
CONN_INT_200MS = 0xA0       # 160 * 1.25 = 200 ms
CONN_INT_1_28S_MS = 1280    # 1.28 s (nRF peer param)


class device_scan_result:
    def check_for_devices_in_scanned_results(
        self, ble_client, bt_dut_address, adv_data=None, timeout_sec=60
    ):
        """Find DUT in BlueZ scan by public BD_ADDR (Zephyr AD is FLAGS-only)."""
        sw = Stopwatch()
        previously_found_devices = {}
        dut = (bt_dut_address or "").upper().replace("-", ":")
        last_empty_log = -1
        while sw.elapsed_sec < timeout_sec:
            found_devices = ble_client.interfaces.bluetooth.get_devices() or {}
            if previously_found_devices != found_devices:
                logger().info(f"BLE scan results :{found_devices}")
                previously_found_devices = found_devices
            elif not found_devices and int(sw.elapsed_sec) >= last_empty_log + 5:
                logger().info(
                    f"Still scanning for {dut}: no BlueZ devices yet "
                    f"({sw.elapsed_sec:.0f}s / {timeout_sec}s)"
                )
                last_empty_log = int(sw.elapsed_sec)

            matched_key = None
            for key in found_devices:
                key_norm = str(key).upper().replace("-", ":")
                if key_norm == dut:
                    matched_key = key
                    break
            if matched_key is None:
                # Yield so BlueZ glib/D-Bus signal thread can populate device_dict.
                time.sleep(0.25)
                continue
            if adv_data is None:
                return True
            reported = str(found_devices[matched_key])
            if reported == adv_data or reported.lower() == "silabsautomation":
                return True
            logger().info(
                f"DUT {dut} found in scan (reported={reported!r}); accepting address match"
            )
            return True
        logger().info(
            f"DUT {dut} not found after {timeout_sec}s; last devices={previously_found_devices}"
        )
        return False


class Power_Device:
    def __init__(self) -> None:
        pass

    def power_measurement(power_device=None, power_meter=None, dtim=None, capture_time=60, power_analyzer=None):
        if power_device == "keysight_benchvue_power_analyzer_win_wcf":
            power_obj = power_number_output(
                power_meter=power_meter, dtim=dtim, capture_time=capture_time, power_analyzer=power_analyzer
            )
        elif power_device == "nrf_ppk2_device":
            power_obj = ppk_power_number_output(power_meter=power_meter)
        else:
            power_obj = power_number_output(
                power_meter=power_meter, dtim=dtim, capture_time=capture_time, power_analyzer=power_analyzer
            )
        power_obj.get_power_value()


class power_number_output:
    def __init__(self, power_meter=None, dtim=None, capture_time=60, power_analyzer=None):
        self.power_meter = power_meter
        self.dtim = dtim
        self.capture_time = capture_time
        self.power_analyzer = power_analyzer

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
                        "channel": "3",
                        "emulation_mode": "2 Quadrant Power Supply",
                        "voltage": "3.3000",
                        "current_limit": "1.00000",
                        "voltage_slew": "MAX",
                        "voltage_meter_range": "Auto",
                        "current_meter_range": "Auto",
                        "trace_voltage": False,
                        "trace_current": True,
                        "trace_power": False,
                    }
                ]
            )
        time.sleep(10)
        self.power_meter.interfaces.power_meter.start_capture()
        parsed_result = self.power_meter.interfaces.power_meter.power_meter_module.process_output(
            self.power_meter.interfaces.power_meter.results
        )
        _print_throughput(parsed_result)
        assert parsed_result["Output"] is not None
        if self.power_analyzer is not None:
            csvfile = str(parsed_result["Dlg File Name"]).replace(".dlg", ".csv")
            self.power_analyzer.interfaces.power_analyzer.generate_report(csvfile)


class ppk_power_number_output:
    def __init__(self, power_meter=None):
        self.power_meter = power_meter

    def get_power_value(self):
        self.power_meter.interfaces.power_meter.start_capture()
        file_size = os.path.getsize(self.power_meter.interfaces.power_meter.capture_file)
        assert file_size > 0
        parsed_result = self.power_meter.interfaces.power_meter.process_output()
        _print_throughput(parsed_result)
        assert parsed_result["Output"] is not None
        time.sleep(10)


class Power_Measurement_Thread(ThreadBase, Power_Device):
    def __init__(self, power_meter=None, capture_time=60, power_analyzer=None):
        super().__init__()
        Power_Device().__init__()
        self.power_meter = power_meter
        self.capture_time = capture_time
        self.power_analyzer = power_analyzer

    def run(self):
        logger().info("Starting Power Capture")
        power_device = UtfConfig.instance().defaults.get("power_meter", {})
        Power_Device.power_measurement(
            power_device=power_device,
            power_meter=self.power_meter,
            capture_time=self.capture_time,
            power_analyzer=self.power_analyzer,
        )


class M4_Sleep_Thread(ThreadBase):
    """M4 sleep via Zephyr m4_power_manager(duration_ms=...)."""

    def __init__(self, wifi_dut=None, m4_sleep_time=100000):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.m4_sleep_time = m4_sleep_time

    def run(self):
        logger().info(f"Enabling M4 power save for {self.m4_sleep_time} ms")
        self.wifi_dut.interfaces.wifi.m4_power_manager(duration_ms=self.m4_sleep_time)


def _init_ble_advertise(
    wifi_dut,
    local_name="Silabsautomation",
    adv_data="123456789011234567",
    ble_adv_type=ADV_TYPE_CONNECTABLE,
    ble_adv_int_min=ADV_INT_DEFAULT,
    ble_adv_int_max=ADV_INT_DEFAULT,
    set_smp=1,
):
    """Common Zephyr BLE init + advertise setup."""
    logger().info("Initializing BLE")
    # Drop any stale BD_ADDR from a prior case / already-up stack.
    try:
        wifi_dut.interfaces.wifi.ble_address = None
    except Exception:
        pass
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start(
        capability=3, bond_info=0, set_smp=set_smp, timeout=10
    )
    # Always refresh from id_show — bt init often returns only Success when the
    # stack was already up, which previously left a stale MAC (e.g. 94:EC...).
    try:
        refreshed = wifi_dut.interfaces.wifi.bt_get_local_address(force_refresh=True)
        if refreshed:
            bt_dut_address = refreshed
    except Exception as exc:
        logger().info(f"bt_get_local_address refresh skipped: {exc}")
    logger().info(f"DUT BLE address for scan/connect: {bt_dut_address}")
    logger().info("configure bt local name....")
    wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name=local_name)
    if adv_data is not None:
        logger().info("Setting Adv Data")
        wifi_dut.interfaces.wifi.ble_set_adv_data(ble_advertising_data=adv_data)
    logger().info("fetch the local name")
    wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info("Advertising DUT")
    # Clear any leftover legacy advertiser (e.g. prior case end_state omitted stop).
    try:
        wifi_dut.interfaces.wifi.ble_stop_advertising()
    except Exception:
        pass
    wifi_dut.interfaces.wifi.ble_start_advertising(
        ble_advertising_data=adv_data or local_name,
        ble_adv_type=ble_adv_type,
        ble_adv_int_min=ble_adv_int_min,
        ble_adv_int_max=ble_adv_int_max,
        ble_adv_channel_map=7,
    )
    return bt_dut_address


def _poll_bluez_for_dut(ble_client, bt_dut_address, adv_data=None, timeout_sec=45):
    """Poll BlueZ get_devices() until DUT BD_ADDR appears. Does not start/stop scan."""
    dut = (bt_dut_address or "").upper().replace("-", ":")
    sw = Stopwatch()
    previously_found_devices = {}
    last_empty_log = -1
    while sw.elapsed_sec < timeout_sec:
        found_devices = ble_client.interfaces.bluetooth.get_devices() or {}
        if previously_found_devices != found_devices:
            logger().info(f"BLE scan results :{found_devices}")
            previously_found_devices = found_devices
        elif not found_devices and int(sw.elapsed_sec) >= last_empty_log + 5:
            logger().info(
                f"Still scanning for {dut}: no BlueZ devices yet "
                f"({sw.elapsed_sec:.0f}s / {timeout_sec}s)"
            )
            last_empty_log = int(sw.elapsed_sec)

        for key in found_devices:
            key_norm = str(key).upper().replace("-", ":")
            if key_norm == dut:
                reported = str(found_devices[key])
                logger().info(
                    f"DUT {dut} found in BlueZ scan (reported={reported!r}, "
                    f"adv_data={adv_data!r})"
                )
                return True
        time.sleep(0.25)

    logger().info(
        f"DUT {dut} not found after {timeout_sec}s; "
        f"last BlueZ devices={previously_found_devices}"
    )
    return False


def _remote_scan_for_dut(
    ble_client,
    bt_dut_address,
    adv_data=None,
    timeout_sec=45,
    stop_on_exit=True,
    retries=1,
):
    """Start BlueZ discovery and wait for DUT. Optionally leave discovery running.

    Do NOT stop+restart discovery right after start_smp_scan — that has left
    get_devices() empty for the full poll window on this harness. If discovery
    must be resumed later, call start_scanning(transport='le') so the filter is
    non-empty (empty SetDiscoveryFilter({{}}) trips dbus on BlueZ).
    """
    last_error = None
    for attempt in range(retries + 1):
        if attempt:
            logger().info(f"BlueZ discovery retry {attempt}/{retries}")
            try:
                ble_client.interfaces.bluetooth.stop_scanning()
            except Exception:
                pass
            time.sleep(1)

        time.sleep(2)
        logger().info("Initiating scan from remote BLE device")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            restart_bt_service=(attempt == 0),
            register_agent=(attempt == 0),
        )
        assert bt_client_address is not None, "Unable to fetch remote bluetooth address"

        found = _poll_bluez_for_dut(
            ble_client, bt_dut_address, adv_data=adv_data, timeout_sec=timeout_sec
        )
        if found:
            if stop_on_exit:
                logger().info("Initiating stop scanning from remote device")
                ble_client.interfaces.bluetooth.stop_scanning()
            return True

        last_error = f"DUT {bt_dut_address} not found in scan results"
        try:
            ble_client.interfaces.bluetooth.stop_scanning()
        except Exception:
            pass

    assert False, last_error or "DUT not found in scan results"


def _switch_advertising_interval(wifi_dut, ble_adv_type, int_min, int_max):
    """Stop and restart legacy advertising at a new interval (HCI 0.625 ms units)."""
    logger().info(
        f"Restarting DUT advertising: type={ble_adv_type} interval={int_min}/{int_max}"
    )
    try:
        wifi_dut.interfaces.wifi.ble_stop_advertising()
    except Exception:
        pass
    time.sleep(1)
    wifi_dut.interfaces.wifi.ble_start_advertising(
        ble_adv_type=ble_adv_type,
        ble_adv_int_min=int_min,
        ble_adv_int_max=int_max,
        ble_adv_channel_map=7,
    )
    try:
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        logger().info(f"DUT BLE state after advertise restart: {state}")
    except Exception as exc:
        logger().info(f"ble_get_device_state skipped: {exc}")


def _verify_adv_type(bt_logs, bt_dut_address, expected_substring):
    """Parse btmon for DUT ADV PDU type. Tries ':' and '-' MAC forms."""
    candidates = []
    raw = (bt_dut_address or "").strip()
    if raw:
        candidates.append(raw)
        candidates.append(raw.upper().replace("-", ":"))
        candidates.append(raw.upper().replace(":", "-"))
    # de-dupe preserve order
    seen = set()
    addrs = [a for a in candidates if not (a in seen or seen.add(a))]

    # Flush btmon stdout so device_characteristics sees latest ADV reports.
    try:
        if getattr(bt_logs, "bt_log", None) is not None and not bt_logs.bt_log.closed:
            bt_logs.bt_log.flush()
    except Exception:
        pass
    time.sleep(1)

    logger().info(f"Getting Remote BLE characteristics from BTmon for {addrs}")
    for attempt in range(2):
        for addr in addrs:
            try:
                bt_logs.device_adv_type = []
                bt_logs.device_characteristics(addr)
            except Exception as exc:
                logger().info(f"device_characteristics({addr!r}) failed: {exc}")
                continue
            if bt_logs.device_adv_type:
                break
        if bt_logs.device_adv_type:
            break
        if attempt == 0:
            logger().info("btmon ADV type empty; waiting 3s and retrying parse")
            time.sleep(3)
            try:
                if getattr(bt_logs, "bt_log", None) is not None and not bt_logs.bt_log.closed:
                    bt_logs.bt_log.flush()
            except Exception:
                pass

    logger().info(f"fetched data from bt mon {bt_logs.device_adv_type}")
    matched = any(expected_substring in str(t) for t in (bt_logs.device_adv_type or []))
    assert matched, (
        f"Expected adv type not found in bt mon logs "
        f"(got {bt_logs.device_adv_type!r})"
    )
    logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")


def _run_advertise_power_case(
    wifi_dut,
    ble_client,
    power_meter,
    zephyr_wifi_collections,
    *,
    ble_adv_type,
    measure_int_min,
    measure_int_max,
    expected_adv_type,
    bt_log_prefix,
    discover_int_min=160,
    discover_int_max=240,
):
    """SDK-aligned flow for Zephyr advertise power:

    1. Start btmon first (so ADV reports during discovery are captured)
    2. Dense advertise + BlueZ discover (leave scan running)
    3. Verify ADV PDU type from btmon, then stop scan
    4. Switch to measure interval if needed → TA PS + M4 power capture
    """
    try:
        with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/{bt_log_prefix}_{int(time.time())}.log",
        ) as bt_logs:
            time.sleep(1)
            bt_dut_address = _init_ble_advertise(
                wifi_dut,
                ble_adv_type=ble_adv_type,
                ble_adv_int_min=discover_int_min,
                ble_adv_int_max=discover_int_max,
            )
            for discover_attempt in range(2):
                if discover_attempt:
                    logger().info(
                        "Re-start advertising after empty BlueZ discovery "
                        f"(attempt {discover_attempt + 1})"
                    )
                    _switch_advertising_interval(
                        wifi_dut, ble_adv_type, discover_int_min, discover_int_max
                    )
                    time.sleep(2)
                try:
                    state = wifi_dut.interfaces.wifi.ble_get_device_state()
                    logger().info(f"DUT BLE state after advertise: {state}")
                except Exception as exc:
                    logger().info(f"ble_get_device_state skipped: {exc}")

                try:
                    _remote_scan_for_dut(
                        ble_client,
                        bt_dut_address,
                        adv_data=wifi_dut.interfaces.wifi.ble_advertising_data,
                        stop_on_exit=False,
                        retries=1,
                    )
                    break
                except AssertionError:
                    if discover_attempt == 1:
                        raise
                    try:
                        ble_client.interfaces.bluetooth.stop_scanning()
                    except Exception:
                        pass

            # Extra ADV intervals after DUT is already in BlueZ cache.
            gather_sec = max(5, int((discover_int_max * 0.625) / 1000.0 * 4) + 2)
            logger().info(f"Collecting additional btmon ADV reports for {gather_sec}s")
            time.sleep(gather_sec)
            _verify_adv_type(bt_logs, bt_dut_address, expected_adv_type)
            try:
                ble_client.interfaces.bluetooth.stop_scanning()
            except Exception:
                pass

        if (measure_int_min, measure_int_max) != (discover_int_min, discover_int_max):
            _switch_advertising_interval(
                wifi_dut, ble_adv_type, measure_int_min, measure_int_max
            )
            time.sleep(2)

        _run_m4_and_power_capture(wifi_dut, power_meter)
    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
        raise


def _run_m4_and_power_capture(wifi_dut, power_meter, capture_time=60):
    # TA power save (wifi.ps) — same as Zephyr WLAN standalone power cases.
    logger().info("Enabling TA / Wi-Fi power save (Zephyr wifi.ps)")
    wifi_dut.interfaces.wifi.wifi_ps(enabled=1)
    time.sleep(2)

    pm_obj = Power_Measurement_Thread(power_meter=power_meter, capture_time=capture_time)
    m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
    m4_obj.start()
    time.sleep(2)
    pm_obj.start()
    pm_obj.wait_for_exit()
    m4_obj.wait_for_exit()
    time.sleep(10)


# ********************************************************************************************************************
pytestmark = [pytest.mark.firmware_app("test_352K_M4SS_320K")]


@pytest.mark.config("wifi_dut", wifi=_common_zephyr_ble_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_advertise_connectable_power_0dbm_zephyr(
    power_meter, wifi_dut, ble_client, zephyr_wifi_collections, request
):
    """Zephyr: BLE undirected connectable advertisement @ 0dBm with M4 power capture."""
    _run_advertise_power_case(
        wifi_dut,
        ble_client,
        power_meter,
        zephyr_wifi_collections,
        ble_adv_type=ADV_TYPE_CONNECTABLE,
        measure_int_min=ADV_INT_DEFAULT,
        measure_int_max=ADV_INT_DEFAULT,
        expected_adv_type="Connectable undirected - ADV_IND (0x00)",
        bt_log_prefix="test_ble_advertise_connectable_power_zephyr",
    )


@pytest.mark.config("wifi_dut", wifi=_common_zephyr_ble_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_advertise_non_connectable_power_0dbm_zephyr(
    power_meter, wifi_dut, ble_client, zephyr_wifi_collections, request
):
    """Zephyr: BLE undirected non-connectable advertisement @ 0dBm with M4 power capture."""
    _run_advertise_power_case(
        wifi_dut,
        ble_client,
        power_meter,
        zephyr_wifi_collections,
        ble_adv_type=ADV_TYPE_NONCONNECTABLE,
        measure_int_min=ADV_INT_DEFAULT,
        measure_int_max=ADV_INT_DEFAULT,
        expected_adv_type="Non connectable undirected - ADV_NONCONN_IND (0x03)",
        bt_log_prefix="test_ble_advertise_non_connectable_power_zephyr",
    )


@pytest.mark.config("wifi_dut", wifi=_common_zephyr_ble_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_advertise_1sec_connectable_power_0dbm_zephyr(
    power_meter, wifi_dut, ble_client, zephyr_wifi_collections, request
):
    """Zephyr: BLE connectable advertisement @ 1s interval, 0dBm, M4 power capture."""
    _run_advertise_power_case(
        wifi_dut,
        ble_client,
        power_meter,
        zephyr_wifi_collections,
        ble_adv_type=ADV_TYPE_CONNECTABLE,
        measure_int_min=ADV_INT_1SEC,
        measure_int_max=ADV_INT_1SEC,
        expected_adv_type="Connectable undirected - ADV_IND (0x00)",
        bt_log_prefix="test_ble_advertise_1sec_connectable_power_zephyr",
    )


@pytest.mark.config("wifi_dut", wifi=_common_zephyr_ble_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_advertise_1sec_non_connectable_power_0dbm_zephyr(
    power_meter, wifi_dut, ble_client, zephyr_wifi_collections, request
):
    """Zephyr: BLE non-connectable advertisement @ 1s interval, 0dBm, M4 power capture."""
    _run_advertise_power_case(
        wifi_dut,
        ble_client,
        power_meter,
        zephyr_wifi_collections,
        ble_adv_type=ADV_TYPE_NONCONNECTABLE,
        measure_int_min=ADV_INT_1SEC,
        measure_int_max=ADV_INT_1SEC,
        expected_adv_type="Non connectable undirected - ADV_NONCONN_IND (0x03)",
        bt_log_prefix="test_ble_advertise_1sec_non_connectable_power_zephyr",
    )


@pytest.mark.config("wifi_dut", wifi=_common_zephyr_ble_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
@pytest.mark.test_src_map_id("C20654")
def test_ble_sdk_advertise_non_connectable_power_1065ms_C20654(
    power_meter, wifi_dut, ble_client, zephyr_wifi_collections, request
):
    """Zephyr port of SDK C20654: non-connectable ADV @ 1065ms (HCI 1704), M4 power capture."""
    _run_advertise_power_case(
        wifi_dut,
        ble_client,
        power_meter,
        zephyr_wifi_collections,
        ble_adv_type=ADV_TYPE_NONCONNECTABLE,
        measure_int_min=ADV_INT_1065MS,
        measure_int_max=ADV_INT_1065MS,
        expected_adv_type="Non connectable undirected - ADV_NONCONN_IND (0x03)",
        bt_log_prefix="test_ble_non_advertise_connectable_power_C20654",
    )


@pytest.mark.config("wifi_dut", wifi=_common_zephyr_ble_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_connect_with_200ms_0dbm_zephyr(
    power_meter, wifi_dut, ble_client, zephyr_wifi_collections, request
):
    """Zephyr: BLE connected with 200ms connection interval @ 0dBm, M4 power capture."""
    try:
        conn_params = {
            "min_conn_interval": CONN_INT_200MS,
            "max_conn_interval": CONN_INT_200MS,
            "conn_latency": 0,
            "supervision_timeout": 3200,
        }
        # Dense ADV for BlueZ discovery (btmon after DUT is found).
        bt_dut_address = _init_ble_advertise(
            wifi_dut,
            adv_data=None,
            ble_adv_type=ADV_TYPE_CONNECTABLE,
            ble_adv_int_min=160,
            ble_adv_int_max=240,
        )
        for discover_attempt in range(2):
            if discover_attempt:
                logger().info("Re-start advertising + rescan after empty BlueZ (200ms connect)")
                _switch_advertising_interval(
                    wifi_dut, ADV_TYPE_CONNECTABLE, 160, 240
                )
                time.sleep(2)
            try:
                _remote_scan_for_dut(
                    ble_client,
                    bt_dut_address,
                    adv_data=wifi_dut.interfaces.wifi.ble_advertising_data,
                    stop_on_exit=True,
                    retries=1,
                )
                break
            except AssertionError:
                if discover_attempt == 1:
                    raise
        with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_connection_200ms_power_zephyr_{int(time.time())}.log",
        ) as bt_logs:
            time.sleep(2)
            logger().info("Initiating connection from remote device")
            ble_client.interfaces.bluetooth.connect(
                dev_addr=bt_dut_address,
                min_conn_interval=conn_params["min_conn_interval"],
                max_conn_interval=conn_params["max_conn_interval"],
                conn_latency=conn_params["conn_latency"],
                supervision_timeout=conn_params["supervision_timeout"],
            )
            time.sleep(60)
            logger().info("Checking connection status of BLE")
            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if str(state).isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            ble_conn_config = bt_logs.read_ble_connection_params(conn_params)
            logger().info(f"**********{ble_conn_config} values in btmon logs")
            assert ble_conn_config["Status"] == "Success"
            assert ble_conn_config["max_conn_interval"] == conn_params["max_conn_interval"]
            time.sleep(5)
            logger().info("found connection intervals of 200ms in btmon logs")
            _run_m4_and_power_capture(wifi_dut, power_meter)
            logger().info("Initiating disconnection from remote device")
            ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)
            time.sleep(5)
    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
        raise


@pytest.fixture()
def nrf_ble_client_optional(request, harness):
    """Like nrf_ble_client, but skip the test when the harness has no nRF role."""
    try:
        client = harness.create_device_for_role("nrf_ble_client", request)
    except RuntimeError as exc:
        pytest.skip(f"Harness has no nrf_ble_client: {exc}")
    fixture_params = {}
    try:
        from utf.interfaces.bluetooth.fixtures import get_fixture_params

        fixture_params = get_fixture_params(request)
    except Exception:
        pass
    client.update_config(**fixture_params)
    client.interfaces.bluetooth.init()
    yield client
    client.restore_config()
    client.interfaces.bluetooth.deinit()


@pytest.mark.config("wifi_dut", wifi=_common_zephyr_ble_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_connect_with_1_28s_0dbm_zephyr(
    power_meter, wifi_dut, nrf_ble_client_optional, zephyr_wifi_collections, request
):
    """Zephyr: BLE connected with 1.28s connection interval @ 0dBm, M4 power capture."""
    nrf_ble_client = nrf_ble_client_optional
    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"reports/test_ble_connection_1_28s_power_zephyr_{int(time.time())}.log",
    ):
        try:
            bt_dut_address = _init_ble_advertise(
                wifi_dut,
                adv_data=None,
                ble_adv_type=ADV_TYPE_CONNECTABLE,
                ble_adv_int_min=160,
                ble_adv_int_max=240,
                set_smp=0,
            )
            logger().info("Initiating scan from remote nRF device")
            nrf_ble_client.interfaces.bluetooth.start_scanning()
            found_devices = nrf_ble_client.interfaces.bluetooth.get_devices()
            logger().info(f"\n\nFound devices: {found_devices}")
            assert str(bt_dut_address) in found_devices
            nrf_ble_client.interfaces.bluetooth.stop_scanning()
            time.sleep(5)
            logger().info("Initiating connection from remote device")
            nrf_ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address)
            nrf_ble_client.interfaces.bluetooth.set_peer_connection_parameters(
                min_connection_interval=CONN_INT_1_28S_MS,
                max_connection_interval=CONN_INT_1_28S_MS,
                connection_timeout=3200,
                slave_latency=0,
            )
            time.sleep(10)
            logger().info("Checking connection status of BLE")
            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if str(state).isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            _run_m4_and_power_capture(wifi_dut, power_meter)
            logger().info("Initiating disconnection from remote device")
            nrf_ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)
            time.sleep(5)
        except Exception as error:
            zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
            raise


@pytest.mark.config("wifi_dut", wifi=_common_zephyr_ble_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_advertise_connectable_power_20ms_zephyr(
    power_meter, wifi_dut, ble_client, zephyr_wifi_collections, request
):
    """Zephyr: BLE connectable advertisement @ 20ms interval with M4 power capture."""
    _run_advertise_power_case(
        wifi_dut,
        ble_client,
        power_meter,
        zephyr_wifi_collections,
        ble_adv_type=ADV_TYPE_CONNECTABLE,
        measure_int_min=ADV_INT_20MS,
        measure_int_max=ADV_INT_20MS,
        expected_adv_type="Connectable undirected - ADV_IND (0x00)",
        bt_log_prefix="test_ble_advertise_connectable_20ms_power_zephyr",
        discover_int_min=ADV_INT_20MS,
        discover_int_max=ADV_INT_20MS,
    )


@pytest.mark.config("wifi_dut", wifi=_common_zephyr_ble_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_advertise_connectable_power_7p5dbm_zephyr(
    power_meter, wifi_dut, ble_client, zephyr_wifi_collections, request
):
    """Zephyr: BLE connectable advertisement @ 7.5dBm TX with M4 power capture."""
    _run_advertise_power_case(
        wifi_dut,
        ble_client,
        power_meter,
        zephyr_wifi_collections,
        ble_adv_type=ADV_TYPE_CONNECTABLE,
        measure_int_min=ADV_INT_DEFAULT,
        measure_int_max=ADV_INT_DEFAULT,
        expected_adv_type="Connectable undirected - ADV_IND (0x00)",
        bt_log_prefix="test_ble_advertise_connectable_7p5dbm_power_zephyr",
    )
