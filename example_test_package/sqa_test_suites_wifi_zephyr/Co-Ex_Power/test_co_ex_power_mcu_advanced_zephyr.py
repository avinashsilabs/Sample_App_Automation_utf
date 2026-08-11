"""
Zephyr WLAN + BLE co-existence standby-associated power cases (M4 enable).

Reference flow (structure only):
  test_co_ex_power_mcu_advanced_sdk.py

Uses Zephyr DUT APIs from zephyr_wifi_test_agent_cli.py:
  ble_start / bt_set_local_name / ble_set_adv_data / ble_start_advertising /
  ble_get_device_state / wifi_filter_broadcast / wifi_ps / m4_power_manager

Does NOT use SDK APIs such as set_performance_profile / set_filter_broadcast /
m4_power_manager(sleep_time=...) / SDK BLE CLI handlers.

Topology:
  - Third-party AP (DTIM-10)
  - Zephyr DUT in WLAN + BLE co-ex
  - Optional remote BLE client (connection cases)
  - Power meter capture during M4 sleep

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


def _common_zephyr_coex_dut_config():
    return {
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    }


class device_scan_result:
    def check_for_devices_in_scanned_results(self, ble_client, bt_dut_address, adv_data=None):
        """Find DUT in BlueZ scan by BD_ADDR.

        Zephyr le_advertise does not put the SDK-style payload string on air; BlueZ
        typically reports the address (e.g. 94-EC-32-BA-BC-0E) as the device name.
        So address presence is enough — do not require found_devices[addr] == adv_data.
        """
        sw = Stopwatch()
        previously_found_devices = {}
        dut = (bt_dut_address or "").upper().replace("-", ":")
        while sw.elapsed_sec < 30:
            found_devices = ble_client.interfaces.bluetooth.get_devices() or {}
            if previously_found_devices != found_devices:
                logger().info(f"BLE scan results :{found_devices}")
                previously_found_devices = found_devices

            for key, reported in found_devices.items():
                key_norm = str(key).upper().replace("-", ":")
                if key_norm != dut:
                    continue
                logger().info(
                    f"DUT {dut} found in scan (reported={reported!r}, adv_data={adv_data!r})"
                )
                return True
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

    def __init__(self, wifi_dut=None, m4_sleep_time=120000):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.m4_sleep_time = m4_sleep_time

    def run(self):
        logger().info(f"Enabling M4 power save for {self.m4_sleep_time} ms")
        self.wifi_dut.interfaces.wifi.m4_power_manager(duration_ms=self.m4_sleep_time)
        wake_wait_sec = (self.m4_sleep_time / 1000.0) + 2
        logger().info(f"Waiting {wake_wait_sec}s for M4 wake-up before leave")
        time.sleep(wake_wait_sec)
        self.wifi_dut.interfaces.wifi.leave()
        logger().info("DUT is leaving the AP")


class WlanThread(ThreadBase):
    """AP DTIM config + Zephyr DUT join (no SDK performance-profile APIs)."""

    def __init__(
        self,
        wifi_dut=None,
        wifi_access_point=None,
        zephyr_wifi_collections=None,
        dtim=10,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.dtim = dtim
        self.device_ip = None
        self.dut_addr = None

    def run(self):
        logger().info(f"Configuring Access Point with dtim : {self.dtim}")
        self.wifi_access_point.interfaces.wifi.start_ap(dtim=self.dtim)
        time.sleep(20)
        logger().info("Scanning and Connecting Zephyr DUT to Access Point")
        self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
            power_save=False,
            ping_after_power_save=False,
            retry_count=3,
        )
        if not self.dut_addr.get("dut_mac_address"):
            self.dut_addr["dut_mac_address"] = self.wifi_dut.interfaces.wifi.get_mac_address()
        self.device_ip = self.dut_addr["device_ip"]
        logger().info(
            f"DUT IP: {self.device_ip}, DUT MAC: {self.dut_addr.get('dut_mac_address')}"
        )


class StandBy_Associated(ThreadBase):
    """
    Zephyr co-ex standby-associated power flow:
      BLE advertise [/ remote connect] -> WLAN join -> wifi_filter_broadcast ->
      wifi_ps -> m4_power_manager + power capture -> optional BLE disconnect
    """

    def __init__(
        self,
        dtim=10,
        wifi_dut=None,
        wifi_access_point=None,
        zephyr_wifi_collections=None,
        power_meter=None,
        capture_time=60,
        m4_sleep_time=120000,
        bcast_filter=True,
        power_analyzer=None,
        ble_client=None,
        ble_advertisement=False,
        ble_with_connection=False,
        utf_constants=None,
        long_run=False,
    ):
        super().__init__()
        self.dtim = dtim
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.power_meter = power_meter
        self.capture_time = capture_time
        self.m4_sleep_time = m4_sleep_time
        self.bcast_filter = bcast_filter
        self.power_analyzer = power_analyzer
        self.ble_client = ble_client
        self.ble_advertisement = ble_advertisement
        self.ble_with_connection = ble_with_connection
        self.utf_constants = utf_constants or {}
        self.long_run = long_run

    def _setup_ble_advertisement(self):
        wifi = self.wifi_dut.interfaces.wifi
        logger().info("Initializing BLE")
        wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
        logger().info("configure bt local name....")
        wifi.bt_set_local_name(bt_local_name="Silabsautomation")
        logger().info("Setting Adv Data")
        wifi.ble_set_adv_data(ble_advertising_data="123456789011234567")
        logger().info("fetch the local name")
        wifi.bt_get_local_name()
        logger().info("Advertising DUT (undirected connectable)")
        wifi.ble_start_advertising(
            ble_adv_type=128,
            ble_adv_int_min=2048,
            ble_adv_int_max=2048,
            ble_adv_channel_map=7,
        )
        time.sleep(2)

    def _setup_ble_connection(self):
        wifi = self.wifi_dut.interfaces.wifi
        conn_params = {
            "min_conn_interval": 0xA0,
            "max_conn_interval": 0xA0,
            "conn_latency": 0,
            "supervision_timeout": 3200,
        }
        logger().info("Initializing BLE")
        bt_dut_address = wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
        logger().info("configure bt local name....")
        wifi.bt_set_local_name(bt_local_name="Silabsautomation")
        logger().info("fetch the local name")
        wifi.bt_get_local_name()
        logger().info("Advertising DUT")
        wifi.ble_start_advertising(
            ble_adv_type=128,
            ble_adv_int_min=2048,
            ble_adv_int_max=2048,
            ble_adv_channel_map=7,
        )
        logger().info("Initiating scan from remote device")
        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address
        )
        assert bt_client_address is not None, "Unable to fetch BD address from remote BLE device"
        scan_result = device_scan_result()
        device_found = scan_result.check_for_devices_in_scanned_results(
            ble_client=self.ble_client,
            bt_dut_address=bt_dut_address,
            adv_data=wifi.ble_advertising_data,
        )
        assert device_found, "DUT not found in scan results"
        logger().info("initiating stop scanning")
        self.ble_client.interfaces.bluetooth.stop_scanning()
        time.sleep(5)
        logger().info("Initiating connection from remote device")
        self.ble_client.interfaces.bluetooth.connect(
            dev_addr=bt_dut_address,
            min_conn_interval=conn_params["min_conn_interval"],
            max_conn_interval=conn_params["max_conn_interval"],
            conn_latency=conn_params["conn_latency"],
            supervision_timeout=conn_params["supervision_timeout"],
        )
        time.sleep(60)
        logger().info("Checking connection status of BLE")
        state = wifi.ble_get_device_state()
        state_int = int(state) if str(state).isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
        time.sleep(5)

    def run(self):
        wifi = self.wifi_dut.interfaces.wifi

        if self.ble_advertisement:
            with BleLogs(
                start_collecting_logs=True,
                bt_log_path=f"reports/test_ble_advertise_connectable_power_zephyr_{int(time.time())}.log",
            ):
                try:
                    self._setup_ble_advertisement()
                except Exception as error:
                    self.zephyr_wifi_collections.exception_handling(
                        wifi_dut=self.wifi_dut, exception=error
                    )
                    raise

        if self.ble_with_connection:
            with BleLogs(
                start_collecting_logs=True,
                bt_log_path=f"reports/test_ble_connection_power_zephyr_{int(time.time())}.log",
            ):
                try:
                    self._setup_ble_connection()
                except Exception as error:
                    self.zephyr_wifi_collections.exception_handling(
                        wifi_dut=self.wifi_dut, exception=error
                    )
                    raise

        wlan_obj = WlanThread(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            zephyr_wifi_collections=self.zephyr_wifi_collections,
            dtim=self.dtim,
        )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)

        if self.bcast_filter:
            logger().info("Setting wifi_filter_broadcast command")
            wifi.wifi_filter_broadcast(
                threshold_ms=5000,
                in_tim=1,
                till_next_cmd=1,
            )
            time.sleep(2)

        logger().info("Enabling Wi-Fi power save (Zephyr wifi.ps)")
        wifi.wifi_ps(enabled=1)
        time.sleep(2)

        m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut, m4_sleep_time=self.m4_sleep_time)
        capture_time = (
            self.utf_constants.get("long_duration", self.capture_time)
            if self.long_run
            else self.capture_time
        )
        pm_obj = Power_Measurement_Thread(
            power_meter=self.power_meter,
            capture_time=capture_time,
            power_analyzer=self.power_analyzer,
        )

        m4_obj.start()
        time.sleep(2)
        pm_obj.start()
        pm_obj.wait_for_exit()
        m4_obj.wait_for_exit()
        time.sleep(10)

        if self.ble_with_connection:
            logger().info("Initiating disconnection from remote device")
            self.ble_client.interfaces.bluetooth.disconnect(wifi.ble_address)
            time.sleep(5)


def _run_and_collect_power(stdby_obj):
    stdby_obj.start()
    stdby_obj.wait_for_exit()


# ********************************************************************************************************************
# Co-Ex power + M4 enable cases — Zephyr
# ********************************************************************************************************************
# pytestmark = [pytest.mark.firmware_app("test_352K_M4SS_320K")]


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_coex_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wlan_conn_dtim_10_ble_adv_zephyr(
    power_meter,
    wifi_access_point,
    wifi_dut,
    zephyr_wifi_collections,
    dtim,
    request,
):
    """Zephyr co-ex: WLAN + BLE advertisement, DTIM-10, M4 power capture."""
    stdby_obj = StandBy_Associated(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        zephyr_wifi_collections=zephyr_wifi_collections,
        power_meter=power_meter,
        ble_advertisement=True,
    )
    try:
        _run_and_collect_power(stdby_obj)
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_coex_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wlan_conn_dtim_10_ble_conn_zephyr(
    power_meter,
    wifi_access_point,
    wifi_dut,
    zephyr_wifi_collections,
    dtim,
    ble_client,
    request,
):
    """Zephyr co-ex: WLAN + BLE connected, DTIM-10, M4 power capture."""
    stdby_obj = StandBy_Associated(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        zephyr_wifi_collections=zephyr_wifi_collections,
        power_meter=power_meter,
        ble_client=ble_client,
        ble_with_connection=True,
    )
    try:
        _run_and_collect_power(stdby_obj)
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise
