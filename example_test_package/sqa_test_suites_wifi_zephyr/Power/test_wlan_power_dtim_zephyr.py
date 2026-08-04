"""
Zephyr WLAN standby-associated power cases for DTIM 1 / 3 / 6 / 10.

References:
  - test_wlan_power_mcu_advanced_sdk.py  (power helpers + StandBy_Associated flow)
  - test_wlan_sta_throughput_11ax_zephyr.py  (Zephyr join / fixtures / collections)

Topology:
  - Third-party AP with configured DTIM
  - Zephyr DUT joins AP, enables wifi_filter_broadcast + powersave,
    m4_power_manager sleep, then power capture

Author: Benazeer K
"""

import os
import time

import pytest

from utf import TransformFileProperties
from utf.utf_config import UtfConfig
from utf.utils import print_dict
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase


def logger():
    return get_logger(__name__)


def _print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)


# ============================================================
# Power helpers (from test_wlan_power_mcu_advanced_sdk.py)
# ============================================================
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
        # Wait for full M4 sleep before leave(); disconnecting early wakes the
        # radio and inflates power-capture averages.
        wake_wait_sec = (self.m4_sleep_time / 1000.0) + 2
        logger().info(f"Waiting {wake_wait_sec}s for M4 wake-up before leave")
        time.sleep(wake_wait_sec)
        self.wifi_dut.interfaces.wifi.leave()
        logger().info("DUT is leaving the AP")


class WlanThread(ThreadBase):
    """AP DTIM config + Zephyr DUT join (from Zephyr throughput / MCU advanced)."""

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

    def getter(self):
        return self.device_ip


class StandBy_Associated(ThreadBase):
    """
    Zephyr standby-associated power flow:
      start_ap(DTIM) -> join -> wifi_filter_broadcast ->
      set_performance_profile(power_save) -> m4_power_manager + power capture
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
        dtim_aligned_type=1,
        power_analyzer=None,
        beacon_drop_threshold=5000,
        filter_bcast_in_tim=1,
        filter_bcast_tim_till_next_cmd=1,
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
        self.dtim_aligned_type = dtim_aligned_type
        self.power_analyzer = power_analyzer
        self.beacon_drop_threshold = beacon_drop_threshold
        self.filter_bcast_in_tim = filter_bcast_in_tim
        self.filter_bcast_tim_till_next_cmd = filter_bcast_tim_till_next_cmd

    def run(self):
        wifi = self.wifi_dut.interfaces.wifi

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
            wifi.wifi_filter_broadcast()
            #     # beacon_drop_threshold=self.beacon_drop_threshold,
            #     # filter_bcast_in_tim=self.filter_bcast_in_tim,
            #     # filter_bcast_tim_till_next_cmd=self.filter_bcast_tim_till_next_cmd,
            # )
            time.sleep(2)

        logger().info("Enabling Wi-Fi power save (Zephyr performance profile)")
        # wifi.set_performance_profile(
        #     mode="power_save",
        #     dtim_aligned_type=self.dtim_aligned_type,
        # )
        self.wifi_dut.interfaces.wifi.wifi_ps(enabled=1)
        time.sleep(2)

        m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut, m4_sleep_time=self.m4_sleep_time)
        pm_obj = Power_Measurement_Thread(
            power_meter=self.power_meter,
            capture_time=self.capture_time,
            power_analyzer=self.power_analyzer,
        )

        m4_obj.start()
        time.sleep(2)
        pm_obj.start()
        pm_obj.wait_for_exit()
        m4_obj.wait_for_exit()
        time.sleep(10)


def _run_and_collect_power(
    stdby_obj, power_meter, request, #performance_data, custom_performance_fixture
):
    # performance_file_root_dir, perf_file_name = custom_performance_fixture
    # obtained_test_name = request.node.name
    # test_name = (
    #     obtained_test_name.split("[")[0]
    #     if obtained_test_name and "[" in obtained_test_name
    #     else obtained_test_name
    # )
    # opn = UtfConfig.instance().defaults.get("opn", {})
    # build_number = UtfConfig.instance().defaults.get("build_number", {})

    stdby_obj.start()
    stdby_obj.wait_for_exit()

    # parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
    #     power_meter.interfaces.power_meter.results
    # )
    # _print_throughput(parsed_result)
    # assert parsed_result["Output"] is not None
    # performance_data.interfaces.power_perf_data.generate_csv(
    #     test_name=test_name,
    #     opn=opn,
    #     build_number=build_number,
    #     memory_configuration="zephyr",
    #     parsed_result=parsed_result["Output"],
    #     file_path=performance_file_root_dir,
    #     file_name=perf_file_name,
    # )


def _common_zephyr_dut_config():
    return {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }


# ********************************************************************************************************************
# DTIM power cases — Zephyr
# ********************************************************************************************************************
pytestmark = [pytest.mark.firmware_app("test_352K_M4SS_320K")]


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_zephyr_dtim.csv", data_type="power_performance"
    )
)
@pytest.mark.parametrize("dtim", [1])
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wlan_standby_associated_dtim_1_zephyr_c1818511(

    power_meter,
    wifi_access_point,
    wifi_dut,
    zephyr_wifi_collections,
    dtim,
    request,
    # performance_data,
    # custom_performance_fixture,
):
    """Zephyr: standby associated current @ DTIM-1."""
    stdby_obj = StandBy_Associated(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        zephyr_wifi_collections=zephyr_wifi_collections,
        power_meter=power_meter,
    )
    try:
        _run_and_collect_power(
            stdby_obj, power_meter, request,
        )
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise


# @pytest.mark.transform_test_results(
#     TransformFileProperties(
#         file_name="perf_power_consumption_zephyr_dtim.csv", data_type="power_performance"
#     )
# )
@pytest.mark.parametrize("dtim", [3])
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wlan_standby_associated_dtim_3_zephyr_c1818512(
    # firmware_loader,
    power_meter,
    wifi_access_point,
    wifi_dut,
    zephyr_wifi_collections,
    dtim,
    request,
    # performance_data,
    # custom_performance_fixture,
):
    """Zephyr: standby associated current @ DTIM-3."""
    stdby_obj = StandBy_Associated(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        zephyr_wifi_collections=zephyr_wifi_collections,
        power_meter=power_meter,
    )
    try:
        _run_and_collect_power(
            stdby_obj, power_meter, request, #performance_data, custom_performance_fixture
        )
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise


# @pytest.mark.transform_test_results(
#     TransformFileProperties(
#         file_name="perf_power_consumption_zephyr_dtim.csv", data_type="power_performance"
#     )
# )
@pytest.mark.parametrize("dtim", [6])
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wlan_standby_associated_dtim_6_zephyr_c1818513(
    # firmware_loader,
    power_meter,
    wifi_access_point,
    wifi_dut,
    zephyr_wifi_collections,
    dtim,
    request,
    # performance_data,
    # custom_performance_fixture,
):
    """Zephyr: standby associated current @ DTIM-6."""
    stdby_obj = StandBy_Associated(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        zephyr_wifi_collections=zephyr_wifi_collections,
        power_meter=power_meter,
    )
    try:
        _run_and_collect_power(
            stdby_obj, power_meter, request, #performance_data, custom_performance_fixture
        )
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise


# @pytest.mark.transform_test_results(
#     TransformFileProperties(
#         file_name="perf_power_consumption_zephyr_dtim.csv", data_type="power_performance"
#     )
# )
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wlan_standby_associated_dtim_10_zephyr_c1818514(
    # firmware_loader,
    power_meter,
    wifi_access_point,
    wifi_dut,
    zephyr_wifi_collections,
    dtim,
    request,
    # performance_data,
    # custom_performance_fixture,
):
    """Zephyr: standby associated current @ DTIM-10."""
    stdby_obj = StandBy_Associated(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        zephyr_wifi_collections=zephyr_wifi_collections,
        power_meter=power_meter,
    )
    try:
        _run_and_collect_power(
            stdby_obj, power_meter, request, #performance_data, custom_performance_fixture
        )
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise


# ********************************************************************************************************************
# DTIM power cases without broadcast filter — Zephyr
# ********************************************************************************************************************


@pytest.mark.parametrize("dtim", [1])
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wlan_standby_associated_dtim_1_without_bcast_filter_zephyr_c1818515(
    power_meter,
    wifi_access_point,
    wifi_dut,
    zephyr_wifi_collections,
    dtim,
    request,
):
    """Zephyr: standby associated current @ DTIM-1 without broadcast filter."""
    stdby_obj = StandBy_Associated(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        zephyr_wifi_collections=zephyr_wifi_collections,
        power_meter=power_meter,
        bcast_filter=False,
    )
    try:
        _run_and_collect_power(stdby_obj, power_meter, request)
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise


@pytest.mark.parametrize("dtim", [3])
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wlan_standby_associated_dtim_3_without_bcast_filter_zephyr_c1818516(
    power_meter,
    wifi_access_point,
    wifi_dut,
    zephyr_wifi_collections,
    dtim,
    request,
):
    """Zephyr: standby associated current @ DTIM-3 without broadcast filter."""
    stdby_obj = StandBy_Associated(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        zephyr_wifi_collections=zephyr_wifi_collections,
        power_meter=power_meter,
        bcast_filter=False,
    )
    try:
        _run_and_collect_power(stdby_obj, power_meter, request)
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise


@pytest.mark.parametrize("dtim", [6])
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wlan_standby_associated_dtim_6_without_bcast_filter_zephyr_c1818517(
    power_meter,
    wifi_access_point,
    wifi_dut,
    zephyr_wifi_collections,
    dtim,
    request,
):
    """Zephyr: standby associated current @ DTIM-6 without broadcast filter."""
    stdby_obj = StandBy_Associated(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        zephyr_wifi_collections=zephyr_wifi_collections,
        power_meter=power_meter,
        bcast_filter=False,
    )
    try:
        _run_and_collect_power(stdby_obj, power_meter, request)
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config("wifi_dut", wifi=_common_zephyr_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wlan_standby_associated_dtim_10_without_bcast_filter_zephyr_c1818518(
    power_meter,
    wifi_access_point,
    wifi_dut,
    zephyr_wifi_collections,
    dtim,
    request,
):
    """Zephyr: standby associated current @ DTIM-10 without broadcast filter."""
    stdby_obj = StandBy_Associated(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        zephyr_wifi_collections=zephyr_wifi_collections,
        power_meter=power_meter,
        bcast_filter=False,
    )
    try:
        _run_and_collect_power(stdby_obj, power_meter, request)
    except Exception as ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise
