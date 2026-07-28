"""
Wi-Fi BC/MC filter power / functional automation.

Topology:
  - Third-party AP
  - DUT (STA) joins AP, configures groupcast filter, enters powersave
  - wifi_client (Raspi STA) joins same AP and generates BC/MC traffic
    (DUT does NOT generate traffic)

Traffic generation mirrors:
  IPv4_traffic_bc_mc_traffic_gen_2.py

DUT filter APIs (require pending test-agent handlers):
  - set_groupcast_filter_config(enable_bcast, enable_mcast, filter_mode)
  - set_beacon_drop_threshold(interface, beacon_drop_threshold)
  - allowlist_mcast_remove_all()
  - allowlist_mcast_add_ip(ip)
  - allowlist_mcast_remove_ip(handle)

References:
  - test_wlan_power_mcu_advanced_sdk.py  (DUT join + powersave + power capture)
  - test_throughput_ap_alone_sdk.py / test_throughput_google_ap_sdk.py
    (wifi_client.join to AP)
"""

import os
import time
import textwrap

import pytest

from utf.utils import print_dict
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utf_config import UtfConfig
from utf import TransformFileProperties
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xJoinFeatureBitMap,
)


# ============================================================
# Traffic defaults — mirror IPv4_traffic_bc_mc_traffic_gen_2.py
# ============================================================
PORT = 5001
MC_ALLOWLIST_IPS = [
    "224.0.0.50",
    "224.0.0.51",
    "224.0.0.52",
    "224.0.0.53",
    "224.0.0.54",
    "224.0.0.55",
]
MC_NONALLOW_IPS = ["224.0.0.60"]
PACKETS_PER_GROUP = 100
PPS = 50
GAP_BETWEEN_GROUPS_SEC = 2
PAYLOAD_SIZE = 200
BEACON_DROP_THRESHOLD = 5000


def logger():
    return get_logger(__name__)


def _print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)


# ============================================================
# Power measurement helpers (from test_wlan_power_mcu_advanced_sdk.py)
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
    """Same pattern as test_wlan_power_mcu_advanced_sdk.py StandBy_Associated."""

    def __init__(self, wifi_dut=None, m4_sleep_time=100000, deep_sleep_without_ret=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.m4_sleep_time = m4_sleep_time
        self.deep_sleep_without_ret = deep_sleep_without_ret

    def run(self):
        logger().info("Enabling M4 power save")
        if self.deep_sleep_without_ret:
            self.wifi_dut.interfaces.wifi.m4_power_manager_deep_sleep(
                state=0, sleep_time=self.m4_sleep_time
            )
        else:
            self.wifi_dut.interfaces.wifi.m4_power_manager(
                sleep_time=self.m4_sleep_time, timeout=150
            )
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.leave()
        logger().info("DUT is leaving the AP")


# ============================================================
# wifi_client BC/MC traffic generator (third-party STA on AP)
# ============================================================
class WifiClientBcMcTraffic:
    """
    Generate IPv4 broadcast / multicast UDP bursts from wifi_client.
    Logic mirrors IPv4_traffic_bc_mc_traffic_gen_2.py.
    """

    TRAFFIC_SCRIPT = textwrap.dedent(
        """\
        import socket, time, sys
        SERVER_IF_IP = "{server_if_ip}"
        BC_IP = "{bc_ip}"
        PORT = {port}
        ALLOW_STREAMS = {allow_streams}
        NONALLOW_STREAMS = {nonallow_streams}
        SEND_BROADCAST = {send_broadcast}
        PACKETS_PER_GROUP = {packets_per_group}
        PPS = {pps}
        GAP_BETWEEN_GROUPS_SEC = {gap_sec}
        PAYLOAD_SIZE = {payload_size}

        def payload(tag, seq):
            b = ("%s|seq=%d|ts=%.6f" % (tag, seq, time.time())).encode("ascii")
            return b + (b"X" * max(0, PAYLOAD_SIZE - len(b)))

        def send_group_burst(sock, dst_ip, label, count, pps):
            gap = 1.0 / float(pps)
            print("  --> Sending %d packets to %s (%s) @ %d pps" % (count, dst_ip, label, pps))
            for seq in range(1, count + 1):
                sock.sendto(payload(label, seq), (dst_ip, PORT))
                time.sleep(gap)
            print("  --> Done %s: %d packets sent" % (dst_ip, count))
            time.sleep(GAP_BETWEEN_GROUPS_SEC)

        bc_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        bc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        mc_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        mc_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        mc_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(SERVER_IF_IP))

        try:
            if SEND_BROADCAST:
                print("[STEP 1] Broadcast burst -> %s" % BC_IP)
                send_group_burst(bc_sock, BC_IP, "BC", PACKETS_PER_GROUP, PPS)
            print("[STEP 2] Allowlisted MC groups")
            for ip in ALLOW_STREAMS:
                send_group_burst(mc_sock, ip, "ALLOW_%s" % ip, PACKETS_PER_GROUP, PPS)
            print("[STEP 3] Non-allowlisted MC groups")
            for ip in NONALLOW_STREAMS:
                send_group_burst(mc_sock, ip, "BLOCK_%s" % ip, PACKETS_PER_GROUP, PPS)
            print("All traffic generation completed.")
        finally:
            bc_sock.close()
            mc_sock.close()
        """
    )

    def __init__(self, wifi_client=None):
        self.wifi_client = wifi_client

    def join_third_party_ap(self, wifi_access_point, interface="wlan0"):
        """Connect wifi_client (Raspi) to the same third-party AP as DUT."""
        ssid = wifi_access_point.interfaces.wifi.ssid
        passphrase = wifi_access_point.interfaces.wifi.passphrase
        security = wifi_access_point.interfaces.wifi.security
        if hasattr(security, "name"):
            security = security.name

        # Must use Wi-Fi NIC (wlan0). eth0/eth1 are wired and will fail nl80211.
        wifi_if = self.wifi_client.interfaces.wifi
        if hasattr(wifi_if, "config") and isinstance(wifi_if.config, dict):
            wifi_if.config["interface"] = interface
            logger().info(f"***** wifi_client interface forced to {interface} *****")

        logger().info(
            f"***** wifi_client joining third-party AP: {ssid} / {security} "
            f"on {getattr(wifi_if, 'config', {}).get('interface', interface)} *****"
        )
        # Same pattern as test_throughput_google_ap_sdk.py
        wifi_if.join(
            ssid=ssid,
            passphrase=passphrase,
            security=security,
        )
        time.sleep(5)
        host_ip = wifi_if.get_ip_address()
        logger().info(f"***** wifi_client IP: {host_ip} *****")
        assert host_ip, "wifi_client failed to get IP after joining AP"
        return host_ip

    def leave(self):
        logger().info("***** wifi_client leaving AP *****")
        self.wifi_client.interfaces.wifi.leave()

    def _broadcast_ip(self, host_ip):
        parts = host_ip.split(".")
        parts[3] = "255"
        return ".".join(parts)

    def generate_traffic(
        self,
        host_ip,
        send_broadcast=True,
        allow_streams=None,
        nonallow_streams=None,
        packets_per_group=PACKETS_PER_GROUP,
        pps=PPS,
        gap_sec=GAP_BETWEEN_GROUPS_SEC,
        payload_size=PAYLOAD_SIZE,
        port=PORT,
    ):
        """
        Run BC/MC UDP bursts from wifi_client (not DUT).
        """
        if allow_streams is None:
            allow_streams = []
        if nonallow_streams is None:
            nonallow_streams = []

        bc_ip = self._broadcast_ip(host_ip)
        script = self.TRAFFIC_SCRIPT.format(
            server_if_ip=host_ip,
            bc_ip=bc_ip,
            port=port,
            allow_streams=repr(list(allow_streams)),
            nonallow_streams=repr(list(nonallow_streams)),
            send_broadcast=str(bool(send_broadcast)),
            packets_per_group=packets_per_group,
            pps=pps,
            gap_sec=gap_sec,
            payload_size=payload_size,
        )

        remote_path = "/tmp/ipv4_bc_mc_traffic_gen.py"
        logger().info(
            f"***** Generating BC/MC traffic from wifi_client "
            f"(BC={send_broadcast}, allow={allow_streams}, block={nonallow_streams}) *****"
        )
        # Write + run on wifi_client (Raspi) — same idea as manual IPv4 gen script
        self.wifi_client.interfaces.wifi.shell.create_file(remote_path, script)
        rc, stdout, stderr = self.wifi_client.interfaces.wifi.shell.execute(
            f"python3 {remote_path}"
        )
        out = stdout.decode() if isinstance(stdout, bytes) else str(stdout)
        err = stderr.decode() if isinstance(stderr, bytes) else str(stderr)
        logger().info(f"Traffic gen stdout:\n{out}")
        if err:
            logger().info(f"Traffic gen stderr:\n{err}")
        assert rc == 0, f"BC/MC traffic generation failed on wifi_client: {err}"
        return out


# ============================================================
# DUT groupcast filter helpers (new SDK 4.1 APIs)
# ============================================================
def configure_groupcast_filter(
    wifi_dut,
    enable_bcast_filter=0,
    enable_mcast_filter=0,
    filter_mode=0,
    allowlist_ips=None,
    beacon_drop_threshold=BEACON_DROP_THRESHOLD,
    clear_allowlist=True,
):
    """
    Configure DUT BC/MC filter using new groupcast APIs.

    NOTE: BC/MC API calls are temporarily commented for script validation.
          Uncomment when test-agent handlers are ready, then push.
    """
    wifi = wifi_dut.interfaces.wifi
    allowlist_ips = allowlist_ips or []

    logger().info(
        f"***** DUT groupcast filter (APIs COMMENTED for now): BC={enable_bcast_filter}, "
        f"MC={enable_mcast_filter}, mode={filter_mode}, allowlist={allowlist_ips} *****"
    )

    # Uncomment MC/BC APIs once handlers are ready
    # wifi.set_groupcast_filter_config(
    #     enable_bcast_filter=enable_bcast_filter,
    #     enable_mcast_filter=enable_mcast_filter,
    #     filter_mode=filter_mode,
    # )
    #
    # if beacon_drop_threshold is not None:
    #     wifi.set_beacon_drop_threshold(
    #         interface="client",
    #         beacon_drop_threshold=beacon_drop_threshold,
    #     )
    #
    # if clear_allowlist:
    #     wifi.allowlist_mcast_remove_all()
    #
    # handles = []
    # for ip in allowlist_ips:
    #     handle = wifi.allowlist_mcast_add_ip(ip)
    #     handles.append(handle)
    #     logger().info(f"Allowlist add: {ip} (handle={handle})")
    # return handles
    _ = wifi  # keep reference while APIs are commented
    return []


# ============================================================
# Main test flow
# ============================================================
class BcMcFilterStandBy(ThreadBase):
    def __init__(
        self,
        dtim=10,
        wifi_dut=None,
        wifi_access_point=None,
        wifi_client=None,
        sl_collections=None,
        power_meter=None,
        capture_time=60,
        power_analyzer=None,
        enable_bcast_filter=1,
        enable_mcast_filter=1,
        filter_mode=0,
        allowlist_ips=None,
        send_broadcast=True,
        nonallow_streams=None,
        generate_traffic=True,
        toggle_filter_times=0,
        m4_sleep_time=120000,
        measure_power=True,
        deep_sleep=False,
    ):
        super().__init__()
        self.dtim = dtim
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.power_meter = power_meter
        self.capture_time = capture_time
        self.power_analyzer = power_analyzer
        self.enable_bcast_filter = enable_bcast_filter
        self.enable_mcast_filter = enable_mcast_filter
        self.filter_mode = filter_mode
        self.allowlist_ips = allowlist_ips if allowlist_ips is not None else []
        self.send_broadcast = send_broadcast
        self.nonallow_streams = nonallow_streams if nonallow_streams is not None else MC_NONALLOW_IPS
        self.generate_traffic = generate_traffic
        self.toggle_filter_times = toggle_filter_times
        self.m4_sleep_time = m4_sleep_time
        self.measure_power = measure_power
        self.deep_sleep = deep_sleep
        self.host_ip = None
        self.device_ip = None

    def run(self):
        dut = UtfConfig.instance().defaults.get("dut", {})
        traffic = WifiClientBcMcTraffic(wifi_client=self.wifi_client)

        if dut != "si917_ncp_sl_wifi":
            logger().info("M4-TA secure handshake")
            self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
        time.sleep(2)

        self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface="client",
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default,
        )

        # AP DTIM + DUT join (same pattern as StandBy_Associated / WlanThread)
        logger().info(f"Configuring Access Point with dtim : {self.dtim}")
        self.wifi_access_point.interfaces.wifi.start_ap(dtim=self.dtim)

        logger().info("Scanning and Connecting DUT to Access Point")
        dictionary = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
            power_save=False,
            retry_count=3,
        )
        self.device_ip = dictionary["device_ip"]
        logger().info(f"DUT IP: {self.device_ip}")

        # wifi_client joins same third-party AP (traffic source)
        self.host_ip = traffic.join_third_party_ap(self.wifi_access_point)

        # DUT BC/MC filter configuration
        configure_groupcast_filter(
            wifi_dut=self.wifi_dut,
            enable_bcast_filter=self.enable_bcast_filter,
            enable_mcast_filter=self.enable_mcast_filter,
            filter_mode=self.filter_mode,
            allowlist_ips=self.allowlist_ips,
        )

        # Optional: enable/disable filter multiple times
        for i in range(self.toggle_filter_times):
            logger().info(f"***** Filter toggle cycle {i + 1}/{self.toggle_filter_times} *****")
            configure_groupcast_filter(
                wifi_dut=self.wifi_dut,
                enable_bcast_filter=0,
                enable_mcast_filter=0,
                filter_mode=self.filter_mode,
                allowlist_ips=[],
                clear_allowlist=True,
            )
            time.sleep(2)
            configure_groupcast_filter(
                wifi_dut=self.wifi_dut,
                enable_bcast_filter=self.enable_bcast_filter,
                enable_mcast_filter=self.enable_mcast_filter,
                filter_mode=self.filter_mode,
                allowlist_ips=self.allowlist_ips,
            )
            time.sleep(2)

        time.sleep(2)
        logger().info("Enabling TA power save")
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save", dtim_aligned_type=1)
        time.sleep(2)

        m4_obj = None
        if dut != "si917_ncp_sl_wifi":
            if self.deep_sleep:
                m4_obj = M4_Sleep_Thread(
                    wifi_dut=self.wifi_dut,
                    m4_sleep_time=self.m4_sleep_time,
                    deep_sleep_without_ret=True,
                )
            else:
                m4_obj = M4_Sleep_Thread(
                    wifi_dut=self.wifi_dut,
                    m4_sleep_time=self.m4_sleep_time,
                )

        pm_obj = None
        if self.measure_power:
            pm_obj = Power_Measurement_Thread(
                power_meter=self.power_meter,
                capture_time=self.capture_time,
                power_analyzer=self.power_analyzer,
            )

        # Match StandBy_Associated: start M4 sleep thread, then power capture
        if m4_obj is not None:
            m4_obj.start()
            time.sleep(2)

        if pm_obj is not None:
            pm_obj.start()
            time.sleep(2)

        # Traffic from wifi_client (third-party STA), not DUT — while DUT is in M4 sleep
        if self.generate_traffic:
            traffic.generate_traffic(
                host_ip=self.host_ip,
                send_broadcast=self.send_broadcast,
                allow_streams=self.allowlist_ips,
                nonallow_streams=self.nonallow_streams,
            )

        if pm_obj is not None:
            pm_obj.wait_for_exit()

        if m4_obj is not None:
            m4_obj.wait_for_exit()
        else:
            # NCP path: M4 thread not used, leave DUT here
            self.wifi_dut.interfaces.wifi.leave()
            logger().info("DUT left the AP")

        traffic.leave()
        time.sleep(5)


def _common_dut_wifi_config():
    return {
        "oper_mode": Si91xOperatingMode.Default,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode
        | Si91xFeatureBitMap.Aggregation
        | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.DNSClient
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints
        | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }


def _run_and_collect_power(stdby_obj, power_meter, request, performance_data, custom_performance_fixture):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = (
        obtained_test_name.split("[")[0]
        if obtained_test_name and "[" in obtained_test_name
        else obtained_test_name
    )
    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})

    stdby_obj.start()
    stdby_obj.wait_for_exit()

    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
        power_meter.interfaces.power_meter.results
    )
    _print_throughput(parsed_result)
    assert parsed_result["Output"] is not None
    performance_data.interfaces.power_perf_data.generate_csv(
        test_name=test_name,
        opn=opn,
        build_number=build_number,
        memory_configuration="test_352K_M4SS_320K",
        parsed_result=parsed_result["Output"],
        file_path=performance_file_root_dir,
        file_name=perf_file_name,
    )


# ********************************************************************************************************************
# Test cases
# ********************************************************************************************************************
pytestmark = [pytest.mark.firmware_app("test_352K_M4SS_320K")]


@pytest.mark.transform_test_results(
    TransformFileProperties(file_name="perf_power_consumption_bc_mc_filter.csv", data_type="power_performance")
)
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config("wifi_dut", wifi=_common_dut_wifi_config())
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_client",
    wifi={
        "interface": "wlan0",
    },
)
def test_wlan_sta_broadcast_only_filter_on_C1818211(
    firmware_loader,
    power_meter,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    sl_collections,
    dtim,
    request,
    performance_data,
    custom_performance_fixture,
):
    """STA connected with Broadcast only filtering ON — traffic from wifi_client."""
    stdby_obj = BcMcFilterStandBy(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_client=wifi_client,
        sl_collections=sl_collections,
        power_meter=power_meter,
        power_analyzer=None,
        enable_bcast_filter=1,
        enable_mcast_filter=0,
        filter_mode=0,
        allowlist_ips=[],
        send_broadcast=True,
        nonallow_streams=MC_NONALLOW_IPS,
    )
    _run_and_collect_power(stdby_obj, power_meter, request, performance_data, custom_performance_fixture)


@pytest.mark.transform_test_results(
    TransformFileProperties(file_name="perf_power_consumption_bc_mc_filter.csv", data_type="power_performance")
)
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config("wifi_dut", wifi=_common_dut_wifi_config())
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_client",
    wifi={
        "interface": "wlan0",
    },
)
def test_wlan_sta_multicast_only_filter_on_C1818210(
    firmware_loader,
    power_meter,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    sl_collections,
    dtim,
    request,
    performance_data,
    custom_performance_fixture,
):
    """STA connected with Multicast only filtering ON — traffic from wifi_client."""
    stdby_obj = BcMcFilterStandBy(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_client=wifi_client,
        sl_collections=sl_collections,
        power_meter=power_meter,
        power_analyzer=None,
        enable_bcast_filter=0,
        enable_mcast_filter=1,
        filter_mode=0,
        allowlist_ips=MC_ALLOWLIST_IPS[:2],
        send_broadcast=False,
        nonallow_streams=MC_NONALLOW_IPS,
    )
    _run_and_collect_power(stdby_obj, power_meter, request, performance_data, custom_performance_fixture)


@pytest.mark.transform_test_results(
    TransformFileProperties(file_name="perf_power_consumption_bc_mc_filter.csv", data_type="power_performance")
)
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config("wifi_dut", wifi=_common_dut_wifi_config())
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_client",
    wifi={
        "interface": "wlan0",
    },
)
def test_wlan_sta_mc_bc_filter_enable_disable_multiple_times_c1818223(
    firmware_loader,
    power_meter,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    sl_collections,
    dtim,
    request,
    performance_data,
    custom_performance_fixture,
):
    """STA connected: MC/BC filter enabled and disabled multiple times."""
    stdby_obj = BcMcFilterStandBy(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_client=wifi_client,
        sl_collections=sl_collections,
        power_meter=power_meter,
        power_analyzer=None,
        enable_bcast_filter=1,
        enable_mcast_filter=1,
        filter_mode=0,
        allowlist_ips=MC_ALLOWLIST_IPS[:2],
        send_broadcast=True,
        toggle_filter_times=3,
    )
    _run_and_collect_power(stdby_obj, power_meter, request, performance_data, custom_performance_fixture)


@pytest.mark.transform_test_results(
    TransformFileProperties(file_name="perf_power_consumption_bc_mc_filter.csv", data_type="power_performance")
)
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config("wifi_dut", wifi=_common_dut_wifi_config())
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_client",
    wifi={
        "interface": "wlan0",
    },
)
def test_wlan_sta_mc_bc_filter_on_stream_mc_bc_more_data_c1818224(
    firmware_loader,
    power_meter,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    sl_collections,
    dtim,
    request,
    performance_data,
    custom_performance_fixture,
):
    """STA connected with MC/BC filter enabled; stream of MC/BC packets (More Data=1 via AP buffering)."""
    stdby_obj = BcMcFilterStandBy(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_client=wifi_client,
        sl_collections=sl_collections,
        power_meter=power_meter,
        power_analyzer=None,
        enable_bcast_filter=1,
        enable_mcast_filter=1,
        filter_mode=0,
        allowlist_ips=MC_ALLOWLIST_IPS[:2],
        send_broadcast=True,
        nonallow_streams=[],
    )
    _run_and_collect_power(stdby_obj, power_meter, request, performance_data, custom_performance_fixture)


@pytest.mark.transform_test_results(
    TransformFileProperties(file_name="perf_power_consumption_bc_mc_filter.csv", data_type="power_performance")
)
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config("wifi_dut", wifi=_common_dut_wifi_config())
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_client",
    wifi={
        "interface": "wlan0",
    },
)
def test_wlan_sta_mc_bc_filter_on_stream_unicast_more_data_c1818225(
    firmware_loader,
    power_meter,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    sl_collections,
    dtim,
    request,
    performance_data,
    custom_performance_fixture,
):
    """
    STA connected with MC/BC filter enabled; stream of unicast packets with More Data=1.
    Unicast UDP is generated from wifi_client to DUT IP (no BC/MC bursts).
    """
    class UnicastMoreDataStandBy(BcMcFilterStandBy):
        def run(self):
            dut = UtfConfig.instance().defaults.get("dut", {})
            traffic = WifiClientBcMcTraffic(wifi_client=self.wifi_client)

            if dut != "si917_ncp_sl_wifi":
                self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
            time.sleep(2)
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                interface="client", join_feature_bitmap=Si91xJoinFeatureBitMap.Default
            )
            self.wifi_access_point.interfaces.wifi.start_ap(dtim=self.dtim)
            dictionary = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut,
                wifi_access_point=self.wifi_access_point,
                associated=self.wifi_dut.interfaces.wifi.associated,
                power_save=False,
                retry_count=3,
            )
            self.device_ip = dictionary["device_ip"]
            self.host_ip = traffic.join_third_party_ap(self.wifi_access_point)

            configure_groupcast_filter(
                wifi_dut=self.wifi_dut,
                enable_bcast_filter=1,
                enable_mcast_filter=1,
                filter_mode=0,
                allowlist_ips=MC_ALLOWLIST_IPS[:2],
            )
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save", dtim_aligned_type=1)
            time.sleep(2)

            m4_obj = None
            if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(
                    wifi_dut=self.wifi_dut,
                    m4_sleep_time=self.m4_sleep_time,
                )

            pm_obj = Power_Measurement_Thread(
                power_meter=self.power_meter,
                capture_time=self.capture_time,
                power_analyzer=self.power_analyzer,
            )

            if m4_obj is not None:
                m4_obj.start()
                time.sleep(2)

            pm_obj.start()
            time.sleep(2)

            uc_script = textwrap.dedent(
                f"""\
                import socket, time
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                dst = ("{self.device_ip}", {PORT})
                for seq in range(1, {PACKETS_PER_GROUP} + 1):
                    sock.sendto(b"UC|seq=%d" % seq, dst)
                    time.sleep(1.0 / {PPS})
                sock.close()
                print("Unicast burst completed")
                """
            )
            remote_path = "/tmp/ipv4_uc_burst.py"
            self.wifi_client.interfaces.wifi.shell.create_file(remote_path, uc_script)
            rc, stdout, stderr = self.wifi_client.interfaces.wifi.shell.execute(f"python3 {remote_path}")
            assert rc == 0, f"Unicast traffic generation failed: {stderr}"

            pm_obj.wait_for_exit()
            if m4_obj is not None:
                m4_obj.wait_for_exit()
            else:
                self.wifi_dut.interfaces.wifi.leave()
            traffic.leave()

    stdby_obj = UnicastMoreDataStandBy(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_client=wifi_client,
        sl_collections=sl_collections,
        power_meter=power_meter,
        power_analyzer=None,
    )
    _run_and_collect_power(stdby_obj, power_meter, request, performance_data, custom_performance_fixture)


@pytest.mark.transform_test_results(
    TransformFileProperties(file_name="perf_power_consumption_bc_mc_filter.csv", data_type="power_performance")
)
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config("wifi_dut", wifi=_common_dut_wifi_config())
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_client",
    wifi={
        "interface": "wlan0",
    },
)
def test_wlan_burst_bc_mc_idle_filter_disabled_c1818215(
    firmware_loader,
    power_meter,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    sl_collections,
    dtim,
    request,
    performance_data,
    custom_performance_fixture,
):
    """Wi-Fi: Burst BC/MC then idle (transient current) — MC/BC filter disabled."""
    stdby_obj = BcMcFilterStandBy(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_client=wifi_client,
        sl_collections=sl_collections,
        power_meter=power_meter,
        power_analyzer=None,
        enable_bcast_filter=0,
        enable_mcast_filter=0,
        filter_mode=0,
        allowlist_ips=[],
        send_broadcast=True,
        nonallow_streams=MC_ALLOWLIST_IPS[:2],  # still send MC; filter off so should wake
    )
    _run_and_collect_power(stdby_obj, power_meter, request, performance_data, custom_performance_fixture)


@pytest.mark.transform_test_results(
    TransformFileProperties(file_name="perf_power_consumption_bc_mc_filter.csv", data_type="power_performance")
)
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config("wifi_dut", wifi=_common_dut_wifi_config())
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_client",
    wifi={
        "interface": "wlan0",
    },
)
def test_wlan_burst_bc_mc_idle_filter_enabled_c1818216(
    firmware_loader,
    power_meter,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    sl_collections,
    dtim,
    request,
    performance_data,
    custom_performance_fixture,
):
    """Wi-Fi: Burst BC/MC then idle (transient current) — MC/BC filter enabled."""
    stdby_obj = BcMcFilterStandBy(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_client=wifi_client,
        sl_collections=sl_collections,
        power_meter=power_meter,
        power_analyzer=None,
        enable_bcast_filter=1,
        enable_mcast_filter=1,
        filter_mode=0,
        allowlist_ips=MC_ALLOWLIST_IPS[:2],
        send_broadcast=True,
        nonallow_streams=MC_NONALLOW_IPS,
    )
    _run_and_collect_power(stdby_obj, power_meter, request, performance_data, custom_performance_fixture)


@pytest.mark.transform_test_results(
    TransformFileProperties(file_name="perf_power_consumption_bc_mc_filter.csv", data_type="power_performance")
)
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.parametrize("filter_mode", [0, 1], ids=["default_mode", "conservative_mode"])
@pytest.mark.config("wifi_dut", wifi=_common_dut_wifi_config())
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_client",
    wifi={
        "interface": "wlan0",
    },
)
def test_wlan_sta_conservative_vs_default_filter_with_2_ips(
    firmware_loader,
    power_meter,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    sl_collections,
    dtim,
    filter_mode,
    request,
    performance_data,
    custom_performance_fixture,
):
    """STA connected: conservative vs default filtering modes (with 2 IPs)."""
    stdby_obj = BcMcFilterStandBy(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_client=wifi_client,
        sl_collections=sl_collections,
        power_meter=power_meter,
        power_analyzer=None,
        enable_bcast_filter=1,
        enable_mcast_filter=1,
        filter_mode=filter_mode,
        allowlist_ips=MC_ALLOWLIST_IPS[:2],  # exactly 2 IPs (PPE path for default)
        send_broadcast=True,
        nonallow_streams=MC_NONALLOW_IPS,
    )
    _run_and_collect_power(stdby_obj, power_meter, request, performance_data, custom_performance_fixture)


@pytest.mark.transform_test_results(
    TransformFileProperties(file_name="perf_power_consumption_bc_mc_filter.csv", data_type="power_performance")
)
@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config("wifi_dut", wifi=_common_dut_wifi_config())
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "11n", "security": "WPA2", "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_client",
    wifi={
        "interface": "wlan0",
    },
)
def test_wlan_sta_default_filter_mode_with_more_than_2_ips(
    firmware_loader,
    power_meter,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    sl_collections,
    dtim,
    request,
    performance_data,
    custom_performance_fixture,
):
    """STA connected default filtering mode (with more than 2 IPs) — NWP fallback path."""
    stdby_obj = BcMcFilterStandBy(
        dtim=dtim,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        wifi_client=wifi_client,
        sl_collections=sl_collections,
        power_meter=power_meter,
        power_analyzer=None,
        enable_bcast_filter=1,
        enable_mcast_filter=1,
        filter_mode=0,  # default; >2 IPs falls back to NWP SW
        allowlist_ips=MC_ALLOWLIST_IPS[:6],  # 6 IPs
        send_broadcast=True,
        nonallow_streams=MC_NONALLOW_IPS,
    )
    _run_and_collect_power(stdby_obj, power_meter, request, performance_data, custom_performance_fixture)
