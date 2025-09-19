import collections
import pytest
import logging
import time
import ipaddress
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xMdnsParams,
)

log = get_logger(__name__)

WIFI_DUT_CFG = {
    "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    "oper_mode": 0,
    "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
    "features": (
        Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation
        | Si91xFeatureBitMap.OpenMode
    ),
    "tcpip_features": (
        Si91xTCPIPFeatureBitMap.Default
        | Si91xTCPIPFeatureBitMap.DHCPv6Client
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
        | Si91xTCPIPFeatureBitMap.IPv6Mode
        | Si91xTCPIPFeatureBitMap.mDNS
    ),
    "config_features": (
        Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp
    ),
    "ext_custom_features": (
        Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
    ),
    "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
}

# ------------------------- AP IPv6 prefix helpers -------------------------

def _maybe_get(obj, *names):
    """Safely try multiple attribute names, returning the first non-empty string."""
    for n in names:
        if hasattr(obj, n):
            val = getattr(obj, n)
            if isinstance(val, str) and val.strip():
                return val.strip()
    return None

def get_ap_ipv6_network(wifi_access_point, default_prefixlen=64):
    """
    Try to derive the AP LAN IPv6 network:
      1) Use lan_ipv6_prefix + lan_prefix_length if present
      2) Else use lan_ipv6_address + lan_prefix_length
      3) Else return None (we'll skip prefix check and only assert global)
    """
    apwifi = wifi_access_point.interfaces.wifi

    # Try explicit LAN prefix
    lan_prefix = _maybe_get(apwifi, "lan_ipv6_prefix", "lanIpv6Prefix")
    # Try prefix length
    lan_plen = _maybe_get(apwifi, "lan_prefix_length", "lanIpv6PrefixLength", "lan_prefixlen")
    try:
        prefix_len = int(lan_plen) if lan_plen is not None else default_prefixlen
    except Exception:
        prefix_len = default_prefixlen

    if lan_prefix:
        try:
            return ipaddress.IPv6Network(f"{lan_prefix}/{prefix_len}", strict=False)
        except Exception:
            pass

    # Fall back to LAN address + length
    lan_addr = _maybe_get(apwifi, "lan_ipv6_address", "lanIpv6Address")
    if lan_addr:
        try:
            return ipaddress.IPv6Network(f"{lan_addr}/{prefix_len}", strict=False)
        except Exception:
            pass

    log.info("AP LAN IPv6 prefix not available; will only assert global IPv6.")
    return None

def assert_dut_ipv6_in_ap_network(dut_ip_str, ap_network):
    """Assert the DUT global IPv6 is inside the AP network"""
    assert dut_ip_str and ":" in dut_ip_str and not dut_ip_str.lower().startswith("fe80:"), f"IPv6 not global: {dut_ip_str}"
    if ap_network:
        dut_ip = ipaddress.IPv6Address(dut_ip_str)
        assert dut_ip in ap_network, f"{dut_ip_str} not in AP LAN IPv6 network {ap_network}"

class InMemoryLogHandler(logging.Handler):
    def __init__(self, level=logging.DEBUG):
        super().__init__(level)
        self.logs = []  # list of (logger_name, message)

    def emit(self, record):
        try:
            self.logs.append((record.name, record.getMessage()))
        except Exception:
            pass

class WLanThread(ThreadBase):
    """Configure sniffer, start capture, and join Wi-Fi with IPv6."""
    dut_info = {"mac_address": None, "ip_address": None, "ap_mac_address": None}

    def __init__(self, wifi_dut, wifi_sniffer, wifi_access_point, sl_collections, test_name, wifi_client=None,
                 ipv6_type="global"):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_sniffer = wifi_sniffer
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.ipv6_type = ipv6_type
        self._logger = log
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        self._logger.info(f"in harness power_save flag set to: {self.power_save}")

    def sniffer_capture(self, mode: str):
        if mode == "start":
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
        else:
            self.wifi_sniffer.interfaces.capture.stop_capture()

    def run(self):
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.sniffer_capture(mode="start")

        info_attr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                                             associated=self.wifi_dut.interfaces.wifi.associated, ip_version="ipv6",
                                                             ipv6_type=self.ipv6_type, retry_count=3, power_save=False)

        self.dut_info["mac_address"] = info_attr.get("dut_mac_address")
        self.dut_info["ip_address"] = info_attr.get("device_ip")
        self.dut_info["ap_mac_address"] = self.wifi_access_point.interfaces.wifi.bssid

# ------------------------- Avahi cycle helper -------------------------
def avahi_cycle(sd_iface, browse_wait_s=10):
    """
    Kill → restart avahi-daemon → run avahi-browse -a -r
    using the existing AvahiDaemonLinux methods.
    """
    sd_iface.stop()                        # avahi-daemon --kill
    time.sleep(2)
    sd_iface.start()                       # sudo avahi-daemon --daemonize
    time.sleep(2)
    sd_iface.start_discovering_services()  # avahi-browse -a -r
    time.sleep(browse_wait_s)
    sd_iface.stop_discovering_services()


@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "enable_ipv6": True,
        "connection_type": "STATIC_IPV6",
        "wan_ipv6_address": "2404:1343:1234:7785:1134:331:243:2221",
        "wan_ipv6_gateway": "2404:1343:1234:7785::1",
        "wan_prefix_length": "64",
        "ipv6_state": "0",  # Stateless (SLAAC)
        "lan_ipv6_address": "2401:2334:1234:1356:7785:1234:1134:3321",
        "lan_prefix_length": "64",
        "lan_ipv6_prefix": "2401:2334:1234:1356::",
    },
)
@pytest.mark.config("wifi_dut", wifi=WIFI_DUT_CFG)
@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_mdns_ipv6_stateless_with_avahi_loop_c767019(wifi_access_point, wifi_dut, wifi_sniffer, sl_collections,
                                                              request, wifi_client, utf_constants, service_discovery):
    """Verify MDNS Initialization, MDNS Service Advertisement,
    MDNS de-Initialization in loop (With IPv6 stateless configuration)"""
    sd_iface = service_discovery.interfaces.sd
    test_name = request.node.name
    ap_net = get_ap_ipv6_network(wifi_access_point, default_prefixlen=64)

    try:
        for i in range(utf_constants.get("iter_count")):
            log.info(f"--- Stateless Iteration {i+1} ---")
            wlan_obj = WLanThread(
                wifi_dut, wifi_sniffer, wifi_access_point,
                sl_collections, test_name, wifi_client,
                ipv6_type="global",
            )
            try:
                # 1) Connect (SLAAC global IPv6 expected)
                wlan_obj.start()
                wlan_obj.wait_for_exit()
                ip6 = wlan_obj.dut_info.get("ip_address")
                assert_dut_ipv6_in_ap_network(ip6, ap_net)

                # 2) Power save (best-effort)
                if hasattr(wifi_dut.interfaces.wifi, "wifi_powersave_enable"):
                    wifi_dut.interfaces.wifi.wifi_powersave_enable()

                # 3–5) mDNS IPv6 init → add iface → register service(s)
                wifi_dut.interfaces.wifi.mdns_init(ip_version=Si91xMdnsParams.IPV6)
                wifi_dut.interfaces.wifi.mdns_add_interface()
                wifi_dut.interfaces.wifi.mdns_register_service()

                # 6) Avahi browse cycle while mDNS is active
                avahi_cycle(sd_iface)

                # 7) mDNS deinit
                wifi_dut.interfaces.wifi.mdns_deinit()

                # 8) Avahi browse cycle after mDNS deinit
                avahi_cycle(sd_iface)

                # 9) Disconnect
                wifi_dut.interfaces.wifi.leave()

                # Optional: disable power save explicitly
                if hasattr(wifi_dut.interfaces.wifi, "wifi_powersave_disable"):
                    wifi_dut.interfaces.wifi.wifi_powersave_disable()

            finally:
                try:
                    wlan_obj.sniffer_capture(mode="stop")
                except Exception:
                    pass

    except Exception as e:
        log.error(f"Exception occurred: {e}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise


@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "enable_ipv6": True,
        "connection_type": "STATIC_IPV6",
        "wan_ipv6_address": "2404:1343:1234:7785:1134:331:243:2221",
        "wan_ipv6_gateway": "2404:1343:1234:7785::1",
        "wan_prefix_length": "64",
        "ipv6_state": "1",  # Stateful (DHCPv6)
        "lan_ipv6_address": "2401:2334:1234:1356:7785:1234:1134:3321",
        "lan_prefix_length": "64",
        "lan_ipv6_prefix": "2401:2334:1234:1356::",
        "lan_ip_pool_start": "2401:2334:1234:1356::1000",
        "lan_ip_pool_end":   "2401:2334:1234:1356::2000",
    },
)
@pytest.mark.config("wifi_dut", wifi=WIFI_DUT_CFG)
@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_mdns_ipv6_stateful_with_avahi_loop_c767020(wifi_access_point, wifi_dut, wifi_sniffer, sl_collections,
                                                             request, wifi_client, utf_constants, service_discovery):
    """Verify WLAN connection, MDNS Initialization, MDNS Service Advertisement, MDNS de-Initialization,
       WLAN disconnection in loop (With IPv6 stateful configuration)"""
    sd_iface = service_discovery.interfaces.sd
    test_name = request.node.name
    ap_net = get_ap_ipv6_network(wifi_access_point, default_prefixlen=64)

    try:
        for i in range(utf_constants.get("iter_count")):
            log.info(f"--- Stateful Iteration {i+1} ---")
            wlan_obj = WLanThread(
                wifi_dut, wifi_sniffer, wifi_access_point,
                sl_collections, test_name, wifi_client,
                ipv6_type="global",
            )
            try:
                # 1) Connect (DHCPv6 global IPv6 expected)
                wlan_obj.start()
                wlan_obj.wait_for_exit()
                ip6 = wlan_obj.dut_info.get("ip_address")
                assert_dut_ipv6_in_ap_network(ip6, ap_net)

                # 2) Power save (best-effort)
                if hasattr(wifi_dut.interfaces.wifi, "wifi_powersave_enable"):
                    wifi_dut.interfaces.wifi.wifi_powersave_enable()

                # 3–5) mDNS IPv6 init → add iface → register service(s)
                wifi_dut.interfaces.wifi.mdns_init(ip_version=Si91xMdnsParams.IPV6)
                wifi_dut.interfaces.wifi.mdns_add_interface()
                wifi_dut.interfaces.wifi.mdns_register_service()

                # 6) Avahi browse cycle while mDNS is active
                avahi_cycle(sd_iface)

                # 7) mDNS deinit
                wifi_dut.interfaces.wifi.mdns_deinit()

                # 8) Avahi browse cycle after mDNS deinit
                avahi_cycle(sd_iface)

                # 9) Disconnect
                wifi_dut.interfaces.wifi.leave()

                # Optional: disable power save explicitly
                if hasattr(wifi_dut.interfaces.wifi, "wifi_powersave_disable"):
                    wifi_dut.interfaces.wifi.wifi_powersave_disable()

            finally:
                try:
                    wlan_obj.sniffer_capture(mode="stop")
                except Exception:
                    pass

    except Exception as e:
        log.error(f"Exception occurred: {e}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise


@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "enable_ipv6": True,
        "connection_type": "STATIC_IPV6",
        "wan_ipv6_address": "2404:1343:1234:7785:1134:331:243:2221",
        "wan_ipv6_gateway": "2404:1343:1234:7785::1",
        "wan_prefix_length": "64",
        "ipv6_state": "1",  # Stateful (DHCPv6)
        "lan_ipv6_address": "2401:2334:1234:1356:7785:1234:1134:3321",
        "lan_prefix_length": "64",
        "lan_ipv6_prefix": "2401:2334:1234:1356::",
        "lan_ip_pool_start": "2401:2334:1234:1356::1000",
        "lan_ip_pool_end":   "2401:2334:1234:1356::2000",
    },
)
@pytest.mark.config("wifi_dut", wifi=WIFI_DUT_CFG)
@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_verify_mdns_functionality_restart_avahi_ipv6_c767022(wifi_access_point, wifi_dut, wifi_sniffer, sl_collections,
                                                                       request, wifi_client, utf_constants, service_discovery):
    """
    Verify MDNS functionality by killing and restarting the Avahi browser from the remote side.

    Steps per iteration:
      1) Connect to AP with IPv6
      2) Power save
      3) Initialize MDNS service
      4) Add an interface to MDNS instance
      5) Register a service (HTTP/FTP/etc.)
      6) Avahi: kill/restart/browse (discover services)
      7) Deinitialize MDNS service
      8) Avahi: kill/restart/browse (discover services)
      9) Disconnect from AP
    """
    sd_iface = service_discovery.interfaces.sd
    test_name = request.node.name
    ap_net = get_ap_ipv6_network(wifi_access_point, default_prefixlen=64)

    try:
        for i in range(utf_constants.get("iter_count")):
            log.info(f"--- Restart-Avahi Iteration {i+1} ---")
            wlan_obj = WLanThread(
                wifi_dut, wifi_sniffer, wifi_access_point,
                sl_collections, test_name, wifi_client,
                ipv6_type="global",
            )
            try:
                # 1) Connect (global IPv6 expected)
                wlan_obj.start()
                wlan_obj.wait_for_exit()
                ip6 = wlan_obj.dut_info.get("ip_address")
                assert_dut_ipv6_in_ap_network(ip6, ap_net)

                # 2) Power save (best-effort)
                if hasattr(wifi_dut.interfaces.wifi, "wifi_powersave_enable"):
                    wifi_dut.interfaces.wifi.wifi_powersave_enable()

                # 3–5) mDNS IPv6 init → add iface → register service(s)
                wifi_dut.interfaces.wifi.mdns_init(ip_version=Si91xMdnsParams.IPV6)
                wifi_dut.interfaces.wifi.mdns_add_interface()
                wifi_dut.interfaces.wifi.mdns_register_service()

                # 6) Avahi restart/browse while mDNS active
                avahi_cycle(sd_iface, browse_wait_s=10)

                # 7) mDNS deinit
                wifi_dut.interfaces.wifi.mdns_deinit()

                # 8) Avahi restart/browse after mDNS deinit
                avahi_cycle(sd_iface, browse_wait_s=10)

                # 9) Disconnect
                wifi_dut.interfaces.wifi.leave()

                # Optional: disable power save explicitly
                if hasattr(wifi_dut.interfaces.wifi, "wifi_powersave_disable"):
                    wifi_dut.interfaces.wifi.wifi_powersave_disable()

            finally:
                # Always stop sniffer even if iteration fails mid-way
                try:
                    wlan_obj.sniffer_capture(mode="stop")
                except Exception:
                    pass

    except Exception as e:
        log.error(f"Exception occurred: {e}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise


@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "enable_ipv6": True,
        "connection_type": "STATIC_IPV6",
        "wan_ipv6_address": "2404:1343:1234:7785:1134:331:243:2221",
        "wan_ipv6_gateway": "2404:1343:1234:7785::1",
        "wan_prefix_length": "64",
        "ipv6_state": "1",
        "lan_ipv6_address": "2401:2334:1234:1356:7785:1234:1134:3321",
        "lan_prefix_length": "64",
        "lan_ipv6_prefix": "2401:2334:1234:1356::",
        "lan_ip_pool_start": "2401:2334:1234:1356::1000",
        "lan_ip_pool_end":   "2401:2334:1234:1356::2000",
    },
)
@pytest.mark.config("wifi_dut", wifi=WIFI_DUT_CFG)
@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_mdns_avahi_discover_1hr_loop_c767026(wifi_access_point, wifi_dut, wifi_sniffer, sl_collections,
                                                       request, wifi_client, utf_constants, service_discovery):
    """
    Verify mDNS IPv6 functionality when multiple mDNS queries are sent to the DUT.

    Pass criteria:
      - Count how many Avahi discovery command iterations actually ran.
      - Count how many of those iterations reported at least one
        "hostname = [wiseconnect.local]" line from the Avahi daemon.

    High-level steps:
      1) Connect DUT to the IPv6-enabled AP.
      2) Enable Wi-Fi power save (if supported).
      3) Initialize the mDNS service (IPv6).
      4) Add the network interface to the mDNS instance.
      5) Register an mDNS service on the DUT.
      6) For the configured duration (e.g., ~1 hour via utf_constants["long_duration"]):
         - Stop/start the service discovery helper.
         - Start/stop active discovery and capture logs for each iteration.
      7) Deinitialize the mDNS service.
      8) Disconnect and restore DUT power-save state.

    """
    sd_iface = service_discovery.interfaces.sd
    test_name = request.node.name
    ap_net = get_ap_ipv6_network(wifi_access_point, default_prefixlen=64)
    wlan_obj = None

    # Capture all logs as (logger_name, message) tuples; independent of global formatters.
    log_handler = InMemoryLogHandler()
    root_logger = logging.getLogger()
    root_logger.addHandler(log_handler)

    AVAHI_LOGGER = "AvahiDaemonLinux"
    CMD_MARKER = "Executing command: '['avahi-browse', '-a', '-r']'"
    HOSTNAME_LINE = "hostname = [wiseconnect.local]"

    try:
        # Bring up Wi-Fi and obtain a global IPv6; verifying it sits within the AP's IPv6 network.
        wlan_obj = WLanThread(wifi_dut, wifi_sniffer, wifi_access_point, sl_collections, test_name, wifi_client, ipv6_type="global")
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ip6 = wlan_obj.dut_info.get("ip_address")
        assert_dut_ipv6_in_ap_network(ip6, ap_net)

        # enabling power save.
        if hasattr(wifi_dut.interfaces.wifi, "wifi_powersave_enable"):
            wifi_dut.interfaces.wifi.wifi_powersave_enable()

        # Initialize and advertise mDNS (IPv6).
        wifi_dut.interfaces.wifi.mdns_init(ip_version=Si91xMdnsParams.IPV6)
        wifi_dut.interfaces.wifi.mdns_add_interface()
        wifi_dut.interfaces.wifi.mdns_register_service()

        # Main discovery loop: run for the configured duration and score each iteration.
        duration_seconds = utf_constants.get("long_duration")
        start_time = time.time()
        total_cmd_executed = 0           # iterations where the Avahi command line was seen
        total_success_iters = 0          # iterations with >=1 "wiseconnect.local" hostname

        while (time.time() - start_time) < duration_seconds:
            # Work on a clean slate each iteration.
            log_handler.logs.clear()

            # Bounce the helper and perform a short active discovery round.
            sd_iface.stop()
            time.sleep(2)
            sd_iface.start()
            time.sleep(2)
            sd_iface.start_discovering_services()
            time.sleep(10)
            sd_iface.stop_discovering_services()

            # Classifying the iteration based on captured logs.
            seen_cmd = any(CMD_MARKER in msg for (_name, msg) in log_handler.logs)
            seen_wise = any(
                (name == AVAHI_LOGGER) and (HOSTNAME_LINE in msg)
                for (name, msg) in log_handler.logs
            )

            if seen_cmd:
                total_cmd_executed += 1
                if seen_wise:
                    # Count per iteration.
                    total_success_iters += 1

        # Final metrics.
        log.info(f"Total Avahi commands executed: {total_cmd_executed}")
        log.info(f"Total mdns response: {total_success_iters}")

        wifi_dut.interfaces.wifi.mdns_deinit()
        wifi_dut.interfaces.wifi.leave()
        if hasattr(wifi_dut.interfaces.wifi, "wifi_powersave_disable"):
            wifi_dut.interfaces.wifi.wifi_powersave_disable()

    finally:
        if wlan_obj:
            try:
                wlan_obj.sniffer_capture(mode="stop")
            except Exception:
                pass
        root_logger.removeHandler(log_handler)
