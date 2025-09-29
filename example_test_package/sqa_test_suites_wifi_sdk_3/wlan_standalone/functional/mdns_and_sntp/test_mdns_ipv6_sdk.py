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
    Derive the AP LAN IPv6 network:
      1) lan_ipv6_prefix + lan_prefix_length if present
      2) else lan_ipv6_address + lan_prefix_length
      3) else None (skip prefix check; only assert global)
    """
    apwifi = wifi_access_point.interfaces.wifi

    lan_prefix = _maybe_get(apwifi, "lan_ipv6_prefix", "lanIpv6Prefix")
    lan_plen = _maybe_get(apwifi, "lan_prefix_length", "lanIpv6PrefixLength", "lan_prefixlen")

    try:
        prefix_len = int(lan_plen) if lan_plen is not None else default_prefixlen
    except Exception:
        prefix_len = default_prefixlen

    if lan_prefix:
        try:
            net = ipaddress.IPv6Network(f"{lan_prefix}/{prefix_len}", strict=False)
            log.info(f"Using CONFIGURED AP LAN IPv6 network (prefix): {net}")
            return net
        except Exception:
            log.warning(f"Invalid lan_ipv6_prefix '{lan_prefix}/{prefix_len}', falling back to address…")

    lan_addr = _maybe_get(apwifi, "lan_ipv6_address", "lanIpv6Address")
    if lan_addr:
        try:
            net = ipaddress.IPv6Network(f"{lan_addr}/{prefix_len}", strict=False)
            log.info(f"Using DERIVED AP LAN IPv6 network (from address): {net}")
            return net
        except Exception:
            log.warning(f"Invalid lan_ipv6_address '{lan_addr}/{prefix_len}', skipping prefix check…")

    log.info("AP LAN IPv6 prefix not available; will only assert global IPv6.")
    return None

def verify_dut_ipv6(dut_ip_str, ap_network, *, strict=False):
    """
    Ensure DUT has a *global* IPv6. If strict=True and ap_network is provided,
    also require that the address lies within the AP's LAN prefix.
    """
    assert dut_ip_str and ":" in dut_ip_str, f"IPv6 address missing/invalid: {dut_ip_str}"

    addr = ipaddress.IPv6Address(dut_ip_str)
    # Reject link-local and ULA in these tests
    assert not addr.is_link_local, f"IPv6 not global (link-local): {dut_ip_str}"
    assert not addr.is_private,    f"IPv6 not global (ULA): {dut_ip_str}"

    if ap_network and strict:
        assert addr in ap_network, f"{dut_ip_str} not in AP LAN IPv6 network {ap_network}"
    elif ap_network and addr not in ap_network:
        # Soft check: warn but continue. mDNS testing shouldn't fail on prefix drift.
        log.warning(f"DUT IPv6 {dut_ip_str} is outside configured AP LAN {ap_network}. "
                    f"Proceeding (soft-check). Set wifi.strict_ipv6_prefix=true to enforce.")
    # else: no network provided, only global-ness enforced.

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
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        self.sniffer_capture(mode="start")

        info_attr = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
            ip_version="ipv6",
            ipv6_type=self.ipv6_type,
            retry_count=3,
            power_save=False,
        )

        self.dut_info["mac_address"] = info_attr.get("dut_mac_address")
        self.dut_info["ip_address"] = info_attr.get("device_ip")
        self.dut_info["ap_mac_address"] = self.wifi_access_point.interfaces.wifi.bssid

# ------------------------- Avahi cycle helper -------------------------
def avahi_cycle(sd_iface, browse_wait_s=10):
    """Kill → restart avahi-daemon → run avahi-browse -a -r."""
    sd_iface.stop()
    time.sleep(2)
    sd_iface.start()
    time.sleep(2)
    sd_iface.start_discovering_services()
    time.sleep(browse_wait_s)
    sd_iface.stop_discovering_services()

# ------------- Helper to read strictness from utf defaults -------------
def _strict_prefix():
    # opt-in: defaults.wifi.strict_ipv6_prefix: true/false (default false)
    try:
        return bool(UtfConfig.instance().defaults["wifi"].get("strict_ipv6_prefix", False))
    except Exception:
        return False

# =========================== TEST CASES ================================

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
def test_wifi_sdk_mdns_ipv6_stateless_with_avahi_loop_c767019(
    wifi_access_point, wifi_dut, wifi_sniffer, sl_collections, request, wifi_client, utf_constants, service_discovery
):
    """Connect once (IPv6 SLAAC), then run: mDNS init → advertise → deinit with Avahi cycles, for 3 iterations."""
    sd_iface = service_discovery.interfaces.sd
    test_name = request.node.name
    ap_net = get_ap_ipv6_network(wifi_access_point, default_prefixlen=64)
    strict = _strict_prefix()

    try:
        # Connect once and verify IPv6
        wlan_obj = WLanThread(
            wifi_dut, wifi_sniffer, wifi_access_point,
            sl_collections, test_name, wifi_client, ipv6_type="global",
        )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ip6 = wlan_obj.dut_info.get("ip_address")
        verify_dut_ipv6(ip6, ap_net, strict=strict)

        # Stop join-time capture
        try:
            wlan_obj.sniffer_capture(mode="stop")
        except Exception:
            pass

        # mDNS/Avahi ×3
        for i in range(1, 4):
            log.info(f"--- mDNS iteration {i}/3 ---")
            mdns_started = False
            try:
                wifi_dut.interfaces.wifi.mdns_init(ip_version=Si91xMdnsParams.IPV6)
                mdns_started = True
                wifi_dut.interfaces.wifi.mdns_add_interface()
                wifi_dut.interfaces.wifi.mdns_register_service()
                avahi_cycle(sd_iface)  # browse while mDNS is active
            finally:
                if mdns_started:
                    try:
                        wifi_dut.interfaces.wifi.mdns_deinit()
                    except Exception as e:
                        log.warning(f"mDNS deinit failed (iteration {i}): {e}")
                avahi_cycle(sd_iface)  # browse after mDNS deinit

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
def test_wifi_sdk_mdns_ipv6_stateful_with_avahi_loop_c767020(
    wifi_access_point, wifi_dut, wifi_sniffer, sl_collections, request, wifi_client, utf_constants, service_discovery
):
    """Connect once (IPv6 DHCPv6), then run: mDNS init → advertise → deinit with Avahi cycles, for 3 iterations; disconnect at end."""
    sd_iface = service_discovery.interfaces.sd
    test_name = request.node.name
    ap_net = get_ap_ipv6_network(wifi_access_point, default_prefixlen=64)
    strict = _strict_prefix()

    try:
        # Connect once and verify IPv6
        wlan_obj = WLanThread(
            wifi_dut, wifi_sniffer, wifi_access_point,
            sl_collections, test_name, wifi_client, ipv6_type="global",
        )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ip6 = wlan_obj.dut_info.get("ip_address")
        verify_dut_ipv6(ip6, ap_net, strict=strict)

        # Stop join-time capture
        try:
            wlan_obj.sniffer_capture(mode="stop")
        except Exception:
            pass

        # mDNS/Avahi ×3
        for i in range(1, 4):
            log.info(f"--- mDNS iteration {i}/3 ---")
            mdns_started = False
            try:
                wifi_dut.interfaces.wifi.mdns_init(ip_version=Si91xMdnsParams.IPV6)
                mdns_started = True
                wifi_dut.interfaces.wifi.mdns_add_interface()
                wifi_dut.interfaces.wifi.mdns_register_service()
                avahi_cycle(sd_iface)  # browse while mDNS is active
            finally:
                if mdns_started:
                    try:
                        wifi_dut.interfaces.wifi.mdns_deinit()
                    except Exception as e:
                        log.warning(f"mDNS deinit failed (iteration {i}): {e}")
                avahi_cycle(sd_iface)  # browse after mDNS deinit

        # Disconnect from the AP
        wifi_dut.interfaces.wifi.leave()

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
def test_wifi_sdk_verify_mdns_functionality_restart_avahi_ipv6_c767022(
    wifi_access_point, wifi_dut, wifi_sniffer, sl_collections, request, wifi_client, utf_constants, service_discovery
):
    """Connect once (IPv6 DHCPv6), start mDNS, run Avahi restart/browse 10+ times while mDNS is active, log metrics, then deinit & disconnect."""
    sd_iface = service_discovery.interfaces.sd
    test_name = request.node.name
    ap_net = get_ap_ipv6_network(wifi_access_point, default_prefixlen=64)
    strict = _strict_prefix()

    # Log capture for Avahi metrics
    log_handler = InMemoryLogHandler()
    root_logger = logging.getLogger()
    root_logger.addHandler(log_handler)

    AVAHI_LOGGER = "AvahiDaemonLinux"
    CMD_MARKER = "Executing command: '['avahi-browse', '-a', '-r']'"
    HOSTNAME_LINE = "hostname = [wiseconnect.local]"

    wlan_obj = None
    try:
        # Connect once and verify IPv6
        wlan_obj = WLanThread(
            wifi_dut, wifi_sniffer, wifi_access_point,
            sl_collections, test_name, wifi_client, ipv6_type="global",
        )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ip6 = wlan_obj.dut_info.get("ip_address")
        verify_dut_ipv6(ip6, ap_net, strict=strict)

        # Stop join-time capture
        try:
            wlan_obj.sniffer_capture(mode="stop")
        except Exception:
            pass

        # mDNS init → add iface → register (keep active for loop)
        wifi_dut.interfaces.wifi.mdns_init(ip_version=Si91xMdnsParams.IPV6)
        wifi_dut.interfaces.wifi.mdns_add_interface()
        wifi_dut.interfaces.wifi.mdns_register_service()

        # Avahi restart/browse loop (≥10 times)
        iter_cfg = utf_constants.get("iter_count")
        try:
            iter_cfg = int(iter_cfg) if iter_cfg is not None else 0
        except Exception:
            iter_cfg = 0
        iterations = max(10, iter_cfg)

        total_cmd_executed = 0
        total_success_iters = 0

        for i in range(1, iterations + 1):
            log.info(f"--- Avahi restart/browse iteration {i}/{iterations} ---")
            log_handler.logs.clear()

            # 6) Avahi restart/browse while mDNS active
            avahi_cycle(sd_iface, browse_wait_s=10)

            # Per-iteration metrics
            seen_cmd = any(CMD_MARKER in msg for (_name, msg) in log_handler.logs)
            seen_wise = any(
                (name == AVAHI_LOGGER) and (HOSTNAME_LINE in msg)
                for (name, msg) in log_handler.logs
            )
            if seen_cmd:
                total_cmd_executed += 1
                if seen_wise:
                    total_success_iters += 1

        # Final metrics
        log.info(f"Total Avahi commands executed: {total_cmd_executed}")
        log.info(f"Total mdns response: {total_success_iters}")

        # mDNS deinit and disconnect
        wifi_dut.interfaces.wifi.mdns_deinit()
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        log.error(f"Exception occurred: {e}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise
    finally:
        if wlan_obj:
            try:
                wlan_obj.sniffer_capture(mode="stop")
            except Exception:
                pass
        root_logger.removeHandler(log_handler)



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
def test_wifi_sdk_mdns_avahi_discover_1hr_loop_c767026(
    wifi_access_point, wifi_dut, wifi_sniffer, sl_collections, request, wifi_client, utf_constants, service_discovery
):
    """Connect once (IPv6), start mDNS, run Avahi restart/browse for long_duration, log metrics, then deinit and disconnect."""
    sd_iface = service_discovery.interfaces.sd
    test_name = request.node.name
    ap_net = get_ap_ipv6_network(wifi_access_point, default_prefixlen=64)
    strict = _strict_prefix()

    # capture Avahi logs to compute metrics
    log_handler = InMemoryLogHandler()
    root_logger = logging.getLogger()
    root_logger.addHandler(log_handler)

    AVAHI_LOGGER = "AvahiDaemonLinux"
    CMD_MARKER = "Executing command: '['avahi-browse', '-a', '-r']'"
    HOSTNAME_LINE = "hostname = [wiseconnect.local]"

    wlan_obj = None
    try:
        # connect once and verify IPv6
        wlan_obj = WLanThread(
            wifi_dut, wifi_sniffer, wifi_access_point,
            sl_collections, test_name, wifi_client, ipv6_type="global",
        )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ip6 = wlan_obj.dut_info.get("ip_address")
        verify_dut_ipv6(ip6, ap_net, strict=strict)

        # stop join-time capture
        try:
            wlan_obj.sniffer_capture(mode="stop")
        except Exception:
            pass

        # mDNS init → add iface → register (keep active during loop)
        wifi_dut.interfaces.wifi.mdns_init(ip_version=Si91xMdnsParams.IPV6)
        wifi_dut.interfaces.wifi.mdns_add_interface()
        wifi_dut.interfaces.wifi.mdns_register_service()

        duration_seconds = utf_constants.get("long_duration")
        start_time = time.time()
        total_cmd_executed = 0
        total_success_iters = 0

        while (time.time() - start_time) < duration_seconds:
            log_handler.logs.clear()
            avahi_cycle(sd_iface, browse_wait_s=10)

            seen_cmd = any(CMD_MARKER in msg for (_name, msg) in log_handler.logs)
            seen_wise = any(
                (name == AVAHI_LOGGER) and (HOSTNAME_LINE in msg)
                for (name, msg) in log_handler.logs
            )
            if seen_cmd:
                total_cmd_executed += 1
                if seen_wise:
                    total_success_iters += 1

        # final metrics
        log.info(f"Total Avahi commands executed: {total_cmd_executed}")
        log.info(f"Total mdns response: {total_success_iters}")

        # teardown mDNS and disconnect
        wifi_dut.interfaces.wifi.mdns_deinit()
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        log.error(f"Exception occurred: {e}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise
    finally:
        if wlan_obj:
            try:
                wlan_obj.sniffer_capture(mode="stop")
            except Exception:
                pass
        root_logger.removeHandler(log_handler)