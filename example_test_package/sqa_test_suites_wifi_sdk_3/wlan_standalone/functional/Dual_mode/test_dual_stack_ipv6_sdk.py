"""
WLAN_IPv6_DUAL_STACK automation for NWP offload + lwIP dual-network-stack mode.

Contains the automatable TestRail cases C793948, C793950, C793952,
C793957, and C793967.
In this framework the NWP offload stack is the firmware network stack (NetX-equivalent);
lwIP is the host/external stack enabled via sl_net_init_client.

Coverage areas:
  - IPv6 dual-stack bring-up and ICMPv6
  - DNS A/AAAA and mDNS on the NWP offload stack
  - TCP Tx over IPv6 on the NWP offload stack
"""

import ipaddress
import random
import socket
import threading
import time

import pytest

from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xBSDSocketParams,
    Si91xCoexMode,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xMdnsParams,
    Si91xOperatingMode,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
)
DOMAIN_NAME_AAAA = "www.google.com"
IPV6_PROTOCOL_FAMILY = Si91xBSDSocketParams.AF_INET6
IPV4_PROTOCOL_FAMILY = Si91xBSDSocketParams.AF_INET
IPPROTO_TCP = Si91xBSDSocketParams.IPPROTO_TCP
IPPROTO_UDP = Si91xBSDSocketParams.IPPROTO_UDP
SOCK_STREAM = Si91xBSDSocketParams.SOCK_STREAM
SOCK_DGRAM = Si91xBSDSocketParams.SOCK_DGRAM
NWP_IPERF_PORT = 5001
LWIP_IPERF_PORT = 5002

_MAP_SECURITY = {
    "OPEN": 0,
    "WPA": 1,
    "WPA2": 2,
    "WEP": 3,
    "WPAENTERPRISE": 4,
    "WPA2ENTERPRISE": 5,
    "WPA_WPA2_MIXED": 6,
    "WPA3": 7,
    "WPA3_TRANSITION": 8,
    "WPA3ENTERPRISE": 9,
    "WPA3_TRANSITION_ENTERPRISE": 10,
}


def logger():
    return get_logger(__name__)


def random_ipv6_addr(prefix: str) -> str:
    if "/" in prefix:
        prefix = prefix.split("/")[0]
    network = ipaddress.IPv6Network(f"{prefix}/64", strict=False)
    full_ip_int = int(network.network_address) | random.getrandbits(64)
    return str(ipaddress.IPv6Address(full_ip_int))


wan_ipv6_addr = random_ipv6_addr("2001:db8:abcd:0012::")
wan_gateway = "2001:db8:abcd:0012::1"

STATELESS_AP_IPV6 = {
    "security": "WPA2",
    "passphrase": "231469460",
    "ipv6_state": "0",
    "wan_ipv6_address": wan_ipv6_addr,
    "wan_ipv6_gateway": wan_gateway,
}


def _decode_cli_output(value):
    if isinstance(value, bytes):
        return value.decode()
    return str(value)


def _normalize_ipv6_addr(value):
    return str(ipaddress.IPv6Address(_decode_cli_output(value).strip()))


def _resolve_host_aaaa_records(domain_name):
    records = set()
    for entry in socket.getaddrinfo(domain_name, None, socket.AF_INET6):
        records.add(_normalize_ipv6_addr(entry[4][0]))
    assert records, f"No IPv6 AAAA records found for {domain_name}"
    return records


def _global_ipv6_from_config(ip_config):
    if isinstance(ip_config, tuple):
        return ip_config[1]
    if hasattr(ip_config, "ip"):
        return ip_config.ip.decode()
    return str(ip_config)


def _is_valid_global_ipv6(addr):
    if not addr or not str(addr).strip():
        return False
    try:
        parsed = ipaddress.IPv6Address(str(addr).split("%")[0].strip())
        return not parsed.is_link_local and not parsed.is_unspecified
    except ValueError:
        return False


def _tshark_mac(mac):
    return mac.replace("-", ":").lower()


def _avahi_cycle(sd_iface, browse_wait_s=10):
    sd_iface.stop()
    time.sleep(2)
    sd_iface.start()
    time.sleep(2)
    sd_iface.start_discovering_services()
    time.sleep(browse_wait_s)
    sd_iface.stop_discovering_services()


def _is_tcp(protocol):
    return protocol == IperfConstants.TCP


def wifi_dut_marker_ipv6(
    tcp_feat_bit=0,
    include_dhcpv6=True,
    include_mdns=False,
):
    tcpip = (
        Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
        | Si91xTCPIPFeatureBitMap.IPv6Mode
        | tcp_feat_bit
    )
    if include_dhcpv6:
        tcpip |= Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
    if include_mdns:
        tcpip |= Si91xTCPIPFeatureBitMap.mDNS

    config = {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": tcpip,
        "ext_tcpip_features": (
            Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_DUAL_MODE_ENABLE
            | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        ),
        "config_features": Si91xConfigFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
    return pytest.mark.config("wifi_dut", wifi=config)


class DualStackIPv6(ThreadBase):
    """IPv6 dual-stack workflow engine (NWP offload + lwIP)."""

    def __init__(
        self,
        wifi_sniffer,
        wifi_dut,
        wifi_access_point,
        sl_collections,
        net_perf_client,
        wifi_client,
        protocol,
        testcase,
        traffic_type="TX",
        capture_file=None,
        service_discovery=None,
        sniffer_filter=None,
    ):
        super().__init__()
        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.testcase = testcase
        self.traffic_type = traffic_type
        self.capture_file = capture_file or testcase
        self.service_discovery = service_discovery
        self.sniffer_filter = sniffer_filter
        self._reset_sniffer_capture_context()

    def _reset_sniffer_capture_context(self):
        self.dut_ipv6 = None
        self.backend_ipv6 = None
        self.ap_mac = None
        self.dut_mac = None
        self._dut_ipv4 = None
        self._dut_ipv6 = None

    def _should_validate_sniffer(self):
        return (
            self.sniffer_filter is not None
            and self.dut_ipv6
            and self.backend_ipv6
            and self.ap_mac
        )

    def _start_sniffer(self):
        channel = self.wifi_access_point.interfaces.wifi.channel
        logger().info(f"Start sniffer capture on channel {channel}")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        capture_name = self.capture_file.replace("[", "_").replace("]", "_")
        if not capture_name.endswith(".pcap"):
            capture_name = f"{capture_name}.pcap"
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_name)

    def _stop_sniffer(self):
        logger().info("Stop sniffer capture")
        self.wifi_sniffer.interfaces.capture.stop_capture()

    @property
    def wifi(self):
        return self.wifi_dut.interfaces.wifi

    def _ap_wifi_params(self):
        ap_wifi = self.wifi_access_point.interfaces.wifi
        return {
            "ssid": ap_wifi.ssid,
            "passphrase": ap_wifi.passphrase,
            "security": ap_wifi.security.name.lower(),
            "channel": ap_wifi.channel,
        }

    def _nwp_connect(self):
        """Wi-Fi association on the NWP offload stack (wifi.client.connect)."""
        join_ok, reason = self.sl_collections.connect(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
        )
        assert join_ok, f"NWP connect failed: {reason}"

    def _lwip_connect(self):
        """Wi-Fi association on the lwIP host stack (wifi.client.connect_lwip)."""
        ap = self._ap_wifi_params()
        self.wifi.is_external_stack_enabled = True
        self.wifi.lwip_join(
            ssid=ap["ssid"],
            passphrase=ap["passphrase"],
            security=ap["security"],
            channel=ap["channel"],
            timeout=60,
        )

    def _nwp_prepare_client(self):
        """Match ipv6_ipv4_sdk client settings used for stateless IPv6 bring-up."""
        self.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0,
            scan_interval=4,
            beacon_missed_count=40,
            first_time_retry_enable=0,
        )

    def _nwp_join_with_ipv4(self):
        """Scan, NWP join, and IPv4 DHCP on the offload stack (not lwIP).

        sl_net_init_client sets is_external_stack_enabled=True; join_to_wifi_network
        must use NWP net.configure_ip here, not lwIP net.up client.
        """
        self._nwp_prepare_client()
        if self.wifi.associated:
            logger().info("DUT still associated; disconnecting before re-join")
            self.wifi.leave()
            time.sleep(2)

        saved = self.wifi.is_external_stack_enabled
        self.wifi.is_external_stack_enabled = False
        try:
            dut_info = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut,
                wifi_access_point=self.wifi_access_point,
                associated=False,
                power_save=False,
                retry_count=3,
                ping_before_power_save=False,
                ping_after_power_save=False,
            )
        finally:
            self.wifi.is_external_stack_enabled = saved

        assert dut_info, (
            "join_to_wifi_network did not return DUT info (NWP IPv4 join failed)"
        )
        logger().info(
            f"NWP IPv4 DHCP: {dut_info.get('device_ip')} "
            f"MAC: {dut_info.get('dut_mac_address')}"
        )
        return dut_info

    def _nwp_configure_ipv4(self):
        saved = self.wifi.is_external_stack_enabled
        self.wifi.is_external_stack_enabled = False
        try:
            ok, ip_config = self.sl_collections.configure_ip(
                self.wifi_dut, retry_count=3, ip_version="ipv4"
            )
        finally:
            self.wifi.is_external_stack_enabled = saved
        assert ok, f"NWP IPv4 DHCP failed: {ip_config}"
        return ip_config

    def _nwp_configure_ipv6(self, timeout=120, retry_count=3):
        saved = self.wifi.is_external_stack_enabled
        self.wifi.is_external_stack_enabled = False
        try:
            ok, ip_config = self.sl_collections.configure_ip(
                self.wifi_dut,
                retry_count=retry_count,
                ip_version="ipv6",
                timeout=timeout,
            )
        finally:
            self.wifi.is_external_stack_enabled = saved
        assert ok, f"NWP IPv6 DHCP failed: {ip_config}"
        if isinstance(ip_config, tuple):
            logger().info(
                f"NWP IPv6: link-local={ip_config[0]}, "
                f"global={ip_config[1]}, gateway={ip_config[2]}"
            )
        return _global_ipv6_from_config(ip_config)

    def _safe_leave(self):
        """Disconnect DUT; ignore invalid-state errors from profile-only joins."""
        if not self.wifi.associated:
            return
        try:
            self.wifi.leave()
        except Exception as ex:
            logger().warning(f"leave skipped or failed: {ex}")
        finally:
            self.wifi.associated = False

    def _lwip_security_code(self):
        sec = self.wifi_access_point.interfaces.wifi.security.name.upper()
        sec = sec.replace(" ", "_").replace("-", "_")
        if "WPA2" in sec and "ENTERPRISE" not in sec:
            return _MAP_SECURITY["WPA2"]
        return _MAP_SECURITY.get(sec, _MAP_SECURITY["WPA2"])

    def _lwip_set_profile(self, ip_type="ipv4"):
        """Program lwIP client profile (net.set_profile + net.set_credential)."""
        ap = self._ap_wifi_params()
        security = self._lwip_security_code()
        cred_id = 1 if security != 0 else 0
        self.wifi.is_external_stack_enabled = True
        self.wifi.sl_net_set_profile(
            ssid=ap["ssid"],
            security=security,
            credential_id=cred_id,
            priority=1,
            profile_id=0,
            ip_type=ip_type,
            channel=ap["channel"],
            encryption="SL_WIFI_DEFAULT_ENCRYPTION",
        )
        if cred_id:
            self.wifi.sl_net_set_credential(
                credential=ap["passphrase"],
                cred_id=cred_id,
            )

    def _poll_lwip_ip(self, ip_version, timeout=120, interval=5):
        """Poll lwIP address assigned by profile + net.up (no lwip.configure_ip)."""
        deadline = time.monotonic() + timeout
        last_ex = None
        while time.monotonic() < deadline:
            try:
                ip_cfg = self._read_lwip_ip(ip_version)
                if ip_version == "ipv6":
                    if isinstance(ip_cfg, tuple):
                        logger().info(
                            f"lwIP IPv6 poll: link-local={ip_cfg[0]}, "
                            f"global={ip_cfg[1]}, gateway={ip_cfg[2]}"
                        )
                    global_ipv6 = _global_ipv6_from_config(ip_cfg)
                    if _is_valid_global_ipv6(global_ipv6):
                        return global_ipv6
                elif hasattr(ip_cfg, "ip") and ip_cfg.ip:
                    ip_str = ip_cfg.ip.decode()
                    if ip_str and ip_str != "0.0.0.0":
                        return ip_cfg
            except Exception as ex:
                last_ex = ex
                logger().info(f"lwIP {ip_version} not ready yet: {ex}")
            time.sleep(interval)
        raise AssertionError(
            f"lwIP {ip_version} not assigned within {timeout}s after profile + net.up"
        ) from last_ex

    def _read_lwip_ip(self, ip_version):
        """Read lwIP address via net.print_ip (lwIP stack path)."""
        return self.wifi.print_ip_command_handler(
            mode="client", ip_version=ip_version, timeout=20,
        )

    def _lwip_bring_up(self, ip_type="ipv6", timeout=120):
        """lwIP: profile + net.up only (do not mix with connect_lwip)."""
        self.wifi.is_external_stack_enabled = True
        self._lwip_set_profile(ip_type=ip_type)
        self.wifi.sl_net_up(mode="client", timeout=timeout)
        self.wifi.associated = True
        return self._poll_lwip_ip(ip_type, timeout=timeout)

    def _ensure_lwip_ready(self):
        """Confirm lwIP netif exists after sl_net_init_client (before net.up)."""
        try:
            self.wifi.is_external_stack_enabled = True
            self.wifi.print_ip_command_handler(
                mode="client", ip_version="ipv4", timeout=20,
            )
        except Exception as ex:
            raise AssertionError(
                "lwIP host netif is not available after sl_net_init_client"
            ) from ex

    def _ping_icmpv6_nwp(self, target_ip, count=5):
        saved = self.wifi.is_external_stack_enabled
        self.wifi.is_external_stack_enabled = False
        try:
            self.wifi.ping(
                server_ip=target_ip,
                num_ping_attempts=count,
                ip_version="ipv6",
                ping_size=64,
            )
        finally:
            self.wifi.is_external_stack_enabled = saved

    def _ping_icmpv6_lwip_dut(self, target_ip, count=10):
        """DUT-initiated ICMPv6 via lwIP/external stack path."""
        saved = self.wifi.is_external_stack_enabled
        self.wifi.is_external_stack_enabled = True
        try:
            self.wifi.ping(
                server_ip=target_ip,
                num_ping_attempts=count,
                ip_version="ipv6",
                ping_size=64,
            )
        finally:
            self.wifi.is_external_stack_enabled = saved

    def _ping_icmpv6_lwip_responds(self, dut_ipv6, count=10):
        """Host-to-DUT ICMPv6 — validates lwIP responds to ping."""
        status = self.sl_collections.ping(
            device_ip=dut_ipv6,
            ping_count=count,
            retry_count=3,
        )
        assert status, f"DUT lwIP IPv6 {dut_ipv6} not responding to ICMPv6"

    def _ping_icmpv6_host_to_nwp(self, dut_ipv6, count=10):
        """Host-to-DUT ICMPv6 — validates NWP stack responds to ping."""
        status = self.sl_collections.ping(
            device_ip=dut_ipv6,
            ping_count=count,
            retry_count=3,
        )
        assert status, f"Host ICMPv6 ping to NWP DUT {dut_ipv6} failed"

    def _refresh_ap_backend_ipv6(self):
        """Cycle LAN interface so wifi_client picks up global IPv6 (SLAAC)."""
        client_wifi = self.wifi_client.interfaces.wifi
        iface = client_wifi.config["interface"]
        logger().info(f"Refresh AP backend IPv6 on interface {iface}")
        shell = client_wifi.shell
        for cmd in (
            f"sudo ifconfig {iface} down",
            f"sudo ifconfig {iface} up",
        ):
            if hasattr(shell, "execute"):
                shell.execute(cmd)
            else:
                shell(cmd)
        time.sleep(10)

    def _read_ap_backend_global_ipv6(self):
        """Read global IPv6 from wifi_client (ifconfig, then ip -6 fallback)."""
        client_wifi = self.wifi_client.interfaces.wifi
        backend_ip = client_wifi.get_ip_address(version=6, addr_type="global")
        if backend_ip:
            return backend_ip

        iface = client_wifi.config["interface"]
        rc, stdout, _stderr = client_wifi.shell(
            f"ip -6 -o addr show dev {iface} scope global"
        )
        if rc != 0 or not stdout:
            return None
        if isinstance(stdout, bytes):
            stdout = stdout.decode()
        for line in stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                addr = parts[3].split("/")[0]
                if addr and not addr.startswith("fe80:"):
                    return addr
        return None

    def _ap_backend_ipv6(self, retry_count=6, retry_delay=5):
        """Global IPv6 of the LAN backend host (wifi_client / Pi) behind the AP."""
        backend_ip = None
        for attempt in range(retry_count):
            backend_ip = self._read_ap_backend_global_ipv6()
            if backend_ip:
                break
            logger().info(
                "AP backend (wifi_client) has no global IPv6 yet; "
                f"retry {attempt + 1}/{retry_count}"
            )
            if attempt == retry_count // 2:
                self._refresh_ap_backend_ipv6()
            else:
                time.sleep(retry_delay)
        assert backend_ip, (
            "AP backend (wifi_client) has no global IPv6 address after "
            f"{retry_count} attempts"
        )
        return _normalize_ipv6_addr(backend_ip)

    def _host_ipv6(self):
        return self._ap_backend_ipv6()

    def _host_ipv4(self):
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        assert host_ip, "AP backend (wifi_client) has no IPv4 address"
        if isinstance(host_ip, bytes):
            return host_ip.decode()
        return str(host_ip)

    def _nwp_dut_ipv4(self):
        if self._dut_ipv4:
            return self._dut_ipv4
        ip_config = self._nwp_configure_ipv4()
        self._dut_ipv4 = ip_config.ip.decode()
        return self._dut_ipv4

    def _nwp_dut_ipv6(self):
        if self._dut_ipv6:
            return self._dut_ipv6
        dut_ipv6 = self._nwp_configure_ipv6()
        self._dut_ipv6 = dut_ipv6
        return dut_ipv6

    def _lwip_dut_ipv6(self):
        if self._dut_ipv6:
            return self._dut_ipv6
        saved = self.wifi.is_external_stack_enabled
        self.wifi.is_external_stack_enabled = True
        try:
            ip_cfg = self._read_lwip_ip("ipv6")
            global_ipv6 = _global_ipv6_from_config(ip_cfg)
            assert global_ipv6, f"lwIP has no global IPv6: {ip_cfg}"
            self._dut_ipv6 = global_ipv6
            return global_ipv6
        finally:
            self.wifi.is_external_stack_enabled = saved

    def _lwip_dut_ipv4(self, timeout=120):
        """DHCP or read lwIP IPv4 for iperf (traffic uses IPv4 sockets)."""
        saved = self.wifi.is_external_stack_enabled
        self.wifi.is_external_stack_enabled = True
        try:
            try:
                ip_cfg = self._read_lwip_ip("ipv4")
                if hasattr(ip_cfg, "ip") and ip_cfg.ip:
                    ip_str = ip_cfg.ip.decode()
                    if ip_str and ip_str != "0.0.0.0":
                        return ip_str
            except Exception as ex:
                logger().info(f"lwIP IPv4 not ready, running DHCP: {ex}")
            ip_cfg = self.wifi.start_ip_lwip(ip_version="ipv4", timeout=timeout)
            ip_str = ip_cfg.ip.decode() if hasattr(ip_cfg, "ip") else str(ip_cfg)
            assert ip_str and ip_str != "0.0.0.0", f"lwIP IPv4 DHCP failed: {ip_cfg}"
            logger().info(f"lwIP IPv4 DHCP: {ip_str}")
            return ip_str
        finally:
            self.wifi.is_external_stack_enabled = saved

    def _verify_icmpv6_nwp(self, dut_ipv6):
        """ICMPv6 data path: DUT -> AP backend and AP backend -> DUT."""
        backend_ipv6 = self._ap_backend_ipv6()
        logger().info(
            f"ICMPv6 endpoints: DUT={dut_ipv6}, AP backend={backend_ipv6}"
        )
        assert str(backend_ipv6) != str(dut_ipv6), (
            "DUT and AP backend must have different IPv6 addresses"
        )
        logger().info("ICMPv6 ping from DUT to AP backend")
        self._ping_icmpv6_nwp(backend_ipv6)
        logger().info("ICMPv6 ping from AP backend to DUT")
        self._ping_icmpv6_host_to_nwp(dut_ipv6)

    def _enable_coex_power_save(self):
        """Enable WLAN and BLE power save on DUT and verify both are active."""
        logger().info("Enable WLAN power save on DUT")
        self.wifi.set_performance_profile("power_save_low_latency")

        logger().info("Enable BLE power save on DUT")
        self.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
        )
        logger().info("BLE power save status is enabled on DUT")
        time.sleep(10)

    def _sniffer_packet_count(self, wifi_sniffer, packet_filter):
        return wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter
        )["packet_count"]

    def validate_ipv6_wireless_capture(self, wifi_sniffer, sniffer_filter):
        """Check stateless IPv6 packet format in wireless capture."""
        assert self.dut_ipv6 and self.backend_ipv6 and self.ap_mac, (
            "IPv6 sniffer validation requires DUT/backend IPv6 and AP MAC"
        )
        ap_mac = _tshark_mac(self.ap_mac)
        dut_mac = _tshark_mac(self.dut_mac) if self.dut_mac else None
        logger().info(
            "Check IPv6 packet format in wireless capture "
            "(stateless NDP + ICMPv6 echo)"
        )

        echo_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_ipv6,
            da_addr=self.backend_ipv6,
            filter_name="echo_req_reply",
        )
        assert self._sniffer_packet_count(wifi_sniffer, echo_filter), (
            "IPv6 packet format invalid: ICMPv6 echo request/reply not found"
        )

        if dut_mac:
            rs_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=dut_mac,
                filter_name="router_solicitation",
            )
            assert self._sniffer_packet_count(wifi_sniffer, rs_filter), (
                "IPv6 packet format invalid: Router Solicitation (type 133) not found"
            )
            ra_unicast = (
                sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    da_addr=dut_mac,
                    filter_name="router_advertisement",
                )
            )
            ra_multicast = f"(icmpv6.type == 134) && (wlan.sa == {ap_mac})"
            assert (
                self._sniffer_packet_count(wifi_sniffer, ra_unicast)
                or self._sniffer_packet_count(wifi_sniffer, ra_multicast)
            ), (
                "IPv6 packet format invalid: Router Advertisement (type 134) not found"
            )

        ra_flag_filter = f"icmpv6.nd.ra.flag.m == 0 && wlan.sa == {ap_mac}"
        if not self._sniffer_packet_count(wifi_sniffer, ra_flag_filter):
            if dut_mac:
                logger().warning(
                    "Stateless RA M=0 flag filter matched 0 packets; "
                    "ICMPv6 NDP and echo checks passed"
                )
            else:
                assert False, (
                    "IPv6 RA format invalid: stateless DHCPv6 (M=0) not seen from AP"
                )

    def _verify_icmpv6_lwip(self, dut_ipv6):
        """ICMPv6 on lwIP stack: DUT -> AP backend and AP backend -> DUT."""
        backend_ipv6 = self.backend_ipv6 or self._ap_backend_ipv6()
        logger().info(
            f"lwIP ICMPv6 endpoints: DUT={dut_ipv6}, AP backend={backend_ipv6}"
        )
        assert str(backend_ipv6) != str(dut_ipv6), (
            "DUT and AP backend must have different IPv6 addresses"
        )
        logger().info("ICMPv6 ping from DUT (lwIP) to AP backend")
        self._ping_icmpv6_lwip_dut(backend_ipv6)
        logger().info("ICMPv6 ping from AP backend to DUT (lwIP)")
        self._ping_icmpv6_lwip_responds(dut_ipv6)

    def _dns_on_stack(self, domain, ip_version, use_lwip):
        if ip_version == "ipv6":
            expected = _resolve_host_aaaa_records(domain)
        saved = self.wifi.is_external_stack_enabled
        self.wifi.is_external_stack_enabled = use_lwip
        try:
            result = self.wifi.dns_get(
                domain_name=domain,
                query_timeout=20000,
                ip_version=ip_version,
                timeout=30,
            )
        finally:
            self.wifi.is_external_stack_enabled = saved
        if ip_version == "ipv6":
            resolved = _normalize_ipv6_addr(result)
            assert resolved in expected, (
                f"{'lwIP' if use_lwip else 'NWP'} AAAA mismatch: "
                f"DUT={resolved}, host={sorted(expected)}"
            )
            return resolved
        decoded = _decode_cli_output(result).strip()
        assert decoded, f"{'lwIP' if use_lwip else 'NWP'} DNS A empty for {domain}"
        ipaddress.IPv4Address(decoded)
        return decoded

    def _dns_aaaa_nwp(self, domain=DOMAIN_NAME_AAAA):
        return self._dns_on_stack(domain, "ipv6", use_lwip=False)

    def _dns_aaaa_lwip(self, domain=DOMAIN_NAME_AAAA):
        return self._dns_on_stack(domain, "ipv6", use_lwip=True)

    def _dns_a_nwp(self, domain=DOMAIN_NAME_AAAA):
        return self._dns_on_stack(domain, "ipv4", use_lwip=False)

    def _dns_a_lwip(self, domain=DOMAIN_NAME_AAAA):
        return self._dns_on_stack(domain, "ipv4", use_lwip=True)

    def _mdns_cycle(self, use_lwip=False, validate_avahi=False):
        saved = self.wifi.is_external_stack_enabled
        self.wifi.is_external_stack_enabled = use_lwip
        mdns_started = False
        try:
            self.wifi.mdns_init(ip_version=Si91xMdnsParams.IPV6)
            mdns_started = True
            self.wifi.mdns_add_interface(interface="client")
            self.wifi.mdns_register_service(interface="client")
            if validate_avahi and self.service_discovery is not None:
                _avahi_cycle(self.service_discovery.interfaces.sd)
            else:
                time.sleep(5)
        finally:
            if mdns_started:
                self.wifi.mdns_deinit()
            self.wifi.is_external_stack_enabled = saved
            if validate_avahi and self.service_discovery is not None:
                _avahi_cycle(self.service_discovery.interfaces.sd)

    def _run_nwp_traffic(
        self, device_ip, host_ip, timeout=30, port=NWP_IPERF_PORT, ip_version=4,
    ):
        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=self.protocol,
            device_ip=device_ip,
            host_ip=host_ip,
            timeout=timeout,
            traffic_type=self.traffic_type,
            ip_version=ip_version,
            mode="nwp",
            port=port,
        )

    def _run_lwip_traffic(
        self, device_ip, host_ip, timeout=30, port=LWIP_IPERF_PORT, ip_version=4,
    ):
        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=self.protocol,
            device_ip=device_ip,
            host_ip=host_ip,
            timeout=timeout,
            traffic_type=self.traffic_type,
            ip_version=ip_version,
            mode="lwip",
            port=port,
        )

    def _setup_dual_stack_ipv6(self):
        dut_info = self._nwp_join_with_ipv4()
        device_ip = dut_info.get("device_ip")
        if isinstance(device_ip, bytes):
            device_ip = device_ip.decode()
        self._dut_ipv4 = device_ip
        time.sleep(10)
        dut_ipv6 = self._nwp_configure_ipv6()
        self._dut_ipv6 = dut_ipv6
        self._enable_coex_power_save()
        return dut_ipv6

    def _setup_lwip_ipv6(self, timeout=120):
        """C793949: sl_net_set_profile(ipv6) + net.up; poll once for global IPv6."""
        self._safe_leave()
        time.sleep(2)
        dut_ipv6 = self._lwip_bring_up(ip_type="ipv6", timeout=timeout)
        self._dut_ipv6 = dut_ipv6
        self._enable_coex_power_save()
        return dut_ipv6

    def run(self):
        self._reset_sniffer_capture_context()
        self._start_sniffer()
        try:
            self._run_testcase()
        finally:
            self._safe_leave()
            time.sleep(2)
            self._stop_sniffer()
            if self._should_validate_sniffer():
                self.validate_ipv6_wireless_capture(
                    self.wifi_sniffer,
                    self.sniffer_filter,
                )

    def _run_testcase(self):
        tc = self.testcase

        if tc == "c793948":
                dut_ipv6 = self._setup_dual_stack_ipv6()
                assert dut_ipv6, "DUT is not assigned an IPv6 address"
                logger().info(f"DUT assigned IPv6 address: {dut_ipv6}")
                self.dut_ipv6 = dut_ipv6
                self.backend_ipv6 = self._ap_backend_ipv6()
                self.ap_mac = self.wifi_access_point.interfaces.wifi.bssid
                self.dut_mac = self.wifi.get_mac_address()
                self._verify_icmpv6_nwp(dut_ipv6)

        elif tc == "c793949":
            self.backend_ipv6 = self._ap_backend_ipv6()
            logger().info(f"AP backend IPv6 (cached): {self.backend_ipv6}")
            dut_ipv6 = self._setup_lwip_ipv6()
            logger().info(f"lwIP IPv6: {dut_ipv6}")
            time.sleep(5)
            self._verify_icmpv6_lwip(dut_ipv6)

        elif tc == "c793950":
            self._setup_dual_stack_ipv6()
            self._dns_aaaa_nwp()

        elif tc == "c793950_lwip":
            self._setup_lwip_ipv6()
            self._dns_aaaa_lwip()

        elif tc == "c793952":
            self._nwp_join_with_ipv4()
            self._enable_coex_power_save()
            self._dns_a_nwp()

        elif tc == "c793952_lwip":
            self._setup_lwip_ipv6()
            self._dns_a_lwip()

        elif tc == "c793957":
            self._setup_dual_stack_ipv6()
            self._mdns_cycle(use_lwip=False, validate_avahi=False)

        elif tc == "c793957_avahi":
            self._setup_dual_stack_ipv6()
            self._mdns_cycle(use_lwip=False, validate_avahi=True)

        elif tc == "c793959_lwip":
            self._setup_lwip_ipv6()
            self._mdns_cycle(use_lwip=True, validate_avahi=False)

        elif tc == "c793961":
            self._setup_lwip_ipv6()
            self._run_lwip_traffic(
                self._lwip_dut_ipv6(), self._host_ipv6(), ip_version=6,
            )

        elif tc == "c793963":
            self._setup_lwip_ipv6()
            host_ipv4 = self._host_ipv4()
            self._run_lwip_traffic(self._lwip_dut_ipv4(), host_ipv4)
            self.wifi.leave()
            time.sleep(5)
            self._setup_lwip_ipv6()
            self._run_lwip_traffic(self._lwip_dut_ipv4(), host_ipv4)

        elif tc == "c793961_rx":
            self._setup_lwip_ipv6()
            self._run_lwip_traffic(self._lwip_dut_ipv4(), self._host_ipv4())

        elif tc == "c793964":
            self._setup_dual_stack_ipv6()
            self._run_nwp_traffic(
                self._nwp_dut_ipv6(), self._host_ipv6(), ip_version=6,
            )

        elif tc == "c793967":
            self._setup_dual_stack_ipv6()
            self._run_nwp_traffic(
                self._nwp_dut_ipv6(), self._host_ipv6(), ip_version=6,
            )

        elif tc == "c793965":
            self._setup_dual_stack_ipv6()
            self._run_nwp_traffic(self._nwp_dut_ipv4(), self._host_ipv4())

        elif tc == "c793966":
            self._setup_dual_stack_ipv6()
            self._run_nwp_traffic(self._nwp_dut_ipv4(), self._host_ipv4())

        elif tc == "c793965_lwip":
            self._setup_lwip_ipv6()
            self._run_lwip_traffic(self._lwip_dut_ipv4(), self._host_ipv4())

        elif tc == "c793966_lwip":
            self._setup_lwip_ipv6()
            self._run_lwip_traffic(self._lwip_dut_ipv4(), self._host_ipv4())

        elif tc == "c793968":
            self._setup_dual_stack_ipv6()
            host_ipv4 = self._host_ipv4()
            self._run_nwp_traffic(self._nwp_dut_ipv4(), host_ipv4)
            self.wifi.leave()
            time.sleep(5)
            self._setup_dual_stack_ipv6()
            self._run_nwp_traffic(self._nwp_dut_ipv4(), host_ipv4)

        elif tc == "c793973":
            self._setup_lwip_ipv6()
            host_ipv4 = self._host_ipv4()
            self._run_lwip_traffic(self._lwip_dut_ipv4(), host_ipv4)
            self.wifi.leave()
            time.sleep(5)
            self._setup_lwip_ipv6()
            self._run_lwip_traffic(self._lwip_dut_ipv4(), host_ipv4)

        elif tc == "c793975":
            self._setup_lwip_ipv6()
            host_ipv4 = self._host_ipv4()
            self._run_lwip_traffic(self._lwip_dut_ipv4(), host_ipv4, timeout=60)
            self.wifi.is_external_stack_enabled = True
            self.wifi.start_ip_lwip(ip_version="ipv6", timeout=120)
            self._run_lwip_traffic(self._lwip_dut_ipv4(), host_ipv4, timeout=30)

        elif tc == "c793976":
            self._setup_lwip_ipv6()
            host_ipv6 = self._host_ipv6()
            dut_ipv6 = self._lwip_dut_ipv6()
            self._run_lwip_traffic(
                dut_ipv6, host_ipv6, timeout=60, ip_version=6,
            )
            self.wifi.is_external_stack_enabled = True
            self.wifi.start_ip_lwip(ip_version="ipv6", timeout=120)
            self._dut_ipv6 = None
            dut_ipv6 = self._lwip_dut_ipv6()
            self._run_lwip_traffic(
                dut_ipv6, host_ipv6, timeout=30, ip_version=6,
            )

        elif tc == "c793978":
            self._nwp_join_with_ipv4()
            saved = self.wifi.is_external_stack_enabled
            self.wifi.is_external_stack_enabled = False
            try:
                ok, ip_config = self.sl_collections.configure_ip(
                    self.wifi_dut,
                    retry_count=1,
                    ip_version="ipv6",
                    timeout=30,
                )
            finally:
                self.wifi.is_external_stack_enabled = saved
            assert not ok, (
                f"IPv6 DHCP should fail with DHCPv6 disabled, got: {ip_config}"
            )
            logger().info(f"Negative IPv6 DHCP failed as expected: {ip_config}")

        else:
            raise NotImplementedError(f"Unknown testcase {tc}")


def _run_dual_stack_ipv6_test(dual_stack, sl_collections, wifi_dut):
    try:
        dual_stack.start()
        dual_stack.wait_for_exit()
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
@wifi_dut_marker_ipv6()
@pytest.mark.config("wifi_access_point", wifi=STATELESS_AP_IPV6)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.firmware_app("test_dual_stack_ipv6")
def test_wifi_sdk_nwp_dhcpv6_icmpv6_dual_stack_c793948(
    firmware_loader, request, wifi_sniffer, wifi_access_point, wifi_dut,
    sl_collections, net_perf_client, wifi_client, protocol,
):
    """C793948: DHCPv6, coex PS, bidirectional ICMPv6 (capture only, no filter validation)."""
    try:
        dual_stack = DualStackIPv6(
            wifi_sniffer, wifi_dut, wifi_access_point, sl_collections,
            net_perf_client, wifi_client, protocol, "c793948",
            capture_file=request.node.name,
        )
        _run_dual_stack_ipv6_test(dual_stack, sl_collections, wifi_dut)
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)




@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
@wifi_dut_marker_ipv6(tcp_feat_bit=Si91xTCPIPFeatureBitMap.DNSClient)
@pytest.mark.config("wifi_access_point", wifi=STATELESS_AP_IPV6)
@pytest.mark.firmware_app("test_dual_stack_ipv6")
def test_wifi_sdk_nwp_dns_aaaa_dual_stack_c793950(
    firmware_loader, request, wifi_sniffer, wifi_access_point, wifi_dut,
    sl_collections, net_perf_client, wifi_client,
):
    """C793950: IPv6 DNS AAAA query on NWP offload stack."""
    _run_dual_stack_ipv6_test(
        DualStackIPv6(
            wifi_sniffer, wifi_dut, wifi_access_point, sl_collections,
            net_perf_client, wifi_client, IperfConstants.TCP, "c793950",
            capture_file=request.node.name,
        ),
        sl_collections, wifi_dut,
    )


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
@wifi_dut_marker_ipv6(tcp_feat_bit=Si91xTCPIPFeatureBitMap.DNSClient)
@pytest.mark.config("wifi_access_point", wifi=STATELESS_AP_IPV6)
@pytest.mark.firmware_app("test_dual_stack_ipv6")
def test_wifi_sdk_nwp_dns_a_dual_stack_c793952(
    firmware_loader, request, wifi_sniffer, wifi_access_point, wifi_dut,
    sl_collections, net_perf_client, wifi_client,
):
    """C793952: IPv4 DNS A query on NWP offload stack in dual-stack mode."""
    _run_dual_stack_ipv6_test(
        DualStackIPv6(
            wifi_sniffer, wifi_dut, wifi_access_point, sl_collections,
            net_perf_client, wifi_client, IperfConstants.TCP, "c793952",
            capture_file=request.node.name,
        ),
        sl_collections, wifi_dut,
    )


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
@wifi_dut_marker_ipv6(include_mdns=True)
@pytest.mark.config("wifi_access_point", wifi=STATELESS_AP_IPV6)
@pytest.mark.firmware_app("test_dual_stack_ipv6")
def test_wifi_sdk_nwp_mdns_ipv6_dual_stack_c793957(
    firmware_loader, request, wifi_sniffer, wifi_access_point, wifi_dut,
    sl_collections, net_perf_client, wifi_client,
):
    """C793957: mDNS init/register/deinit on NWP stack over IPv6."""
    _run_dual_stack_ipv6_test(
        DualStackIPv6(
            wifi_sniffer, wifi_dut, wifi_access_point, sl_collections,
            net_perf_client, wifi_client, IperfConstants.TCP, "c793957",
            capture_file=request.node.name,
        ),
        sl_collections, wifi_dut,
    )

@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
@wifi_dut_marker_ipv6()
@pytest.mark.config("wifi_access_point", wifi=STATELESS_AP_IPV6)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.firmware_app("test_dual_stack_ipv6")
def test_wifi_sdk_nwp_tcp_tx_ipv6_dual_stack_c793967(
    firmware_loader, request, wifi_sniffer, wifi_access_point, wifi_dut,
    sl_collections, net_perf_client, wifi_client, protocol,
):
    """C793967: IPv6 TCP Tx on NWP offload stack."""
    _run_dual_stack_ipv6_test(
        DualStackIPv6(
            wifi_sniffer, wifi_dut, wifi_access_point, sl_collections,
            net_perf_client, wifi_client, protocol, "c793967",
            traffic_type="TX", capture_file=request.node.name,
        ),
        sl_collections, wifi_dut,
    )

