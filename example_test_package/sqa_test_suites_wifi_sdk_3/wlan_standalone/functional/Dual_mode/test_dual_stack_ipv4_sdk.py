""" Test Steps:
        1. Configure the DUT in Wlan for 2.4Gh with Dual stack and validate the WLAN functionality.

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Every constant, helper and marker used by the test cases is defined on
    ``DualStack``; the test functions below only reach them through that class.

    Author: Jyothi Nagireddy
"""

import time
import pytest
import random
import string
import ipaddress
from copy import deepcopy
from threading import Thread
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xMqttQos,
    Si91xOperatingMode,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
)


class DualStack(ThreadBase):
    """Run dual-stack / lwIP bypass validation loops."""

    END_STATE = [
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "unassociated",
    ]

    DEFAULT_STATIC_IP = "192.168.50.11"
    DEFAULT_STATIC_SUBNET = "255.255.255.0"
    DEFAULT_STATIC_GATEWAY = "192.168.50.1"

    NWP_IPERF_PORT = 5001
    LWIP_IPERF_PORT = 5002

    FIRMWARE_APP_IPV4 = "test_dual_stack_ipv4"
    FIRMWARE_APP_IPV6 = "test_dual_stack_ipv6"

    WAN_IPV6_PREFIX = "2401:4900:1cb3:3444::"
    WAN_IPV6_GATEWAY = "2401:4900:1cb3:3444::1"

    SECURITY_MAP = {
        "OPEN": 0,
        "WPA": 1,
        "WPA2": 2,
        "WEP": 3,
        "WPA_WPA2_MIXED": 6,
        "WPA3": 7,
        "WPA3_TRANSITION": 8,
    }

    # Shared by every test marker so all cases run against the same WAN address.
    _ap_ipv6_config = None

    def __init__(
        self,
        wifi_sniffer,
        wifi_dut,
        wifi_access_point,
        sl_collections,
        net_perf_client,
        wifi_client,
        protocol,
        http_server=None,
        http_client=None,
        index_path=None,
        iterations=1,
        traffic_type="TX",
        testcase=None,
        rps_path=None,
        capture_file=None,
        mqtt_server=None,
        mqtt_client=None,
        static_ip=DEFAULT_STATIC_IP,
        static_subnet=DEFAULT_STATIC_SUBNET,
        static_gateway=DEFAULT_STATIC_GATEWAY,
    ):
        super().__init__()
        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.http_server = http_server
        self.http_client = http_client
        self.index_path = index_path
        self.iterations = iterations
        self.traffic_type = traffic_type
        self.testcase = testcase
        self.rps_path = rps_path
        self.capture_file = capture_file
        self.mqtt_server = mqtt_server
        self.mqtt_client = mqtt_client
        self.static_ip = static_ip
        self.static_subnet = static_subnet
        self.static_gateway = static_gateway
        self.dut_ip = None

    # ------------------------------------------------------------------
    # Test entry points and pytest markers
    # ------------------------------------------------------------------
    @classmethod
    def run_test(cls, sl_collections, wifi_dut, **kwargs):
        """Build the engine, run the selected case and report failures."""
        try:
            cls(sl_collections=sl_collections, wifi_dut=wifi_dut, **kwargs).run()
        except Exception as ex:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)

    @classmethod
    def random_ipv6_addr(cls, prefix):
        # Ensure the prefix is interpreted as a /64 network
        if "/" in prefix:
            prefix = prefix.split("/")[0]  # Remove any existing netmask
        network = ipaddress.IPv6Network(f"{prefix}/64", strict=False)

        # Combine the prefix with a random 64-bit interface identifier
        full_ip_int = int(network.network_address) | random.getrandbits(64)
        return str(ipaddress.IPv6Address(full_ip_int))

    @classmethod
    def ap_ipv6_config(cls):
        """AP config for the stateful IPv6 (DHCPv6) cases, built once."""
        if cls._ap_ipv6_config is None:
            cls._ap_ipv6_config = {
                "security": "WPA2",
                "passphrase": "231469460",
                "connection_type": "STATIC_IPV6",
                "wan_ipv6_address": cls.random_ipv6_addr(cls.WAN_IPV6_PREFIX),
                "wan_ipv6_gateway": cls.WAN_IPV6_GATEWAY,
                "wan_prefix_length": "64",
                "ipv6_state": "1",
                "lan_ipv6_address": "2401:3500:133c:1341:1134:ffed:13cd:1134",
                "lan_prefix_length": "64",
                "lan_ipv6_prefix": "2401:3500:133c:1341::",
                "lan_ip_pool_start": "1000",
                "lan_ip_pool_end": "2000",
                "lan_lease_time": "86400",
                "use_ipv6_web": True,
                "enable_ipv6": True,
            }
        return cls._ap_ipv6_config

    @classmethod
    def wifi_dut_marker(
        cls, tcp_feat_bit=0, ext_tcp_bit=0, ca_cert=None, mqtt=False, dual_mode=True
    ):
        if dual_mode:
            ext_tcpip = (
                Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_DUAL_MODE_ENABLE
                | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
            )
        else:
            # Bypass / lwIP-only: dual-mode bit must NOT be set (mutually exclusive)
            ext_tcpip = Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        if mqtt:
            ext_tcpip |= Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature
        config = {
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default,
            "custom_features": (
                Si91xCustomFeatureBitMap.Default
                | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
            ),
            "tcpip_features": (
                Si91xTCPIPFeatureBitMap.DHCPv4Client
                | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid
                | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                | tcp_feat_bit
            ),
            "ext_tcpip_features": ext_tcpip | ext_tcp_bit,
            "ext_custom_features": (
                Si91xExtCustomFeatureBitMap.Default
                | Si91xExtCustomFeatureBitMap.FeatureLowPower
                | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
            ),
            "config_features": (
                Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                | Si91xConfigFeatureBitMap.EnahanceMaxPsp
            ),
            "bt_features": 0,
            "ble_features": 0,
            "ble_custom_ext_features": 0,
            "ca_cert": ca_cert,
        }
        return pytest.mark.config("wifi_dut", wifi=config)

    # ------------------------------------------------------------------
    # Sniffer / power save helpers
    # ------------------------------------------------------------------
    def _get_capture_file(self):
        capture_name = self.capture_file or f"{self.testcase}.pcap"
        capture_name = (
            capture_name.replace("[", "_")
            .replace("]", "_")
            .replace("/", "_")
            .replace(" ", "_")
        )
        if not capture_name.endswith(".pcap"):
            capture_name = f"{capture_name}.pcap"
        return capture_name

    def _enable_powersave(self):
        wifi = self.wifi_dut.interfaces.wifi
        self.logger.info("Enabling Wi-Fi and BT power save on DUT")
        wifi.set_performance_profile(mode="power_save_low_latency")
        wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
        )
        self.logger.info("Wi-Fi and BT power save enabled successfully")

    def _high_performance_for_traffic(self):
        """Keep radio awake for TCP/HTTPS — coex powersave breaks dual_stack.*_iperf connect."""
        wifi = self.wifi_dut.interfaces.wifi
        self.logger.info("Switching to high_performance before application traffic")
        try:
            wifi.enable_bt_power_save(psp_mode=0, psp_type=0)
        except Exception as ex:
            self.logger.info(f"BT powersave disable ignored: {ex}")
        wifi.set_performance_profile(mode="high_performance")
        time.sleep(1)

    # ------------------------------------------------------------------
    # Association and IP configuration
    # ------------------------------------------------------------------
    def _ensure_lwip_ready(self, wifi, expected_ip):
        try:
            ip_config = wifi.display_device_ip_lwip(ip_version="ipv4")
        except Exception as ex:
            raise AssertionError(
                "lwIP host netif is not available after sl_net_init_client"
            ) from ex
        lwip_ip = ip_config.ip.decode()
        assert lwip_ip == expected_ip, (
            f"NWP IPv4 was not synchronized to lwIP: "
            f"expected {expected_ip}, got {lwip_ip}"
        )
        self.logger.info(f"Verified lwIP synchronized IPv4 address: {lwip_ip}")

    def _ap_security(self):
        ap = self.wifi_access_point.interfaces.wifi
        sec_name = ap.security.name if hasattr(ap.security, "name") else str(ap.security)
        return self.SECURITY_MAP.get(sec_name, 2), sec_name.lower()

    def _scan(self, required=False):
        """Optional wifi.scan — dual-mode agent often returns 0x11; net.up does join."""
        ap = self.wifi_access_point.interfaces.wifi
        try:
            scan_ok, reason = self.sl_collections.scan(
                self.wifi_dut, channel=ap.channel or 0
            )
            if not scan_ok:
                self.logger.info(
                    f"Scan skipped/failed ({reason}); continuing with net.up/join"
                )
                if required:
                    assert scan_ok, f"scan failed: {reason}"
                return False
            return True
        except Exception as ex:
            self.logger.info(f"Scan exception ({ex}); continuing with net.up/join")
            if required:
                raise
            return False

    def _resolve_static_ip(self):
        """Prefer configured static; otherwise derive free IP from wifi_client subnet."""
        if self.static_ip:
            return self.static_ip, self.static_subnet, self.static_gateway
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        parts = host_ip.split(".")
        # Use .11 in same /24 as host (lab AP LAN is typically 192.168.50.0/24)
        return f"{parts[0]}.{parts[1]}.{parts[2]}.11", "255.255.255.0", f"{parts[0]}.{parts[1]}.{parts[2]}.1"

    def _net_join(self, wifi, ip_type="ipv4"):
        """Scan (best-effort) + set_profile + net.up (NWP DHCP, sync IP to lwIP in dual mode)."""
        ap = self.wifi_access_point.interfaces.wifi
        security, _ = self._ap_security()

        self.logger.info("Boot stack / scan and connect to AP")
        wifi.is_external_stack_enabled = True
        self._scan(required=False)

        wifi.sl_net_set_profile(
            ssid=ap.ssid,
            security=security,
            credential_id=1 if security != 0 else 0,
            priority=1,
            profile_id=0,
            ip_type=ip_type,
            channel=ap.channel,
        )
        if security != 0:
            wifi.sl_net_set_credential(credential=ap.passphrase, cred_id=1)

        self.logger.info(
            "net.up → associate + IP (NWP DHCP / sync to lwIP when dual-mode)"
        )
        wifi.sl_net_up(mode="client", timeout=100)
        wifi.associated = True
        wifi.networked = True
        time.sleep(2)

        ip_config = wifi.print_ip_command_handler(mode="client", ip_version="ipv4")
        device_ip = ip_config.ip.decode()
        gateway = ip_config.gateway.decode()
        subnet = ip_config.netmask.decode()
        self.logger.info(f"DUT IP after net.up: {device_ip}/{subnet} gw={gateway}")
        return device_ip, gateway, subnet

    def _lwip_join_and_static_ip(self, wifi):
        """Bypass/lwIP static path for test_agent_6.

        ``lwip.configure_ip`` is NOT registered on dual-stack agent (async 0x1).
        Working path:
          1) connect_lwip
          2) apply static via ``net.configure_ip`` (start_ip)
          3) assert print_ip shows the static address
        """
        ap = self.wifi_access_point.interfaces.wifi
        _, sec_name = self._ap_security()
        static_ip, static_subnet, static_gateway = self._resolve_static_ip()
        self.static_ip = static_ip
        self.static_subnet = static_subnet
        self.static_gateway = static_gateway

        wifi.is_external_stack_enabled = True
        self.logger.info("lwIP join to AP")
        wifi.lwip_join(
            ssid=ap.ssid,
            passphrase=ap.passphrase,
            security=sec_name,
            timeout=60,
        )
        wifi.associated = True

        self.logger.info(
            f"Configure static IP via net.configure_ip (not lwip.configure_ip): "
            f"{static_ip}/{static_subnet} gw={static_gateway}"
        )
        # Use registered net.configure_ip — applies on NWP and is the only working
        # static IP CLI on test_agent_6 after connect_lwip.
        saved = wifi.is_external_stack_enabled
        wifi.is_external_stack_enabled = False
        try:
            wifi.start_ip(
                static_ip=static_ip,
                static_subnet=static_subnet,
                static_gateway=static_gateway,
                timeout=30,
            )
        finally:
            wifi.is_external_stack_enabled = saved
        wifi.networked = True

        ip_config = wifi.print_ip_command_handler(mode="client", ip_version="ipv4")
        self.dut_ip = ip_config.ip.decode()
        self.logger.info(f"Static IP after configure: {self.dut_ip}")
        assert self.dut_ip == static_ip, (
            f"Expected static IP {static_ip}, got {self.dut_ip}"
        )
        return self.dut_ip

    def _nwp_static_ip(self, wifi, device_ip, subnet=None, gateway=None):
        """Configure NWP/offload stack with the same static IP."""
        subnet = subnet or self.static_subnet
        gateway = gateway or self.static_gateway
        saved = wifi.is_external_stack_enabled
        wifi.is_external_stack_enabled = False
        try:
            self.logger.info(
                f"Pass IP to NWP and configure NWP statically: {device_ip}"
            )
            self.sl_collections.configure_dut_in_static_ip(
                self.wifi_dut,
                static_ip=device_ip,
                static_subnet=subnet,
                static_gateway=gateway,
            )
        finally:
            wifi.is_external_stack_enabled = saved
        wifi.networked = True
        return device_ip

    def _prepare_dual_stack_dhcp(self, wifi, ip_type="ipv4"):
        """Dual-mode: net.up does NWP DHCP and syncs IP to lwIP statically."""
        self.logger.info("Boot dual-mode stack (NWP + lwIP)")
        return self._net_join(wifi, ip_type=ip_type)

    def _acquire_nwp_ipv6(self, wifi):
        saved = wifi.is_external_stack_enabled
        wifi.is_external_stack_enabled = False
        try:
            ok6, ip6 = self.sl_collections.configure_ip(
                self.wifi_dut, retry_count=3, ip_version="ipv6"
            )
        finally:
            wifi.is_external_stack_enabled = saved
        assert ok6, f"NWP IPv6 DHCP failed: {ip6}"
        self.logger.info(f"NWP IPv6 config: {ip6}")
        return ip6

    @classmethod
    def _assert_global_ipv6(cls, ipv6_config):
        """Validate the (link-local, global, gateway) tuple returned by NWP DHCPv6.

        ``start_ip`` splits the CLI output positionally without inspecting it, so a
        lease that yields no routable address still reports success.
        """
        assert isinstance(ipv6_config, tuple) and len(ipv6_config) == 3, (
            f"Unexpected IPv6 config from NWP DHCPv6: {ipv6_config}"
        )
        link_local, global_ipv6, ipv6_gateway = (str(v).strip() for v in ipv6_config)
        cls.logger.info(
            f"NWP IPv6 link-local={link_local} global={global_ipv6} gw={ipv6_gateway}"
        )
        try:
            parsed = ipaddress.IPv6Address(global_ipv6.split("%")[0])
        except ValueError as ex:
            raise AssertionError(
                f"DUT did not get a valid global IPv6 from DHCPv6: {global_ipv6!r}"
            ) from ex
        assert not parsed.is_link_local and not parsed.is_unspecified, (
            f"DUT global IPv6 is not a routable address: {global_ipv6}"
        )
        return str(parsed)

    def _safe_leave(self, wifi):
        try:
            wifi.leave()
        except Exception as ex:
            self.logger.info(f"leave() ignored: {ex}")

    # ------------------------------------------------------------------
    # Reachability
    # ------------------------------------------------------------------
    def _ping_dut(self, device_ip):
        status = self.sl_collections.ping(
            device_ip=device_ip, ping_count=10, retry_count=3
        )
        assert status, f"DUT NOT RESPONDING FOR PING REQUEST: {device_ip}"
        return status

    def _ping_gateway(self, gateway):
        status = ping(gateway, 10)
        assert status, f"Gateway {gateway} is not reachable"
        return status

    def _host_ipv6(self):
        """Global IPv6 of the LAN backend host used as the iperf peer."""
        client_wifi = self.wifi_client.interfaces.wifi
        backend_ip = client_wifi.get_ip_address(version=6, addr_type="global")
        assert backend_ip, "AP backend (wifi_client) has no global IPv6 address"
        return str(ipaddress.IPv6Address(str(backend_ip).split("%")[0].strip()))

    # ------------------------------------------------------------------
    # Traffic
    # ------------------------------------------------------------------
    @staticmethod
    def _net_perf_port_kwargs(port):
        """Return init_server/init_client kwargs with iperf host port override."""
        if port is None:
            return {}
        defaults = UtfConfig.instance().defaults.get("net_perf", {})
        host = deepcopy(defaults.get("host", {"TCP": {}, "UDP": {}}))
        for proto in host:
            host[proto]["port"] = port
        return {"host": host}

    def _run_nwp_traffic(
        self,
        device_ip,
        host_ip,
        timeout=30,
        traffic_type=None,
        port=None,
        buffer_size_tcp=1460,
        buffer_size_udp=1470,
        ip_version=4,
    ):
        """NWP/offload traffic via dual_stack.offload_iperf (local, not sl_collections)."""
        traffic_type = traffic_type or self.traffic_type
        protocol = self.protocol
        wifi = self.wifi_dut.interfaces.wifi
        net_perf = self.net_perf_client.interfaces.net_perf
        iperf_kwargs = self._net_perf_port_kwargs(port)
        protocol_family = 24 if ip_version == 6 else 2
        self._high_performance_for_traffic()
        saved = wifi.is_external_stack_enabled
        wifi.is_external_stack_enabled = False
        try:
            if traffic_type == "TX":
                self.logger.info(
                    "starting the server from Remote device (NWP offload stack)"
                )
                net_perf.init_server(
                    host_ip=host_ip,
                    device_ip=device_ip,
                    protocol=protocol,
                    time_out=timeout,
                    version=ip_version,
                    **iperf_kwargs,
                )
                net_perf.start()
                time.sleep(2)
                iperf_port = port or net_perf.server_port
                if protocol == "TCP":
                    self.logger.info("sending data from DUT over NWP offload stack")
                    wifi.dual_stack_offload_iperf_command_handler(
                        family=protocol_family,
                        transfer_type=1,
                        protocol=6,
                        port=iperf_port,
                        remote_ip=host_ip,
                        size=buffer_size_tcp,
                        ttl=timeout,
                        throughput_type=1,
                        timeout=timeout + 20,
                    )
                elif protocol == "UDP":
                    self.logger.info("sending data from DUT over NWP offload stack")
                    wifi.dual_stack_offload_iperf_command_handler(
                        family=protocol_family,
                        transfer_type=2,
                        protocol=17,
                        port=iperf_port,
                        remote_ip=host_ip,
                        size=buffer_size_udp,
                        ttl=timeout,
                        throughput_type=2,
                        timeout=timeout + 20,
                    )
                tp = net_perf.process_output()
                assert tp is not None, "NWP offload throughput not found"
                self.logger.info("NWP offload data transfer is successful")
                net_perf.iperf_process.stop(5)
            else:
                net_perf.init_client(
                    host_ip=host_ip,
                    device_ip=device_ip,
                    protocol=protocol,
                    time_out=timeout,
                    version=ip_version,
                    bandwidth="60M",
                    **iperf_kwargs,
                )
                iperf_port = port or net_perf.client_port

                def start_client():
                    time.sleep(3)
                    net_perf.start()

                rx_thread = Thread(target=start_client, args=())
                rx_thread.start()
                if protocol == "TCP":
                    wifi.dual_stack_offload_iperf_command_handler(
                        family=protocol_family,
                        transfer_type=1,
                        protocol=6,
                        port=iperf_port,
                        remote_ip=host_ip,
                        size=buffer_size_tcp,
                        ttl=timeout,
                        throughput_type=3,
                        timeout=timeout + 20,
                    )
                elif protocol == "UDP":
                    wifi.dual_stack_offload_iperf_command_handler(
                        family=protocol_family,
                        transfer_type=2,
                        protocol=17,
                        port=iperf_port,
                        remote_ip=host_ip,
                        size=buffer_size_udp,
                        ttl=timeout,
                        throughput_type=4,
                        timeout=timeout + 20,
                    )
                rx_thread.join()
                self.logger.info("NWP offload data transfer is successful")
                net_perf.iperf_process.stop(5)
                time.sleep(5)
        finally:
            wifi.is_external_stack_enabled = saved

    def _run_lwip_traffic(
        self,
        device_ip,
        host_ip,
        timeout=30,
        traffic_type=None,
        port=None,
        buffer_size_tcp=1460,
        buffer_size_udp=1470,
    ):
        """lwIP traffic via dual_stack.lwip_iperf (local, not sl_collections)."""
        traffic_type = traffic_type or self.traffic_type
        protocol = self.protocol
        wifi = self.wifi_dut.interfaces.wifi
        net_perf = self.net_perf_client.interfaces.net_perf
        iperf_kwargs = self._net_perf_port_kwargs(port)
        protocol_family = 2
        self._high_performance_for_traffic()
        saved = wifi.is_external_stack_enabled
        wifi.is_external_stack_enabled = True
        try:
            if traffic_type == "TX":
                self.logger.info("starting the server from Remote device (lwIP stack)")
                net_perf.init_server(
                    host_ip=host_ip,
                    device_ip=device_ip,
                    protocol=protocol,
                    time_out=timeout,
                    version=4,
                    **iperf_kwargs,
                )
                net_perf.start()
                time.sleep(2)
                iperf_port = port or net_perf.server_port
                if protocol == "TCP":
                    self.logger.info("sending data from DUT over lwIP stack")
                    wifi.dual_stack_lwip_iperf_command_handler(
                        family=protocol_family,
                        transfer_type=1,
                        protocol=6,
                        port=iperf_port,
                        remote_ip=host_ip,
                        size=buffer_size_tcp,
                        ttl=timeout,
                        throughput_type=1,
                        timeout=timeout + 20,
                    )
                elif protocol == "UDP":
                    self.logger.info("sending data from DUT over lwIP stack")
                    wifi.dual_stack_lwip_iperf_command_handler(
                        family=protocol_family,
                        transfer_type=2,
                        protocol=17,
                        port=iperf_port,
                        remote_ip=host_ip,
                        size=buffer_size_udp,
                        ttl=timeout,
                        throughput_type=2,
                        timeout=timeout + 20,
                    )
                tp = net_perf.process_output()
                assert tp is not None, "lwIP throughput not found"
                self.logger.info("lwIP data transfer is successful")
                net_perf.iperf_process.stop(5)
            else:
                net_perf.init_client(
                    host_ip=host_ip,
                    device_ip=device_ip,
                    protocol=protocol,
                    time_out=timeout,
                    version=4,
                    bandwidth="60M",
                    **iperf_kwargs,
                )
                iperf_port = port or net_perf.client_port

                def start_client():
                    time.sleep(3)
                    net_perf.start()

                rx_thread = Thread(target=start_client, args=())
                rx_thread.start()
                if protocol == "TCP":
                    wifi.dual_stack_lwip_iperf_command_handler(
                        family=protocol_family,
                        transfer_type=1,
                        protocol=6,
                        port=iperf_port,
                        remote_ip=host_ip,
                        size=buffer_size_tcp,
                        ttl=timeout,
                        throughput_type=3,
                        timeout=timeout + 20,
                    )
                elif protocol == "UDP":
                    wifi.dual_stack_lwip_iperf_command_handler(
                        family=protocol_family,
                        transfer_type=2,
                        protocol=17,
                        port=iperf_port,
                        remote_ip=host_ip,
                        size=buffer_size_udp,
                        ttl=timeout,
                        throughput_type=4,
                        timeout=timeout + 20,
                    )
                rx_thread.join()
                assert net_perf.process_output() is not None, (
                    "lwIP RX throughput not found"
                )
                self.logger.info("lwIP data transfer is successful")
                net_perf.iperf_process.stop(5)
                time.sleep(5)
        finally:
            wifi.is_external_stack_enabled = saved

    def _run_parallel_tcp_tx(
        self, device_ip, host_ip, nwp_port=NWP_IPERF_PORT, lwip_port=LWIP_IPERF_PORT,
        timeout=30,
    ):
        """TCP TX on both stacks (NWP :nwp_port, lwIP :lwip_port)."""
        self.logger.info(
            f"TCP TX on NWP port {nwp_port} then lwIP port {lwip_port}, IP={device_ip}"
        )
        self._run_nwp_traffic(
            device_ip=device_ip,
            host_ip=host_ip,
            timeout=timeout,
            traffic_type="TX",
            port=nwp_port,
        )
        self._run_lwip_traffic(
            device_ip=device_ip,
            host_ip=host_ip,
            timeout=timeout,
            traffic_type="TX",
            port=lwip_port,
        )
        self.logger.info("NWP+lwIP TCP TX on both stacks completed")

    # ------------------------------------------------------------------
    # HTTPS on the NWP stack
    # ------------------------------------------------------------------
    def _https_otaf_nwp(self, wifi):
        assert self.http_server is not None, "http_server required for OTAF"
        assert self.rps_path, "rps_path required for OTAF"
        wifi.is_external_stack_enabled = False
        status_http = self.http_server.interfaces.http.started
        assert status_http, "HTTPS OTAF server is inactive"
        self.logger.info("dut fw version before upgrade...")
        fw_before = wifi.version()
        self.logger.info(f"dut fw version before upgrade = {fw_before}")
        self.logger.info("Initiate HTTPS OTAF using NWP stack")
        http_interface = self.http_server.interfaces.http.interface
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address(http_interface)
        ota_server_host = getattr(
            self.http_server.interfaces.http, "host_name", host_ip
        )
        wifi.firmware_upgrade(
            flags=1,
            ip_address=host_ip,
            http_url=self.rps_path,
            port=443,
            host_name=ota_server_host,
        )

    def _https_get_nwp(self, wifi):
        assert self.http_server is not None and self.http_client is not None
        assert self.index_path, "index_path required for HTTPS GET"
        wifi.is_external_stack_enabled = False
        self.wifi_dut.interfaces["http"] = wifi
        wifi.http_client_init(https_enable=True)
        self.logger.info("Perform HTTPS GET on NWP stack")
        status_dut, content_dut = wifi.http_get(
            self.http_server.interfaces.http, self.index_path, server_port=443
        )
        _status_client, content_client = self.http_client.interfaces.http.http_get(
            self.http_server.interfaces.http, self.index_path
        )
        assert content_dut == content_client, "HTTPS GET content mismatch"
        self.logger.info(f"HTTPS GET status_dut={status_dut}")
        wifi.http_client_deinit()

    # ------------------------------------------------------------------
    # Test cases
    # ------------------------------------------------------------------
    def run(self):
        self.logger.info(
            f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}"
        )
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        capture_name = self._get_capture_file()
        self.logger.info(f"Starting sniffer capture file: {capture_name}")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_name)
        wifi = self.wifi_dut.interfaces.wifi
        try:
            self._run_cases(wifi)
        finally:
            self.logger.info("Stop Sniffer finally")
            self.wifi_sniffer.interfaces.capture.stop_capture()

    def _case_c794003(self, wifi):
        """C794003: Static IP path on lwIP (TCP/IP bypass) + NWP static mirror.

        On test_agent_6, ``lwip.configure_ip`` is not registered (async 0x1).
        Bypass ``net.up`` brings up lwIP via host DHCP; that address is then
        applied statically on NWP (steps 6-7) and used for ping/traffic.
        """
        self.logger.info("===== C794003: Static IP to lwIP + NWP =====")
        # Steps 3-5: boot LwIP (bypass), scan(best-effort), connect, acquire IP on lwIP
        wifi.is_external_stack_enabled = True
        device_ip, gateway, subnet = self._net_join(wifi)
        self.static_ip = device_ip
        self.static_subnet = subnet
        self.static_gateway = gateway
        self.logger.info(
            f"lwIP IP after bypass net.up: {device_ip}/{subnet} gw={gateway}"
        )

        # Steps 6-7: pass acquired IP to NWP and configure NWP statically
        self._nwp_static_ip(wifi, device_ip, subnet=subnet, gateway=gateway)
        self._high_performance_for_traffic()

        # Steps 8-9
        self.logger.info("Ping DUT from network")
        self._ping_dut(device_ip)
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        self.logger.info("Run application traffic (lwIP TX)")
        wifi.is_external_stack_enabled = True
        self._run_lwip_traffic(device_ip=device_ip, host_ip=host_ip, timeout=30, traffic_type="TX")
        # Step 10
        self.logger.info("Disconnect")
        self._safe_leave(wifi)

    def _case_c794004(self, wifi):
        """C794004: Dual-mode DHCP IPv4+IPv6 on NWP, sync to lwIP, ping, IPv6 iperf."""
        self.logger.info("===== C794004: Dual IP (IPv4+IPv6) offload DHCP =====")
        for _ in range(self.iterations):
            # Steps 3-5: dual-mode bring-up, NWP DHCPv4 followed by NWP DHCPv6
            device_ip, gateway, subnet = self._prepare_dual_stack_dhcp(wifi)
            self.logger.info("Acquire IPv6 via NWP DHCP (dual IPv4+IPv6)")
            global_ipv6 = self._assert_global_ipv6(self._acquire_nwp_ipv6(wifi))

            # Steps 6-7: dual mode syncs the NWP DHCP IPv4 onto the host lwIP netif
            wifi.is_external_stack_enabled = True
            self.logger.info(
                f"Host lwIP holds NWP DHCP IPv4 statically: {device_ip}/{subnet} gw={gateway}"
            )
            self._ensure_lwip_ready(wifi, expected_ip=device_ip)

            # Steps 8-9
            self._high_performance_for_traffic()
            self._ping_gateway(gateway)
            self.logger.info("Ping DUT from network on both address families")
            self._ping_dut(device_ip)
            self._ping_dut(global_ipv6)
            host_ipv6 = self._host_ipv6()
            self.logger.info(
                f"Run application traffic (NWP IPv6 TX) DUT={global_ipv6} host={host_ipv6}"
            )
            self._run_nwp_traffic(
                device_ip=global_ipv6,
                host_ip=host_ipv6,
                timeout=30,
                traffic_type="TX",
                ip_version=6,
            )
            # Step 10
            self.logger.info("Disconnect")
            self._safe_leave(wifi)

    def _case_c794007(self, wifi):
        """C794007: TCP TX on lwIP, HTTPS OTAF on NWP, then lwIP reconnect + TX.

        test_agent_6: bypass + dual-mode are mutually exclusive. Dual-mode keeps
        both stacks available so lwIP TCP and NWP HTTPS can run without reflash.
        """
        self.logger.info("===== C794007: lwIP TCP TX + NWP HTTPS OTAF =====")
        # Steps 1-4: dual-mode bring-up, ping
        device_ip, gateway, _subnet = self._prepare_dual_stack_dhcp(wifi)
        self._high_performance_for_traffic()
        self._ping_gateway(gateway)
        self._ping_dut(device_ip)
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()

        # Steps 5-6: TCP TX on lwIP (must succeed before HTTPS)
        self.logger.info("TCP TX on lwIP stack")
        self._run_lwip_traffic(device_ip=device_ip, host_ip=host_ip, timeout=30, traffic_type="TX")

        # Steps 7-10: NWP HTTPS OTAF (certs loaded via marker)
        self.logger.info("Switch to NWP for HTTPS OTAF (disable lwIP path)")
        wifi.is_external_stack_enabled = False
        self._https_otaf_nwp(wifi)

        # Steps 11-14: re-init lwIP path, reconnect, ping, TCP TX
        self.logger.info("Switch back to lwIP after OTAF")
        wifi.is_external_stack_enabled = True
        wifi.set_state(["sl_net_init_client"])
        wifi = self.wifi_dut.interfaces.wifi
        device_ip, gateway, _subnet = self._prepare_dual_stack_dhcp(wifi)
        self._high_performance_for_traffic()
        self._ping_gateway(gateway)
        self._ping_dut(device_ip)
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        self.logger.info("TCP TX on lwIP after OTAF")
        self._run_lwip_traffic(device_ip=device_ip, host_ip=host_ip, timeout=30, traffic_type="TX")
        self._safe_leave(wifi)

    def _case_c794009(self, wifi):
        """C794009: TCP TX on NWP (:5001) and lwIP (:5002)."""
        self.logger.info("===== C794009: Parallel TCP TX on two stacks =====")
        for _ in range(self.iterations):
            # Dual-mode required so both stacks share DHCP IP (bypass exclusive)
            device_ip, gateway, _subnet = self._prepare_dual_stack_dhcp(wifi)
            self._high_performance_for_traffic()
            self._ping_gateway(gateway)
            self._ping_dut(device_ip)
            host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            self._run_parallel_tcp_tx(
                device_ip=device_ip,
                host_ip=host_ip,
                nwp_port=self.NWP_IPERF_PORT,
                lwip_port=self.LWIP_IPERF_PORT,
                timeout=30,
            )
            self.logger.info("Disconnect")
            self._safe_leave(wifi)

    def _case_c794013(self, wifi):
        """C794013: TCP TX on lwIP, HTTPS GET on NWP, then lwIP reconnect + TX."""
        self.logger.info("===== C794013: lwIP TCP TX + NWP HTTPS GET =====")
        device_ip, gateway, _subnet = self._prepare_dual_stack_dhcp(wifi)
        self._high_performance_for_traffic()
        self._ping_gateway(gateway)
        self._ping_dut(device_ip)
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()

        # Steps 5-6: lwIP TCP TX (must succeed before HTTPS GET)
        self.logger.info("TCP TX on lwIP stack")
        self._run_lwip_traffic(device_ip=device_ip, host_ip=host_ip, timeout=30, traffic_type="TX")

        # Steps 7-11: NWP HTTPS GET
        self.logger.info("Switch to NWP for HTTPS GET")
        wifi.is_external_stack_enabled = False
        self._https_get_nwp(wifi)

        # Steps 12-15: switch back to lwIP, reconnect, TCP TX
        self.logger.info("Switch back to lwIP")
        wifi.is_external_stack_enabled = True
        self._safe_leave(wifi)
        device_ip, gateway, _subnet = self._prepare_dual_stack_dhcp(wifi)
        self._high_performance_for_traffic()
        self._ping_gateway(gateway)
        self._ping_dut(device_ip)
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        self.logger.info("TCP TX on lwIP after HTTPS GET")
        self._run_lwip_traffic(device_ip=device_ip, host_ip=host_ip, timeout=30, traffic_type="TX")
        self._safe_leave(wifi)

    def _case_c794000_c794001(self, wifi):
        for _ in range(self.iterations):
            device_ip, _gateway, _subnet = self._prepare_dual_stack_dhcp(wifi)
            self.logger.info("Ping DUT from network")
            self._high_performance_for_traffic()
            self._ping_dut(device_ip)
            host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            self._run_nwp_traffic(
                device_ip=device_ip,
                host_ip=host_ip,
                timeout=30,
                traffic_type=self.traffic_type,
            )
            self._safe_leave(wifi)

    def _case_c794012(self, wifi):
        device_ip, _gateway, _subnet = self._prepare_dual_stack_dhcp(wifi)
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        self._high_performance_for_traffic()
        self._run_lwip_traffic(device_ip=device_ip, host_ip=host_ip, timeout=30, traffic_type="TX")
        wifi.is_external_stack_enabled = False
        assert self.mqtt_server is not None and self.mqtt_client is not None
        topic = "mytesttopic_C794012"
        message = "".join(random.choices(string.ascii_uppercase + string.digits, k=300))
        self.wifi_dut.interfaces["mqtt"] = wifi
        self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client", qos=1
        )
        self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
            server=self.mqtt_server.interfaces.mqtt
        )
        self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
            server=self.mqtt_server.interfaces.mqtt
        )
        time.sleep(5)
        self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(
            topic=topic, qos=Si91xMqttQos.QOS1
        )
        self.wifi_dut.interfaces.mqtt.mqtt_client_subscribe(
            topic=topic, qos=Si91xMqttQos.QOS1
        )
        time.sleep(5)
        self.wifi_dut.interfaces.mqtt.mqtt_client_publish(
            topic=topic, message=message, qos=Si91xMqttQos.QOS1, timeout=20
        )
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].payload.decode() == message
        wifi.is_external_stack_enabled = True
        self._safe_leave(wifi)
        device_ip, _gateway, _subnet = self._prepare_dual_stack_dhcp(wifi)
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        self._run_lwip_traffic(device_ip=device_ip, host_ip=host_ip, timeout=30, traffic_type="TX")
        self._safe_leave(wifi)

    def _case_c794018(self, wifi):
        device_ip, _gateway, _subnet = self._prepare_dual_stack_dhcp(wifi)
        self._enable_powersave()
        self._ping_dut(device_ip)
        self.wifi_dut.reset()
        wifi = self.wifi_dut.interfaces.wifi
        wifi.set_state(["sl_net_init_client"])
        device_ip, _gateway, _subnet = self._prepare_dual_stack_dhcp(wifi)
        self._enable_powersave()
        self._ping_dut(device_ip)
        self._safe_leave(wifi)

    def _run_cases(self, wifi):
        handlers = {
            "c794000": self._case_c794000_c794001,
            "c794001": self._case_c794000_c794001,
            "c794003": self._case_c794003,
            "c794004": self._case_c794004,
            "c794007": self._case_c794007,
            "c794009": self._case_c794009,
            "c794012": self._case_c794012,
            "c794013": self._case_c794013,
            "c794018": self._case_c794018,
        }
        handler = handlers.get(self.testcase)
        assert handler is not None, f"Unsupported testcase: {self.testcase}"
        handler(wifi)


@pytest.mark.firmware_app(DualStack.FIRMWARE_APP_IPV4)
@DualStack.wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=DualStack.END_STATE)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_fetch_dhcp_ip_tcp_rx_dual_stack_c794001(
    firmware_loader,
    request,
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    sl_collections,
    net_perf_client,
    wifi_client,
    protocol,
):
    """C794001: dual-mode LwIP boot, NWP DHCP, static LwIP sync, ping, then NWP TCP RX.

    Steps:
      1. Initialize DUT
      2. Configure LwIP with dual mode bit enable
      3. Boot LwIP stack
      4. Scan and connect to AP
      5. DUT will get IP via NWP
      6. Configure LWIP stack statically
      7. Ping DUT from network
      8. TCP RX traffic on NWP offload stack (dual_stack.offload_iperf)
    """
    DualStack.run_test(
        sl_collections=sl_collections,
        wifi_dut=wifi_dut,
        wifi_sniffer=wifi_sniffer,
        wifi_access_point=wifi_access_point,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
        iterations=1,
        traffic_type="RX",
        testcase="c794001",
        capture_file=request.node.name,
    )


@pytest.mark.start_state("wifi_dut", wifi="sl_net_init_client")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=DualStack.END_STATE)
@DualStack.wifi_dut_marker()
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.firmware_app(DualStack.FIRMWARE_APP_IPV4)
def test_wifi_sdk_fetch_static_ip_assign_lwip_c794003(
    firmware_loader,
    request,
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    sl_collections,
    net_perf_client,
    wifi_client,
    protocol,
):
    """C794003: Static IP on lwIP (TCP/IP bypass), sync same IP to NWP, ping, traffic.

    Steps (test_agent_6):
      1. Initialize DUT
      2. Configure LwIP for Static (SL_SI91X_TCP_IP_FEAT_BYPASS) — marker
      3-5. Boot + connect via net.up (bypass host DHCP on lwIP)
      6-7. Pass that IP to NWP and configure NWP statically
      8. Ping DUT from network
      9. Run application traffic (lwIP TX)
      10. Disconnect

    Note: ``lwip.configure_ip`` is not registered on dual-stack agent (fails async 0x1);
    bypass ``net.up`` + ``net.configure_ip`` is the working static/IP path.
    """
    DualStack.run_test(
        sl_collections=sl_collections,
        wifi_dut=wifi_dut,
        wifi_sniffer=wifi_sniffer,
        wifi_access_point=wifi_access_point,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
        iterations=1,
        traffic_type="TX",
        testcase="c794003",
        capture_file=request.node.name,
        static_ip=DualStack.DEFAULT_STATIC_IP,
        static_subnet=DualStack.DEFAULT_STATIC_SUBNET,
        static_gateway=DualStack.DEFAULT_STATIC_GATEWAY,
    )


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=DualStack.END_STATE)
@DualStack.wifi_dut_marker(
    tcp_feat_bit=Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.IPv6Mode
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point", wifi=DualStack.ap_ipv6_config())
@pytest.mark.firmware_app(DualStack.FIRMWARE_APP_IPV6)
def test_wifi_sdk_fetch_check_dual_ip_offload_stack_c794004(
    firmware_loader,
    request,
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    sl_collections,
    net_perf_client,
    wifi_client,
    protocol,
):
    """C794004: DHCP IPv4+IPv6 on NWP (dual-mode), sync IPv4 to lwIP, ping, IPv6 iperf.

    Steps:
      1. Initialize DUT
      2. Configure NWP for DHCP (EXT_TCP_IP_DUAL_MODE_ENABLE)
      3. Boot NWP with internal stack
      4. Scan and connect to AP
      5. DUT gets IPv4 and IPv6 via DHCP
      6. Pass acquired IPv4 to host (lwIP) stack
      7. Host stack uses that IP statically (SDK set_sta_link_up)
      8. Ping DUT from network (IPv4 and IPv6)
      9. Run application traffic (NWP IPv6 TX)
      10. Disconnect
    """
    DualStack.run_test(
        sl_collections=sl_collections,
        wifi_dut=wifi_dut,
        wifi_sniffer=wifi_sniffer,
        wifi_access_point=wifi_access_point,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
        iterations=5,
        traffic_type="TX",
        testcase="c794004",
        capture_file=request.node.name,
    )


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@DualStack.wifi_dut_marker(
    tcp_feat_bit=Si91xTCPIPFeatureBitMap.HTTPClient
    | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid
    | Si91xTCPIPFeatureBitMap.SSL,
    ext_tcp_bit=Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF,
    ca_cert=[
        "ca-chain.cert.pem",
        "SL_NET_SIGNING_CERTIFICATE",
        "SL_NET_TLS_SERVER_CREDENTIAL_START",
    ],
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"] + DualStack.END_STATE)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.firmware_app(DualStack.FIRMWARE_APP_IPV4)
def test_wifi_sdk_tcp_tx_lwip_https_otaf_nwp_C794007(
    firmware_loader,
    request,
    utf_constants,
    http_server,
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    sl_collections,
    net_perf_client,
    protocol,
    wifi_client,
):
    """C794007: TCP TX on lwIP, HTTPS OTAF on NWP, then lwIP reconnect + TCP TX.

    Note: dual-mode is used (bypass + dual-mode are mutually exclusive) so both
    stacks can be exercised; lwIP path uses TCP/IP host stack for data.

    Steps:
      1-6. lwIP join/static, ping gateway, TCP TX
      7-10. Switch to NWP, certs (marker), HTTPS OTAF
      11-14. Re-init lwIP, connect, ping, TCP TX
    """
    DualStack.run_test(
        sl_collections=sl_collections,
        wifi_dut=wifi_dut,
        wifi_sniffer=wifi_sniffer,
        wifi_access_point=wifi_access_point,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
        http_server=http_server,
        iterations=1,
        traffic_type="TX",
        testcase="c794007",
        capture_file=request.node.name,
        rps_path=utf_constants.get("rps_filename"),
    )


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=DualStack.END_STATE)
@DualStack.wifi_dut_marker(
    ca_cert=[
        "ca-chain.cert.pem",
        "SL_NET_SIGNING_CERTIFICATE",
        "SL_NET_TLS_SERVER_CREDENTIAL_START",
    ]
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.firmware_app(DualStack.FIRMWARE_APP_IPV4)
def test_wifi_sdk_tcp_tx_lwip_https_get_nwp_C794013(
    firmware_loader,
    request,
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    sl_collections,
    net_perf_client,
    protocol,
    wifi_client,
    http_server,
    index_path,
    http_client,
):
    """C794013: TCP TX on lwIP, HTTPS GET on NWP, then lwIP reconnect + TCP TX.

    Steps:
      1-6. lwIP join/static, ping gateway, TCP TX
      7-11. Switch to NWP, HTTPS GET, verify response
      12-15. Switch back to lwIP, connect, ping, TCP TX
    """
    DualStack.run_test(
        sl_collections=sl_collections,
        wifi_dut=wifi_dut,
        wifi_sniffer=wifi_sniffer,
        wifi_access_point=wifi_access_point,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
        http_server=http_server,
        http_client=http_client,
        index_path=index_path,
        iterations=1,
        traffic_type="TX",
        testcase="c794013",
        capture_file=request.node.name,
    )


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=DualStack.END_STATE)
@DualStack.wifi_dut_marker()
@pytest.mark.config(
    "net_perf_client",
    net_perf={
        "host": {
            "TCP": {"port": DualStack.NWP_IPERF_PORT},
            "UDP": {"port": 5202},
        }
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.firmware_app(DualStack.FIRMWARE_APP_IPV4)
def test_wifi_sdk_parallel_tcp_data_transfer_on_two_stacks_C794009(
    firmware_loader,
    request,
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    sl_collections,
    net_perf_client,
    wifi_client,
    protocol,
):
    """C794009: TCP TX on NWP (port 5001) and lwIP (port 5002).

    Dual-mode is required so both stacks share the DHCP IP. Procedure text
    mentioning bypass is not used here (bypass and dual-mode are exclusive).
    Transfers run back-to-back on the shared net_perf host (one iperf process).

    Steps:
      1-4. Dual-mode bring-up, scan/connect, ping gateway
      5-9. TCP servers on 5001/5002; sockets on NWP and lwIP
      10-12. TX on both stacks, throughput asserts, sniffer capture
    """
    DualStack.run_test(
        sl_collections=sl_collections,
        wifi_dut=wifi_dut,
        wifi_sniffer=wifi_sniffer,
        wifi_access_point=wifi_access_point,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
        http_server=None,
        iterations=1,
        traffic_type="TX",
        testcase="c794009",
        capture_file=request.node.name,
    )
