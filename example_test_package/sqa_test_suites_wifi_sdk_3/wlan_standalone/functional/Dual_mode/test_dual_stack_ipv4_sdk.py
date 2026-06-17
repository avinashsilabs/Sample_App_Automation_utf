import time
import pytest
import random
import ipaddress
import threading
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xOperatingMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
)


""" Test Steps:
        1. Configure the DUT in Wlan for 2.4Gh with Dual stack and validate the WLAN functionality.

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Jyothi Nagireddy
"""

def logger():
    return get_logger(__name__)

def random_ipv6_addr(prefix: str) -> str:
    # Ensure the prefix is interpreted as a /64 network
    if '/' in prefix:
        prefix = prefix.split('/')[0]  # Remove any existing netmask from the prefix
    network = ipaddress.IPv6Network(f"{prefix}/64", strict=False)

    # Generate a random 64-bit interface identifier
    random_suffix = random.getrandbits(64)

    # Combine the prefix and the random suffix
    full_ip_int = int(network.network_address) | random_suffix
    full_ip = ipaddress.IPv6Address(full_ip_int)

    return str(full_ip)


wan_ipv6_addr = random_ipv6_addr("2001:db8:abcd:0012::")
wan_gateway = "2001:db8:abcd:0012::1"

class DualStack(ThreadBase):
    """Run dual-stack validation loop."""

    def __init__(
        self,
        wifi_sniffer,
        wifi_dut,
        wifi_access_point,
        sl_collections,
        net_perf_client,
        wifi_client,
        protocol,
        http_server=None,http_client=None,
            index_path=None,
        iterations=1, traffic_type="TX", testcase=None, rps_path=None, capture_file=None,
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

    def _ensure_lwip_ready(self, wifi):
        try:
            wifi.display_device_ip_lwip(ip_version="ipv4")
        except Exception as ex:
            raise AssertionError(
                "lwIP host netif is not available after sl_net_init_client"
            ) from ex

    def _get_capture_file(self):
        capture_name = self.capture_file or f"{self.testcase}.pcap"
        capture_name = capture_name.replace("[", "_").replace("]", "_").replace("/", "_").replace(" ", "_")
        if not capture_name.endswith(".pcap"):
            capture_name = f"{capture_name}.pcap"
        return capture_name

    def run(self):
        logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        capture_name = self._get_capture_file()
        logger().info(f"Starting sniffer capture file: {capture_name}")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_name)
        wifi = self.wifi_dut.interfaces.wifi
        if self.testcase == "c794018":
            wifi = self.wifi_dut.interfaces.wifi
            # 1. Initialize DUT is already handled by start_state -> sl_net_init_client
            self._ensure_lwip_ready(wifi)
            # 2. Start DHCP on lwIP stack
            wifi.is_external_stack_enabled = True

            self.sl_collections.connect(
                wifi_dut=self.wifi_dut,
                wifi_access_point=self.wifi_access_point,
            )
            lwip_ip_cfg = wifi.start_ip_lwip(timeout=30)
            logger().info(f"lwIP DHCP before reset: {lwip_ip_cfg}")
            status = self.sl_collections.ping(
                device_ip=lwip_ip_cfg.ip.decode(),
                ping_count=10,
                retry_count=3,
            )
            assert status, "Connectivity failed before reset"
            # 3. Reset DUT
            logger().info("Resetting DUT")
            self.wifi_dut.reset()
            logger().info("Re-initializing Wi-Fi client after reset")
            wifi = self.wifi_dut.interfaces.wifi
            wifi.set_state(["sl_net_init_client"])
            return wifi
            # 4. Boot DUT
            # handled by reset + sl_net_init_client
            # 5. Stack initializes
            self._ensure_lwip_ready(wifi)
            # 6. Acquire IP and test connectivity
            wifi.is_external_stack_enabled = True
            join_ok, reason = self.sl_collections.connect(
                wifi_dut=self.wifi_dut,
                wifi_access_point=self.wifi_access_point,
            )
            assert join_ok, f"Reconnect failed after reset: {reason}"
            lwip_ip_cfg = wifi.start_ip_lwip(timeout=30)
            logger().info(f"lwIP DHCP after reset: {lwip_ip_cfg}")
            status = self.sl_collections.ping(
                device_ip=lwip_ip_cfg.ip.decode(),
                ping_count=10,
                retry_count=3,
            )
            assert status, "Connectivity failed after reset"
            logger().info("disconnecting from AP")
            wifi.leave()
        if self.testcase in ("c794009"):
            for i in range(self.iterations):
                join_ok, reason = self.sl_collections.connect(
                    wifi_dut=self.wifi_dut,
                    wifi_access_point=self.wifi_access_point,
                )
                assert join_ok, f"connect failed: {reason}"
                saved = wifi.is_external_stack_enabled
                wifi.is_external_stack_enabled = False
                try:
                    ok, ip_config = self.sl_collections.configure_ip(
                        self.wifi_dut,
                        retry_count=3,
                        ip_version="ipv4",
                    )
                finally:
                    wifi.is_external_stack_enabled = saved
                assert ok, f"NWP DHCP failed: {ip_config}"
                device_ip = ip_config.ip.decode()
                gateway = ip_config.gateway.decode()
                subnet = ip_config.netmask.decode()
                logger().info(f"NWP DHCP IP: {device_ip}")
                logger().info(f"Gateway IP: {gateway}")
                self._ensure_lwip_ready(wifi)
                wifi.is_external_stack_enabled = True
                wifi.start_ip_lwip(
                    static_ip=device_ip,
                    static_subnet=subnet,
                    static_gateway=gateway,
                    timeout=10,
                )
                lwip_ip_cfg = wifi.display_device_ip_lwip()
                lwip_ip = lwip_ip_cfg.ip.decode()
                logger().info(f"lwIP IP: {lwip_ip}")
                assert lwip_ip == device_ip, (
                    f"Expected same IP on both stacks, but got "
                    f"NWP={device_ip}, lwIP={lwip_ip}"
                )
                status = ping(gateway, 10)
                assert status, f"Gateway {gateway} is not reachable"
                nwp_port = 5001
                lwip_port = 5002
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(
                    f"Starting parallel traffic on same IP {device_ip} "
                    f"with NWP port {nwp_port} and lwIP port {lwip_port}"
                )
                traffic_errors = []

                def run_nwp_traffic():
                    try:
                        self.sl_collections.run_traffic(
                            wifi_dut=self.wifi_dut,
                            net_perf_client=self.net_perf_client,
                            protocol=self.protocol,
                            device_ip=device_ip,
                            host_ip=host_ip,
                            timeout=30,
                            traffic_type=self.traffic_type,
                            ip_version=4,
                            port=nwp_port,
                        )
                    except Exception as ex:
                        traffic_errors.append(ex)

                def run_lwip_traffic():
                    try:
                        self.sl_collections.run_traffic(
                            wifi_dut=self.wifi_dut,
                            net_perf_client=self.net_perf_client,
                            protocol=self.protocol,
                            device_ip=device_ip,
                            host_ip=host_ip,
                            timeout=30,
                            traffic_type=self.traffic_type,
                            ip_version=4,
                            mode="lwip",
                            port=lwip_port,
                        )
                    except Exception as ex:
                        traffic_errors.append(ex)

                nwp_thread = threading.Thread(target=run_nwp_traffic, name="nwp_tcp_thread")
                lwip_thread = threading.Thread(target=run_lwip_traffic, name="lwip_tcp_thread")
                nwp_thread.start()
                lwip_thread.start()
                nwp_thread.join()
                lwip_thread.join()
                if traffic_errors:
                    raise traffic_errors[0]
                logger().info(
                    f"Parallel transfer completed successfully on same IP {device_ip} "
                    f"using ports {nwp_port} and {lwip_port}"
                )
                time.sleep(5)
                logger().info("disconnecting from AP")
                wifi.leave()
        if self.testcase in ("c794003", "c794007", "c794013", "c794012"):
            self.wifi_dut.interfaces.wifi.lwip_join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                                    passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                                    security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                    timeout=60)

            self.wifi_dut.interfaces.wifi.start_ip_lwip(static_ip="192.168.50.11",
                                                        static_subnet="255.255.255.0",
                                                        static_gateway="192.168.50.1")
            ip_config = self.wifi_dut.interfaces.wifi.display_device_ip_lwip()
            logger().info(f"*******{ip_config}")
            self.dut_ip = ip_config.ip.decode()
            host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            if self.testcase in ("c794007", "c794013", "c794012"):
                self.sl_collections.run_traffic(
                    wifi_dut=self.wifi_dut,
                    net_perf_client=self.net_perf_client,
                    protocol=self.protocol,
                    device_ip=self.dut_ip,
                    host_ip=host_ip,
                    timeout=30,
                    traffic_type=self.traffic_type,
                    ip_version=4, mode="lwip"
                )

                time.sleep(5)

            if self.testcase in ("c794003", "c794007", "c794013"):
                self.wifi_dut.interfaces.wifi.is_external_stack_enabled = False
                logger().info(f"********* configuring static ip {self.dut_ip} to DUT *********")
                # join_ok, reason = self.sl_collections.connect(
                #     wifi_dut=self.wifi_dut,
                #     wifi_access_point=self.wifi_access_point,
                # )
                # assert join_ok, f"NWP reconnect failed: {reason}"
                ok, ip_config = self.sl_collections.configure_ip(
                    self.wifi_dut,
                    retry_count=3,
                    ip_version="ipv4",
                )
                assert ok, f"NWP DHCP failed: {ip_config}"
                self.dut_ip = ip_config.ip.decode()
                logger().info(f"NWP DHCP IP: {self.dut_ip}")
                self.dut_ip = ip_config.ip.decode()
                status = ping(self.dut_ip, 10)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
            if self.testcase in ("c794007"):
                status_http = self.http_server.interfaces.http.started
                assert status_http, 'Server is inactive'
                logger().info(f'http server state is {status_http}')
                logger().info("dut fw version before upgrade...")
                self.fw_version_before_upgrade = self.wifi_dut.interfaces.wifi.version()
                logger().info(f"*** dut fw version before upgrade = {self.fw_version_before_upgrade} ***")
                ota_server_ip = self.http_server.interfaces.http.ip_address
                ota_server_host = getattr(self.http_server.interfaces.http, "host_name", ota_server_ip)
                self.wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=ota_server_ip, http_url=self.rps_path, port=443,
                                                               host_name=ota_server_host)
            if self.testcase in ("c794013"):
                status_dut, content_dut = self.wifi_dut.interfaces.wifi.http_get(
                    self.http_server.interfaces.http,
                    self.index_path,
                    server_port=443)
                status_client, content_client = self.http_client.interfaces.http.http_get(
                    self.http_server.interfaces.http, self.index_path)

                assert not status_dut, "failed to fetch the https data"
                assert status_client, "failed to load the https data"

                logger().info(status_dut)
                logger().info(content_dut)
                assert content_dut == content_client, "fetched data is not same as expected data"
                status = self.wifi_dut.interfaces.wifi.http_client_deinit()
            if self.testcase in ("c794012"):
                topic = "mytesttopic_C127757"
                message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
                self.wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
                self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
                logger().info(".....DUT connects to MQTT server.....")
                self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
                logger().info(".....MQTT Client connects to MQTT server.....")
                mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
                time.sleep(5)

                logger().info("MQTT Client subscribes to the topic")
                mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

                logger().info("DUT subscribes to the topic")
                self.wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

                time.sleep(5)

                logger().info("DUT publishes message over the topic")
                self.wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=self.message, qos=Si91xMqttQos.QOS1,
                                                                  timeout=20)
                time.sleep(5)

                msgs = []
                sw = Stopwatch()
                while sw.elapsed_sec < 10:
                    time.sleep(0.1)
                    msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                    if len(msgs) == 1:
                        break
                assert len(msgs) == 1, "No message is received by mqtt-client"
                assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
                assert msgs[0].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
                assert msgs[
                           0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                           "message received is wrong"

            if self.testcase in ("c794007", "c794013", "c794012"):
                self.wifi_dut.interfaces.wifi.is_external_stack_enabled = True
                self.wifi_dut.interfaces.wifi.lwip_join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                                        passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                                        security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                        timeout=60)

                self.wifi_dut.interfaces.wifi.start_ip_lwip(static_ip="192.168.50.11",
                                                            static_subnet="255.255.255.0",
                                                            static_gateway="192.168.50.1")
                ip_config = self.wifi_dut.interfaces.wifi.display_device_ip_lwip()
                logger().info(f"*******{ip_config}")
                self.dut_ip = ip_config.ip.decode()



            if self.testcase in ("c794003", "c794007", "c794013", "c794012"):
                self.sl_collections.run_traffic(
                    wifi_dut=self.wifi_dut,
                    net_perf_client=self.net_perf_client,
                    protocol=self.protocol,
                    device_ip=self.dut_ip,
                    host_ip=host_ip,
                    timeout=30,
                    traffic_type=self.traffic_type,
                    ip_version=4, mode="lwip"
                )

                time.sleep(5)
            if self.testcase in ("c794003", "c794007", "c794013"):
                logger().info("disconnecting from AP")
                wifi.leave()
        if self.testcase in ("c794000", "c794001", "c794004"):
            for i in range(self.iterations):
                scan_ok, reason = self.sl_collections.scan(
                    self.wifi_dut,
                    channel=self.wifi_access_point.interfaces.wifi.channel or 0,
                )
                assert scan_ok, f"scan failed: {reason}"

                join_ok, reason = self.sl_collections.connect(
                    wifi_dut=self.wifi_dut,
                    wifi_access_point=self.wifi_access_point,
                )
                assert join_ok, f"connect failed: {reason}"

                saved = wifi.is_external_stack_enabled
                wifi.is_external_stack_enabled = False
                try:
                    ok, ip_config = self.sl_collections.configure_ip(
                        self.wifi_dut,
                        retry_count=3,
                        ip_version="ipv4",
                    )
                finally:
                    wifi.is_external_stack_enabled = saved
                if self.testcase == "c794004":
                    wifi.is_external_stack_enabled = False
                    try:
                        ok, ip_config = self.sl_collections.configure_ip(
                            self.wifi_dut,
                            retry_count=3,
                            ip_version="ipv6"
                        )
                    finally:
                        wifi.is_external_stack_enabled = saved


                assert ok, f"NWP DHCP failed: {ip_config}"

                device_ip = ip_config.ip.decode()
                gateway = ip_config.gateway.decode()
                subnet = ip_config.netmask.decode()
                logger().info(f"NWP DHCP: {device_ip}")

                time.sleep(10)

                self._ensure_lwip_ready(wifi)

                wifi.is_external_stack_enabled = True
                wifi.start_ip_lwip(
                    static_ip=device_ip,
                    static_subnet=subnet,
                    static_gateway=gateway,
                    timeout=10,
                )

                self._ensure_lwip_ready(wifi)

                logger().info("ping from remote to DUT")
                status = self.sl_collections.ping(
                    device_ip=device_ip,
                    ping_count=10,
                    retry_count=3,
                )
                assert status, "DUT NOT RESPONDING FOR PING REQUEST"

                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                self.sl_collections.run_traffic(
                    wifi_dut=self.wifi_dut,
                    net_perf_client=self.net_perf_client,
                    protocol=self.protocol,
                    device_ip=device_ip,
                    host_ip=host_ip,
                    timeout=30,
                    traffic_type=self.traffic_type,
                    ip_version=4,
                )

                time.sleep(5)
                logger().info("disconnecting from AP")
                wifi.leave()
        logger().info("Stop Sniffer finally")
        self.wifi_sniffer.interfaces.capture.stop_capture()

@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def wifi_dut_marker(tcp_feat_bit=0, ca_cert=None):
    config = {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": (
            Si91xTCPIPFeatureBitMap.DHCPv4Client
            | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid
            | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | tcp_feat_bit
        ),
        "ext_tcpip_features": (
            Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_DUAL_MODE_ENABLE
            | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        ),
        "config_features": Si91xConfigFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "ca_cert": ca_cert,
    },
    return pytest.mark.config("wifi_dut", wifi=config)


@wifi_dut_marker()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": (
            Si91xTCPIPFeatureBitMap.DHCPv4Client
            | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid
            | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
        ),
        "ext_tcpip_features": (
            Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_DUAL_MODE_ENABLE
            | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        ),
        "config_features": Si91xConfigFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_fetch_dhcp_ip_offload_stack_c794000(request,
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    sl_collections,
    net_perf_client,
    wifi_client,
    protocol,
):
    """Verify DHCP IP acquisition on NWP offload stack and traffic."""

    dual_stack = DualStack(
        wifi_sniffer =wifi_sniffer,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        sl_collections=sl_collections,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
        iterations=5,
        traffic_type="TX", testcase="c794000", capture_file=request.node.name,
    )

    try:
        dual_stack.run()
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)

@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_fetch_dhcp_ip_dual_stack_c794001(request,
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    sl_collections,
    net_perf_client,
    wifi_client,
    protocol,
):
    """Verify DHCP IP acquisition on NWP offload stack and traffic."""

    dual_stack = DualStack(
        wifi_sniffer=wifi_sniffer,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        sl_collections=sl_collections,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
        iterations=5,
        traffic_type="RX", testcase="c794001", capture_file=request.node.name,
    )

    try:
        dual_stack.run()
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)



@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.TCPIPBypass)
def test_dut_functionality_user_enables_mutually_exclusive_C794015(request, wifi_access_point):
    with pytest.raises(AssertionError) as exc_info:
        request.getfixturevalue("wifi_dut")

    msg = str(exc_info.value)
    assert "SL_STATUS_INVALID_CONFIGURATION" in msg
    assert "status:0x23" in msg


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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@wifi_dut_marker()
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_fetch_static_ip_lwip_c794003(request,
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    sl_collections,
    net_perf_client,
    wifi_client,
    protocol,
):
    """Verify DHCP IP acquisition on NWP offload stack and traffic on 5GHz."""

    dual_stack = DualStack(
        wifi_sniffer=wifi_sniffer,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        sl_collections=sl_collections,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
        iterations=5,
        traffic_type="TX", testcase="c794003", capture_file=request.node.name,
    )

    try:
        dual_stack.run()
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.IPv6Mode)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               }
)
def test_wifi_sdk_fetch_check_dual_ip_offload_stack_c794004(request, wifi_sniffer, wifi_access_point, wifi_dut,
                                             sl_collections, net_perf_client, wifi_client, protocol):
    dual_stack = DualStack(
        wifi_sniffer=wifi_sniffer,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        sl_collections=sl_collections,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
        iterations=5,
        traffic_type="TX", testcase="c794004", capture_file=request.node.name,
    )

    try:
        dual_stack.start()
        dual_stack.wait_for_exit()
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@wifi_dut_marker(ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.http_server("raspi_lighttpd_tls")
def test_wifi_sdk_tcp_tx_lwip_https_otaf_nwp_C794007(request, utf_constants, http_server, wifi_sniffer, wifi_access_point, wifi_dut, sl_collections, net_perf_client, protocol, wifi_client):
    rps_path = utf_constants.get("rps_filename")
    dual_stack = DualStack(
        wifi_sniffer=wifi_sniffer,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        sl_collections=sl_collections,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
        http_server = http_server,
        iterations=5,
        traffic_type="TX", testcase="c794007", capture_file=request.node.name,
        rps_path=rps_path
       )

    try:
        dual_stack.run()
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@wifi_dut_marker(ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("index_path", {"index.html"})
def test_wifi_sdk_tcp_tx_lwip_https_get_nwp_C794013(request, wifi_sniffer, wifi_access_point, wifi_dut, sl_collections, net_perf_client, protocol, wifi_client, http_server,index_path,http_client):

    dual_stack = DualStack(
        wifi_sniffer = wifi_sniffer,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        sl_collections=sl_collections,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
        http_server=http_server,
        index_path=index_path,
        iterations=5, testcase="c794013", capture_file=request.node.name,
    )

    try:
        dual_stack.run()
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)



@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@wifi_dut_marker(ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
def test_wifi_sdk_tcp_tx_lwip_mqqt_nwp_C794012(request, wifi_sniffer, wifi_access_point, wifi_dut, sl_collections, wifi_client, net_perf_client, protocol):

    dual_stack = DualStack(
        wifi_sniffer =wifi_sniffer,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        sl_collections=sl_collections,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
        iterations=5, testcase="c794012", capture_file=request.node.name,
    )

    try:
        dual_stack.run()
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
@wifi_dut_marker()
def test_wifi_sdk_lwip_dhcp_resume_after_reset_c794018(request,
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    sl_collections,
    net_perf_client,
    wifi_client,
    protocol,
):
    dual_stack = DualStack(
        wifi_sniffer=wifi_sniffer,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        sl_collections=sl_collections,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
        iterations=1,
        traffic_type="TX",
        testcase="c794018", capture_file=request.node.name,
    )
    try:
        dual_stack.run()
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@wifi_dut_marker()
@pytest.mark.config(
    "net_perf_client",
    net_perf={
        "host": {
            "TCP": {"port": 5001},
            "UDP": {"port": 5202},
        }
             }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_parallel_tcp_data_transfer_on_two_stacks_C794009(request, wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    sl_collections,
    net_perf_client,
    wifi_client,
    protocol):
    dual_stack = DualStack(
        wifi_sniffer=wifi_sniffer,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        sl_collections=sl_collections,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
        http_server=None,
        iterations=5,
        traffic_type="TX",
        testcase="c794009",capture_file=request.node.name,
    )
    try:
        dual_stack.run()
    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@wifi_dut_marker(ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.http_server("raspi_lighttpd_tls")
def test_wifi_sdk_tcp_tx_lwip_https_otaf_nwp_overnight_C802580(request, wifi_sniffer, utf_constants, http_server,  wifi_access_point, wifi_dut, sl_collections, net_perf_client, protocol, wifi_client):
    rps_path = utf_constants.get("rps_filename")
    dual_stack = DualStack(
        wifi_sniffer=wifi_sniffer,
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        sl_collections=sl_collections,
        net_perf_client=net_perf_client,
        wifi_client=wifi_client,
        protocol=protocol,
        http_server = http_server,
        iterations=5,
        traffic_type="TX", testcase="c794007",
        rps_path=rps_path, capture_file=request.node.name,
       )
    long_duration = utf_constants.get("long_duration")
    sw = Stopwatch()
    logger().info(f"Time duration is {long_duration} secs")
    while sw.elapsed_sec < long_duration:
        try:
            dual_stack.run()
        except Exception as ex:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)