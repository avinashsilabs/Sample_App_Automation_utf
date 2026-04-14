from utf.utils.logger import get_logger
import pytest
import string
import time
from utf.utils.thread_base import ThreadBase
from utf.utf_config import UtfConfig
from utf.utils.stopwatch import Stopwatch
import re
from utf_wifi_zephyr.devices.si91x import Si91xBSDSocketParams, ZephyrHttpMethods
from base64 import b64decode
from threading import Thread



def logger():
    return get_logger(__name__)


def ap_switch(switch, ap_turn_off_time, start_delay):
    time.sleep(start_delay)
    logger().info(f"Turn off AP for {ap_turn_off_time} seconds")
    switch.interfaces.pdu_switch.turn_off(delay=1)
    time.sleep(ap_turn_off_time)
    switch.interfaces.pdu_switch.turn_on()
    logger().info("AP is turn on")


"""
     Setup Requirement:

        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)  

     Test Steps:

        1. Configure the DUT in 2G.
        2. Connect to AP
        3. Configure the IPv6 addresses.
        4. Ping to the specified IPv6 address.
        5. Validate the Sniffer Checks.
        6. Verify TCP TX, UDP TX, TCP RX, UDP RX, HTTP, and MQTT functionality as per the test case 

     Author:
      - Vinod.G
"""

import ipaddress
import random


def random_ipv6_addr(prefix: str) -> str:
    # Ensure the prefix is interpreted as a /64 network
    logger().info(f"prefix-------------> {prefix}")
    network = ipaddress.IPv6Network(f"{prefix}/64", strict=False)

    # Generate a random 64-bit interface identifier
    random_suffix = random.getrandbits(64)

    # Combine the prefix and the random suffix
    full_ip_int = int(network.network_address) | random_suffix
    full_ip = ipaddress.IPv6Address(full_ip_int)

    return str(full_ip)


wan_ipv6_addr = random_ipv6_addr("2001:db8:abcd:0012::")
wan_gateway = "2001:db8:abcd:0012::1"


class WLanThread(ThreadBase):
    client_info = {"mac_address": None, "ip_address": None}
    dut_info = {"mac_address": None, "ip_address": None}

    def __init__(self, wifi_dut=None, wifi_sniffer=None, wifi_access_point=None, zephyr_wifi_collections=None,
                 test_name=None,
                 wifi_client=None, test_id=None, ping_before_power_save=False, ping_after_power_save=False,
                 ipv6_addr_type="global", static_ipv6=None, ip_config_disable=False, skip_sniffer_capture=False, power_save=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_sniffer = wifi_sniffer
        self.wifi_access_point = wifi_access_point
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.ping_before_power_save = ping_before_power_save
        self.ping_after_power_save = ping_after_power_save
        self.ipv6_addr_type = ipv6_addr_type
        self.static_ipv6 = static_ipv6
        self.ip_config_disable = ip_config_disable
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        self.remote_ipv6 = None
        self.remote_ipv4 = None
        self.dut_ipv6 = None
        self.skip_sniffer_capture = skip_sniffer_capture
        self.dut_mac_address = None
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def sniffer_capture(self, mode: str = None):
        if mode == 'start':
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
        else:
            self.wifi_sniffer.interfaces.capture.stop_capture()

    def run(self):
        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        if not self.skip_sniffer_capture:
            self.sniffer_capture(mode='start')

        info_attr = self.zephyr_wifi_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                      wifi_access_point=self.wifi_access_point,
                                                                      associated=self.wifi_dut.interfaces.wifi.associated,
                                                                      ip_version='ipv6',
                                                                      ping_before_power_save=True,
                                                                      ping_after_power_save=True,
                                                                      ipv6_type=self.ipv6_addr_type,
                                                                      retry_count=1,
                                                                      power_save=self.power_save)

        device_ip = info_attr['device_ip']
        logger().info(f"device_ip  {device_ip}")
        self.dut_ipv6 = device_ip
        self.dut_info['ap_mac_address'] = self.wifi_access_point.interfaces.wifi.bssid
        remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.ipv6_addr_type)
        logger().info(f"remote_ip: {remote_ip}")
        self.remote_ipv6 = remote_ip

        self.dut_info['mac_address'] = info_attr['dut_mac_address']
        self.dut_info['ip_address'] = info_attr['device_ip']

    def icmp_send_test(self, target_ip=None, packet_count=100, timeout_ms=1000,
                       success_threshold=80):
        """
        Send ICMP packets and validate success rate

        Arguments:
            target_ip - Target IP address to ping
            packet_count - Number of ICMP packets to send (default: 100)
            timeout_ms - Timeout for each packet in milliseconds (default: 1000ms)
            success_threshold - Minimum success percentage required (default: 80%)

        Returns:
            bool - True if success rate meets threshold, False otherwise
        """
        logger().info(f"\n *** Starting ICMP Send Test *** \n")
        logger().info(f"Target IP: {target_ip}")
        logger().info(f"Packet Count: {packet_count}")
        logger().info(f"Timeout: {timeout_ms}ms")
        logger().info(f"Success Threshold: {success_threshold}%")

        if not target_ip:
            target_ip = self.target_ip

        try:
            # Send ICMP packets using the DUT's icmp_ping method
            logger().info(f"Sending {packet_count} ICMP packets to {target_ip}")

            # Use the icmp_ping method from the WiFi interface
            data = self.wifi_dut.interfaces.wifi.icmp_ping(
                target_ip=target_ip,
                packet_count=packet_count,
                timeout_ms=timeout_ms,
                ip_version=6,
                timeout=120  # Overall timeout for the operation
            )

            success_count = data

            # Calculate success percentage
            success_percentage = (success_count / packet_count) * 100
            logger().info(f"Success Rate: {success_percentage:.2f}%")

            # Validate against threshold
            if success_percentage >= success_threshold:
                logger().info(
                    f"✓ ICMP test PASSED - Success rate {success_percentage:.2f}% meets threshold {success_threshold}%")
                return True
            else:
                logger().error(
                    f"✗ ICMP test FAILED - Success rate {success_percentage:.2f}% below threshold {success_threshold}%")
                return False


        except Exception as e:
            logger().error(f"ICMP ping operation failed: {str(e)}")
            return False

    def subscribe_and_publish(self, wifi_dut, mqtt_client, mqtt_server, qos=0, keep_alive=60):

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt,
                                                               keep_alive_time=keep_alive, ip_version=6)

        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(2)
        if qos == 0:
            dut_subscribe_topic = "mytesttopic_qos0_dut"
            topic = "mytesttopic_qos0"
        elif qos == 1:
            dut_subscribe_topic = "mytesttopic_qos1_dut"
            topic = "mytesttopic_qos1"
        else:
            dut_subscribe_topic = "mytesttopic_qos2_dut"
            topic = "mytesttopic_qos2"

        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
        client_message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))

        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=qos)

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=dut_subscribe_topic, qos=qos)

        logger().info("DUT publishes message over the topic")
        publish_response = wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=qos,
                                                                        timeout=20)
        logger().info(f"publish response-----------> {publish_response}")
        time.sleep(2)

        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        if qos == 0:
            assert msgs[0].qos == qos, "DUT sent message with wrong QOS. expected is QOS0"
        if qos == 1:
            assert msgs[0].qos == qos, "DUT sent message with wrong QOS. expected is QOS1"
        if qos == 2:
            assert msgs[0].qos == qos, "DUT sent message with wrong QOS. expected is QOS2"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"

        mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=dut_subscribe_topic, payload=client_message, qos=qos)
        data = wifi_dut.interfaces.mqtt.mqtt_client_set_idle(sync_timeout=10000)

        topic_match = re.search(r"topic\s*-\s*['\"]([^'\"]+)['\"]", data)
        topic_receive = topic_match.group(1) if topic_match else None

        # Extract payload (after "payload:")
        payload_match = re.search(r"payload:\s*(.+?)(?:\n|$)", data, re.IGNORECASE)
        payload_receive = payload_match.group(1).strip() if payload_match else None

        assert topic_receive == dut_subscribe_topic, "No message received by DUT on MQTT on subscribed topic"
        assert payload_receive == client_message, "No message is received by DUT on MQTT on subscribed topic or " \
                                                  "message received is wrong"

        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic, qos=qos)
        wifi_dut.interfaces.mqtt.mqtt_client_disconnect()

    def http_get_put_post(self, wifi_dut, http_client, http_server, port=80, server_ip="", url="",
                          method=ZephyrHttpMethods.GET,
                          payload=""):
        try:
            socket_id = wifi_dut.interfaces.wifi.socket(domain=Si91xBSDSocketParams.AF_INET6,
                                                        stream_type=Si91xBSDSocketParams.SOCK_STREAM,
                                                        protocol=Si91xBSDSocketParams.IPPROTO_TCP)
            logger().info(f"Socket open successfully : {socket_id}")
            wifi_dut.interfaces.wifi.bind(
                socket_fd=socket_id, device_ip=self.dut_ipv6, port=5001, timeout=5, ip_version=6)

            logger().info("DUT is connecting to server socket")
            for count in range(3):
                connect_status = False
                try:
                    wifi_dut.interfaces.wifi.bsdSocketConnect(
                        socket_id, server_ip, port, ip_version=6)
                    connect_status = True
                    break
                except:
                    logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                    assert connect_status, "Socket connection failed in DUT"

            if method == ZephyrHttpMethods.GET:

                http_content_dut = wifi_dut.interfaces.wifi.http_client_req(socket_id, ZephyrHttpMethods.GET, url,
                                                                            server_ip, ip_version="IPv6")
                status_client, content_client = http_client.interfaces.http.http_get(
                    http_server.interfaces.http, url)
                assert status_client, "failed to load the https data"
                logger().info(f"http dut response--------->  {http_content_dut}")
                logger().info(f"http client response---------->{content_client}")
                http_data = http_content_dut.split(":")[1]
                http_data_decode = b64decode(http_data)
                logger().info(f"http dut response after decode ---------> {http_data_decode}")
                http_data_decode = http_data_decode.decode()

                match = re.search(r'<html.*', http_data_decode, re.DOTALL | re.IGNORECASE)
                if match:
                    http_content = match.group(0)
                    logger().info("http_content:", http_content)
                else:
                    http_content = ""
                    logger().info("<html' not found in the string")
                assert http_content == content_client.decode(), "fetched data is not same as expected data"
            elif method == ZephyrHttpMethods.POST:
                wifi_dut.interfaces.wifi.http_client_req(socket_id, ZephyrHttpMethods.POST, url,
                                                         server_ip, payload=payload)
            else:

                wifi_dut.interfaces.wifi.http_client_req(socket_id, ZephyrHttpMethods.PUT, url,
                                                         server_ip, payload=payload)

        except:
            logger().info("HTTP GET, POST, or PUT METHOD FAILED")
        finally:
            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)


class IperfThraed(ThreadBase):

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None, wifi_client=None,
                 test_id=None,
                 traffic_type=None, protocol=None, net_perf_client=None, timeout=60,
                 device_ip=None, remote_ip=None, ip_version=4, async_socket=0):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.traffic_type = traffic_type
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.timeout = timeout
        self.ip_version = ip_version
        self.device_ip = device_ip
        self.remote_ip = remote_ip
        self.async_socket = async_socket

    def run_traffic(self):
        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=self.protocol,
            device_ip=self.device_ip,
            host_ip=self.remote_ip,
            timeout=self.timeout,
            traffic_type=self.traffic_type,
            ip_version=self.ip_version,
            buffer_size_tcp=1380,
            buffer_size_udp=1390,
            async_socket=self.async_socket
        )

    def run(self):
        self.run_traffic()


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C19033')
def test_wifi_zephyr_tcp_tx_ipv6_c19033(wifi_dut, wifi_access_point,
                                        wifi_sniffer, sniffer_filter,
                                        zephyr_wifi_collections, request,
                                        utf_constants, wifi_client,
                                        net_perf_clients):
    """ Verify TCP tx functionality with IPV6 """

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                              test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        device_ip = wlan_obj.dut_ipv6
        host_ip = wlan_obj.remote_ipv6

        socket1_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="TX", protocol="TCP", net_perf_client=net_perf_clients[0], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=6
                                     )

        socket1_thread.start()
        time.sleep(5)

        socket1_thread.wait_for_exit()
        time.sleep(5)
        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C19033')
def test_wifi_zephyr_tcp_rx_ipv6_c19033(wifi_dut, wifi_access_point,
                                        wifi_sniffer, sniffer_filter,
                                        zephyr_wifi_collections, request,
                                        utf_constants, wifi_client,
                                        net_perf_clients):
    """ Verify TCP rx functionality with IPV6 """

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                              test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        device_ip = wlan_obj.dut_ipv6
        host_ip = wlan_obj.remote_ipv6

        socket1_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="RX", protocol="TCP", net_perf_client=net_perf_clients[0], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=6
                                     )

        socket1_thread.start()
        time.sleep(5)

        socket1_thread.wait_for_exit()
        time.sleep(5)
        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C19033')
def test_wifi_zephyr_udp_tx_ipv6_c19033(wifi_dut, wifi_access_point,
                                        wifi_sniffer, sniffer_filter,
                                        zephyr_wifi_collections, request,
                                        utf_constants, wifi_client,
                                        net_perf_clients):
    """ Verify UDP tx functionality with IPV6 """

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                              test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        device_ip = wlan_obj.dut_ipv6
        host_ip = wlan_obj.remote_ipv6

        socket1_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[0], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=6
                                     )

        socket1_thread.start()
        time.sleep(5)

        socket1_thread.wait_for_exit()
        time.sleep(5)
        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C19033')
def test_wifi_zephyr_udp_rx_ipv6_c19033(wifi_dut, wifi_access_point,
                                        wifi_sniffer, sniffer_filter,
                                        zephyr_wifi_collections, request,
                                        utf_constants, wifi_client,
                                        net_perf_clients):
    """ Verify UDP rx functionality with IPV6 """

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                              test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        device_ip = wlan_obj.dut_ipv6
        host_ip = wlan_obj.remote_ipv6

        socket1_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[0], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=6
                                     )

        socket1_thread.start()
        time.sleep(5)

        socket1_thread.wait_for_exit()
        time.sleep(5)
        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C19033')
def test_wifi_zephyr_tcp_tx_tcp_rx_ipv6_c19033(wifi_dut, wifi_access_point,
                                               wifi_sniffer, sniffer_filter,
                                               zephyr_wifi_collections, request,
                                               utf_constants, wifi_client,
                                               net_perf_clients):
    """ Verify TCP tx and TCP RX functionality in multiple threads """

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"***** Start get IP address ******")
        # host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                              test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        device_ip = wlan_obj.dut_ipv6
        host_ip = wlan_obj.remote_ipv6

        socket1_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="TX", protocol="TCP", net_perf_client=net_perf_clients[0], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=6
                                     )
        socket2_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="RX", protocol="TCP", net_perf_client=net_perf_clients[1], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=6

                                     )

        socket1_thread.start()
        socket2_thread.start()
        time.sleep(5)

        socket1_thread.wait_for_exit()
        socket2_thread.wait_for_exit()
        time.sleep(5)
        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C19033')
def test_wifi_zephyr_udp_tx_tcp_rx_ipv6_c19033(wifi_dut, wifi_access_point,
                                               wifi_sniffer, sniffer_filter,
                                               zephyr_wifi_collections, request,
                                               utf_constants, wifi_client,
                                               net_perf_clients):
    """ Verify UDP tx and TCP RX functionality in multiple threads """

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"***** Start get IP address ******")
        # host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                              test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        device_ip = wlan_obj.dut_ipv6
        host_ip = wlan_obj.remote_ipv6

        socket1_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[0], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=6
                                     )
        socket2_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="RX", protocol="TCP", net_perf_client=net_perf_clients[1], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=6

                                     )

        socket1_thread.start()
        socket2_thread.start()
        time.sleep(5)

        socket1_thread.wait_for_exit()
        socket2_thread.wait_for_exit()
        time.sleep(5)
        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C19033')
def test_wifi_zephyr_udp_tx_udp_rx_ipv6_c19033(wifi_dut, wifi_access_point,
                                               wifi_sniffer, sniffer_filter,
                                               zephyr_wifi_collections, request,
                                               utf_constants, wifi_client,
                                               net_perf_clients):
    """ Verify UDP tx and UDP RX functionality in multiple threads """

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"***** Start get IP address ******")
        # host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                              test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        device_ip = wlan_obj.dut_ipv6
        host_ip = wlan_obj.remote_ipv6

        socket1_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[0], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=6
                                     )
        socket2_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=6

                                     )

        socket1_thread.start()
        socket2_thread.start()
        time.sleep(5)

        socket1_thread.wait_for_exit()
        socket2_thread.wait_for_exit()
        time.sleep(5)
        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C19033')
def test_wifi_zephyr_tcp_rx_udp_rx_ipv6_c19033(wifi_dut, wifi_access_point,
                                               wifi_sniffer, sniffer_filter,
                                               zephyr_wifi_collections, request,
                                               utf_constants, wifi_client,
                                               net_perf_clients):
    """ Verify TCP RX and UDP RX functionality in multiple threads """

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"***** Start get IP address ******")
        # host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                              test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        device_ip = wlan_obj.dut_ipv6
        host_ip = wlan_obj.remote_ipv6

        socket1_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="RX", protocol="TCP", net_perf_client=net_perf_clients[0], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=6
                                     )
        socket2_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=6

                                     )

        socket1_thread.start()
        socket2_thread.start()
        time.sleep(5)

        socket1_thread.wait_for_exit()
        socket2_thread.wait_for_exit()
        time.sleep(5)
        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119348')
def test_wifi_zephyr_verify_stateless_dhcpv6_configuration_c119348(wifi_dut, wifi_access_point,
                                                                wifi_sniffer,
                                                                zephyr_wifi_collections, request, sniffer_filter,
                                                                wifi_client):
    """" Configure DHCPV6 option to stateless in router,  and verify the sniffer packets after DUT gets IPV6 address """
    test_name = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, zephyr_wifi_collections=zephyr_wifi_collections, test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wlan_obj.sniffer_capture(mode='stop')
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
        logger().info("checking for router advertisement packet to check the stateless dhcpv6 configuration")
        packet_filter = f"icmpv6.nd.ra.flag.o == 1 && icmpv6.nd.ra.flag.m == 0 && wlan.addr== {wlan_obj.dut_info['ap_mac_address']}"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
            'Sniffer: AP is not configured with stateless dhcpv6'

        # Router solicitation message
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info['mac_address'],
            filter_name='router_solicitation')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: router_solicitation message not received'
        # Router advertisement message
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wlan_obj.dut_info['mac_address'],
            filter_name='router_advertisement')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Sniffer: advertisement message not received'
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "Open", "ipv6_state": "1",
                               "wan_ipv6_address": wan_ipv6_addr, "wan_ipv6_gateway": wan_gateway}
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119349')
def test_wifi_zephyr_verify_stateful_dhcpv6_procedure_c119349(wifi_dut, wifi_access_point, wifi_sniffer,
                                                           zephyr_wifi_collections,
                                                           sniffer_filter, request,
                                                           wifi_client):
    """" Configure DHCPV6 option to stateful in router,  and verify the sniffer packets after DUT gets IPV6 address """
    test_name = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, zephyr_wifi_collections=zephyr_wifi_collections,
                              wifi_client=wifi_client, test_id=119349,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wlan_obj.sniffer_capture(mode='stop')
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '

        logger().info("checking for router advertisement packet to check the stateful dhcpv6 configuration")
        packet_filter1 = f"icmpv6.nd.ra.flag.m == 1 && wlan.addr== {wlan_obj.dut_info['ap_mac_address']}"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: AP is not configured with stateful dhcpv6'
        # Router solicitation message
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info['mac_address'],
            filter_name='router_solicitation')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: router_solicitation message not received'
        # Router advertisement message
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wlan_obj.dut_info['mac_address'],
            filter_name='router_advertisement')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Sniffer: advertisement message not received'
        # Stateful IPv6 address
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_info['mac_address'],
            filter_name='stateful_ipv6_address')
        logger().info(f"The filter is {packet_filter3}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Sniffer: stateful ipv6 address not received'

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119348')
def test_wifi_zephyr_dhcpv6_multiple_iterations_c119348(wifi_dut, wifi_access_point,
                                                        wifi_sniffer,
                                                        zephyr_wifi_collections, request, sniffer_filter,
                                                        wifi_client, utf_constants):
    """" Get the ipv6 address through dhcpv6 after connet and disconnect to AP multiple times """

    test_name = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        ipv6_iter_count = utf_constants.get("ipv6_iteration_count")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, zephyr_wifi_collections=zephyr_wifi_collections, test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save,
                              skip_sniffer_capture=True)

        for count in range(1, ipv6_iter_count + 1):
            logger().info(f"Running the test case for {count} iteration")
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            logger().info("Disconnect to AP")
            wifi_dut.interfaces.wifi.leave()

        wlan_obj.sniffer_capture(mode='stop')
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119348')
def test_wifi_zephyr_ipv6_verify_adaptive_ping_c119348(wifi_dut, wifi_access_point,
                                                       wifi_sniffer,
                                                       zephyr_wifi_collections, request, sniffer_filter,
                                                       wifi_client):
    """" Verify whether DUT is able to respond to ping request packets from remote device when received in flood on ipv6 network """
    test_name = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, zephyr_wifi_collections=zephyr_wifi_collections, test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        device_ip = wlan_obj.dut_ipv6
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping  {device_ip} -c {100} -i {0.3}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wlan_obj.sniffer_capture(mode='stop')
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119348')
def test_wifi_zephyr_dual_stack_adaptive_ping_c119348(wifi_dut, wifi_access_point,
                                                      wifi_sniffer,
                                                      zephyr_wifi_collections, request, sniffer_filter,
                                                      wifi_client):
    """" Verify whether DUT is able to respond to ping request packets from remote device when received in flood both on IPV4 and IPV6 networks"""
    test_name = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, zephyr_wifi_collections=zephyr_wifi_collections, test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        device_ip6 = wlan_obj.dut_ipv6
        wifi_dut.interfaces.wifi.start_ip(ip_version='ipv4')
        device_ip_v4 = wifi_dut.interfaces.wifi.get_ip_address()
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping  {device_ip6} -c {100} -i {0.3}")
        assert rc == 0, f"RASPI-STA failed to ping DUT on ipv6 network"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")

        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping  {device_ip_v4} -c {100} -i {0.3}")
        assert rc == 0, f"RASPI-STA failed to ping DUT on ipv4 network"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wlan_obj.sniffer_capture(mode='stop')
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C119348')
def test_wifi_zephyr_ipv6_imcp_from_dut_c119348(wifi_dut, wifi_access_point,
                                                wifi_sniffer,
                                                zephyr_wifi_collections, request, sniffer_filter,
                                                wifi_client):
    """" Send 1000 ICMPV6 packets from DUT, and Verify pass%"""
    test_name = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, zephyr_wifi_collections=zephyr_wifi_collections, test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        host_ip = wlan_obj.remote_ipv6
        # Execute ICMP send test
        test_result = wlan_obj.icmp_send_test(
            target_ip=host_ip,
            packet_count=100,
            timeout_ms=1000,
            success_threshold=80
        )

        # Assert test result
        assert test_result, "ICMP send test failed - success rate below 80% threshold"

        # Log MAC addresses for reference
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC ADDRESS: {ap_mac_address}")

        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wlan_obj.sniffer_capture(mode='stop')
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.skip()
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C19033')
def test_wifi_zephyr_udp_tx_functionality_ipv6_after_rejoin_successful_c19033(wifi_dut, wifi_access_point,
                                                                              wifi_sniffer, sniffer_filter,
                                                                              zephyr_wifi_collections, request,
                                                                              utf_constants, wifi_client,
                                                                              net_perf_clients, switch):
    """ Verify UDP tx functionality with IPV6 after rejoin to AP success"""

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                              test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        device_ip = wlan_obj.dut_ipv6
        host_ip = wlan_obj.remote_ipv6

        socket1_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[0], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=6
                                     )

        socket1_thread.start()
        time.sleep(3)

        socket1_thread.wait_for_exit()
        time.sleep(1)

        ap_turn_off_time = 10
        start_delay = 2
        thread = Thread(target=ap_switch, args=(switch, ap_turn_off_time, start_delay), )
        thread.start()

        logger().info("Stop sending data on DUT as rejoin is going, wait for 90 seconds")
        time.sleep(90)
        socket1_thread.start()
        time.sleep(3)

        socket1_thread.wait_for_exit()
        time.sleep(1)
        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('TC127757')
def test_wifi_zephyr_mqtt_qos0_connect_subscribe_publish_unsubscribe_ipv6_TC127757(wifi_dut, wifi_access_point,
                                                                                   wifi_sniffer,
                                                                                   zephyr_wifi_collections, request,
                                                                                   sniffer_filter,
                                                                                   wifi_client, mqtt_server,
                                                                                   mqtt_client):
    """Verify MQTT functionality on IPV6 when publishing message with QOS0, and receiving the message on subscribed topic with QOS0"""
    test_name = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, zephyr_wifi_collections=zephyr_wifi_collections, test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wlan_obj.subscribe_and_publish(wifi_dut, mqtt_client, mqtt_server, qos=0, keep_alive=60)

        # Log MAC addresses for reference
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC ADDRESS: {ap_mac_address}")

        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wlan_obj.sniffer_capture(mode='stop')
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('TC127757')
def test_wifi_zephyr_mqtt_qos1_connect_subscribe_publish_unsubscribe_ipv6_TC127757(wifi_dut, wifi_access_point,
                                                                                   wifi_sniffer,
                                                                                   zephyr_wifi_collections, request,
                                                                                   sniffer_filter,
                                                                                   wifi_client, mqtt_server,
                                                                                   mqtt_client):
    """Verify MQTT functionality on IPV6 when publishing message with QOS1, and receiving the message on subscribed topic with QOS1"""
    test_name = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, zephyr_wifi_collections=zephyr_wifi_collections, test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wlan_obj.subscribe_and_publish(wifi_dut, mqtt_client, mqtt_server, qos=1, keep_alive=60)

        # Log MAC addresses for reference
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC ADDRESS: {ap_mac_address}")

        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wlan_obj.sniffer_capture(mode='stop')
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('TC127757')
def test_wifi_zephyr_mqtt_qos2_connect_subscribe_publish_unsubscribe_ipv6_TC127757(wifi_dut, wifi_access_point,
                                                                                   wifi_sniffer,
                                                                                   zephyr_wifi_collections, request,
                                                                                   sniffer_filter,
                                                                                   wifi_client, mqtt_server,
                                                                                   mqtt_client):
    """Verify MQTT functionality on IPV6 when publishing message with QOS2, and receiving the message on subscribed topic with QOS2"""
    test_name = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, zephyr_wifi_collections=zephyr_wifi_collections, test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wlan_obj.subscribe_and_publish(wifi_dut, mqtt_client, mqtt_server, qos=2, keep_alive=60)

        # Log MAC addresses for reference
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC ADDRESS: {ap_mac_address}")

        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wlan_obj.sniffer_capture(mode='stop')
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '


    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": wan_ipv6_addr,
                               "wan_ipv6_gateway": wan_gateway,
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('TC0123570318')
def test_wifi_zephyr_http_get_ipv6(wifi_dut, wifi_access_point,
                                   wifi_sniffer,
                                   zephyr_wifi_collections, request,
                                   sniffer_filter,
                                   http_server, wifi_client, index_path, http_client):
    """Verify HTTP get functionality on IPV6 """
    test_name = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, zephyr_wifi_collections=zephyr_wifi_collections, test_id=119348,
                              wifi_client=wifi_client,
                              power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        # device_ip = wlan_obj.dut_ipv6
        host_ip = wlan_obj.remote_ipv6

        wlan_obj.http_get_put_post(wifi_dut, http_client, http_server, port=80, server_ip=host_ip, url="/" + index_path)

        # Log MAC addresses for reference
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC ADDRESS: {ap_mac_address}")

        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wlan_obj.sniffer_capture(mode='stop')
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
