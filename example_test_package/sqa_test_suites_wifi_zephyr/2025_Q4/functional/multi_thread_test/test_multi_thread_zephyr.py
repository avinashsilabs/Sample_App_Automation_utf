from utf.utils import print_dict
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
import re
import random
import string
from utf.utils.stopwatch import Stopwatch
from utf_wifi_zephyr.devices.si91x import Si91xBSDSocketParams, ZephyrHttpMethods
from base64 import b64decode
from utf.utf_config import UtfConfig

"""This function runs below test steps for DUT-Si91x
        1. Configuration of DUT in 2G : gnbax
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Run TCP, UDP, MQTT, SNTP functionalities in multiple threads
       

    setup requirement:
        1. soc board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)
        
    Author: Vinod 
"""


def logger():
    return get_logger(__name__)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, net_perf_client=None, wifi_client=None,
                 protocol=None, capture_filename=None, zephyr_wifi_collections=None, power_save=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.capture_filename = capture_filename
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.dut_addr = None
        self.power_save = power_save

    def run(self):
        try:
            logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
            # The below method is not supported in zephyr
            # self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
            #                                                               beacon_missed_count=40,
            #                                                               first_time_retry_enable=0)
            self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                              associated=self.wifi_dut.interfaces.wifi.associated,
                                                                              ping_after_power_save=True,
                                                                              power_save=self.power_save)
        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")


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


class ICMPTX(ThreadBase):
    def __init__(self, wifi_dut, target_ip, packet_count, timeout_ms, success_threshold):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.target_ip = target_ip
        self.packet_count = packet_count
        self.timeout_ms = timeout_ms
        self.success_threshold = success_threshold

    def run(self):
        logger().info(f"\n *** Starting ICMP Send Test *** \n")
        logger().info(f"Target IP: {self.target_ip}")
        logger().info(f"Packet Count: {self.packet_count}")
        logger().info(f"Timeout: {self.timeout_ms}ms")
        logger().info(f"Success Threshold: {self.success_threshold}%")

        try:
            # Send ICMP packets using the DUT's icmp_ping method
            logger().info(f"Sending {self.packet_count} ICMP packets to {self.target_ip}")

            # Use the icmp_ping method from the WiFi interface
            data = self.wifi_dut.interfaces.wifi.icmp_ping(
                target_ip=self.target_ip,
                packet_count=self.packet_count,
                timeout_ms=self.timeout_ms,
                ip_version=4,
                timeout=120  # Overall timeout for the operation
            )

            success_count = data

            # Calculate success percentage
            success_percentage = (success_count / self.packet_count) * 100
            logger().info(f"Success Rate: {success_percentage:.2f}%")

            # Validate against threshold
            if success_percentage >= self.success_threshold:
                logger().info(
                    f"✓ ICMP test PASSED - Success rate {success_percentage:.2f}% meets threshold {self.success_threshold}%")
                return True
            else:
                logger().error(
                    f"✗ ICMP test FAILED - Success rate {success_percentage:.2f}% below threshold {self.success_threshold}%")
                return False


        except Exception as e:
            logger().error(f"ICMP ping operation failed: {str(e)}")
            return False


class ICMPRX(ThreadBase):
    def __init__(self, zephyr_wifi_collections, device_ip, ping_count, byte_size):
        super().__init__()
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.device_ip = device_ip
        self.ping_count = ping_count
        self.byte_size = byte_size

    def run(self):
        try:
            ping_status = self.zephyr_wifi_collections.ping_with_custom_size(self.device_ip, ping_counts=60,
                                                                             byte_size=10)
            assert ping_status, "DUT is not responding to ping request"
            logger().info("ping to DUT is successful....")
        except Exception as e:
            logger().error(f"ICMP ping operation failed: {str(e)}")
            return False


class SNTPTHREAD(ThreadBase):
    def __init__(self, wifi_dut, query_count):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.query_count = query_count
        self.query_success = 0
        self.query_fail = 0

    def run(self):
        try:
            logger().info(f"\n *** Starting ICMP Send Test *** \n")
            # Initialize SNTP once
            logger().info("Initializing SNTP client for multiple queries...")
            status, init_data = self.wifi_dut.interfaces.wifi.sntp_init(port=123,
                                                                        ip_version=4,
                                                                        timeout=30
                                                                        )
            logger().info(f"SNTP Init Status: {status}")
            # Perform multiple queries
            for i in range(self.query_count):
                logger().info(f"Performing SNTP query {i + 1}/{self.query_count}...")

                date_time_string = self.wifi_dut.interfaces.wifi.sntp_query(
                    timeout_ms=5000,
                    timeout=30
                )
                if "Date and Time" in date_time_string:
                    self.query_success = self.query_success + 1
                else:
                    self.query_fail = self.query_fail + 1

            logger().info(f"sntp query  successful attempts {self.query_success}, failed attempts {self.query_fail}")
            # Close SNTP context
            logger().info("Closing SNTP context...")
            close_status, close_data = self.wifi_dut.interfaces.wifi.sntp_close(timeout=10)
            logger().info(f"SNTP Close Status: {close_status}")

        except Exception as e:
            logger().error(f"Test failed with exception: {str(e)}")
            # Attempt to close SNTP context
            try:
                self.wifi_dut.interfaces.wifi.sntp_close(timeout=10)
            except:
                pass


class DNSTHREAD(ThreadBase):
    def __init__(self, wifi_dut, query_count):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.query_count = query_count
        self.query_success = 0
        self.query_fail = 0

    def run(self):
        try:
            for count in range(0, self.query_count):
                status, data = self.wifi_dut.interfaces.wifi.dns_get_addr_info()
                if ("DNS resolving finished" in data) and ("DNS IPv4 address" in data):
                    self.query_success = self.query_success + 1
                else:
                    self.query_fail = self.query_fail + 1
            logger().info(
                f"DNS query stats status\nNumber of dns queries sent: {self.query_count}\nsuccess:{self.query_success}\nfail:{self.query_fail}\n")
        except Exception as e:
            logger().error(f"Test failed with exception: {str(e)}")


class HTTP_CLIENT_THREAD(ThreadBase):
    def __init__(self, wifi_dut, http_client=None, device_ip=None, port=80, server_ip="", url="",
                 method=ZephyrHttpMethods.GET,
                 payload="", iteration_count=1):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.iteration_count = iteration_count
        self.port = port
        self.server_ip = server_ip
        self.url = url
        self.method = method
        self.payload = payload
        self.http_client = http_client
        self.device_ip = device_ip

    def run(self):
        for iter_count in range(0, self.iteration_count):
            logger().info(f"Running http_client test iteration for {iter_count + 1} time")
            try:
                socket_id = self.wifi_dut.interfaces.wifi.socket(domain=Si91xBSDSocketParams.AF_INET,
                                                                 stream_type=Si91xBSDSocketParams.SOCK_STREAM,
                                                                 protocol=Si91xBSDSocketParams.IPPROTO_TCP)
                logger().info(f"Socket open successfully : {socket_id}")
                logger().info("bind the socket")
                self.wifi_dut.interfaces.wifi.bind(
                    socket_fd=socket_id, device_ip=self.device_ip, port=5001, timeout=5)

                logger().info("DUT is connecting to server socket")
                for count in range(3):
                    connect_status = False
                    try:
                        self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                            socket_id, self.server_ip, self.port)
                        connect_status = True
                        break
                    except:
                        logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                        assert connect_status, "Socket connection failed in DUT"

                http_content_dut = self.wifi_dut.interfaces.wifi.http_client_req(socket_id, ZephyrHttpMethods.GET,
                                                                                 self.url,
                                                                                 self.server_ip)
                status_client, content_client = self.http_client.interfaces.http.http_get(
                    self.http_server.interfaces.http, self.url)
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

            except:
                logger().info("HTTP GET, POST, or PUT METHOD FAILED")
            finally:
                self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)


class MQTTTHREAD(ThreadBase):
    def __init__(self, wifi_dut, mqtt_client, mqtt_server, qos=0, iteration_count=10):
        self.wifi_dut = wifi_dut
        self.mqtt_client = mqtt_client
        self.mqtt_server = mqtt_server
        self.qos = qos
        self.iteration_count = iteration_count

    def run(self):
        try:
            for cont in range(0, self.iteration_count):
                self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
                self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
                logger().info(".....MQTT Client connects to MQTT server.....")
                self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=self.mqtt_server.interfaces.mqtt)
                time.sleep(2)
                if self.qos == 0:
                    dut_subscribe_topic = "mytesttopic_qos0_dut"
                    topic = "mytesttopic_qos0"
                elif self.qos == 1:
                    dut_subscribe_topic = "mytesttopic_qos1_dut"
                    topic = "mytesttopic_qos1"
                else:
                    dut_subscribe_topic = "mytesttopic_qos2_dut"
                    topic = "mytesttopic_qos2"

                message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
                client_message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))

                logger().info("MQTT Client subscribes to the topic")
                self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=self.qos)

                logger().info("DUT subscribes to the topic")
                self.wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=dut_subscribe_topic, qos=self.qos)

                logger().info("DUT publishes message over the topic")
                publish_response = self.wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message,
                                                                                     qos=self.qos,
                                                                                     timeout=20)
                logger().info(f"publish response-----------> {publish_response}")
                time.sleep(2)

                msgs = []
                sw = Stopwatch()
                while sw.elapsed_sec < 10:
                    time.sleep(0.1)
                    msgs = self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                    if len(msgs) == 1:
                        break
                assert len(msgs) == 1, "No message is received by mqtt-client"
                assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
                if self.qos == 0:
                    assert msgs[0].qos == self.qos, "DUT sent message with wrong QOS. expected is QOS0"
                if self.qos == 1:
                    assert msgs[0].qos == self.qos, "DUT sent message with wrong QOS. expected is QOS1"
                if self.qos == 2:
                    assert msgs[0].qos == self.qos, "DUT sent message with wrong QOS. expected is QOS2"
                assert msgs[
                           0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                           "message received is wrong"

                self.mqtt_client.interfaces.mqtt.mqtt_client_publish(topic=dut_subscribe_topic, payload=client_message,
                                                                     qos=self.qos)
                data = self.wifi_dut.interfaces.mqtt.mqtt_client_set_idle(sync_timeout=10)

                topic_match = re.search(r"topic\s*-\s*['\"]([^'\"]+)['\"]", data)
                topic_receive = topic_match.group(1) if topic_match else None

                # Extract payload (after "payload:")
                payload_match = re.search(r"payload:\s*(.+?)(?:\n|$)", data, re.IGNORECASE)
                payload_receive = payload_match.group(1).strip() if payload_match else None

                assert topic_receive == dut_subscribe_topic, "No message received by DUT on MQTT on subscribed topic"
                assert payload_receive == client_message, "No message is received by DUT on MQTT on subscribed topic or " \
                                                          "message received is wrong"

                self.wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic, qos=self.qos)

                self.wifi_dut.interfaces.mqtt.mqtt_client_disconnect()

        except Exception as e:
            logger().error(f"Test failed with exception: {str(e)}")
            # Attempt to close MQTT context
            try:
                self.wifi_dut.interfaces.wifi.mqtt_client_disconnect(timeout=10)
            except:
                pass


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C792360')
def test_wifi_zephyr_tcp_tx_udp_tx_c792360(wifi_dut, wifi_access_point,
                                           wifi_sniffer, sniffer_filter,
                                           zephyr_wifi_collections, request,
                                           utf_constants, wifi_client,
                                           net_perf_clients):
    """ Verify TCP TX and UDP TX functionalities in multiple threads """

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_clients[0], wifi_client=wifi_client,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                            power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        device_ip = wifi_obj.dut_addr['device_ip']
        dut_mac_address = wifi_obj.dut_addr['dut_mac_address']
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid

        ipv4_obj = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                               sl_collections=zephyr_wifi_collections,
                               test_name=capture_filename, wifi_client=wifi_client,
                               traffic_type="TX", protocol="TCP", net_perf_client=net_perf_clients[0], timeout=60,
                               device_ip=device_ip, remote_ip=host_ip,
                               ip_version=4
                               )
        ipv6_obj = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                               sl_collections=zephyr_wifi_collections,
                               test_name=capture_filename, wifi_client=wifi_client,
                               traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=60,
                               device_ip=device_ip, remote_ip=host_ip,
                               ip_version=4

                               )

        ipv4_obj.start()
        ipv6_obj.start()
        time.sleep(5)

        ipv4_obj.wait_for_exit()
        ipv6_obj.wait_for_exit()
        time.sleep(5)
        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C792355')
def test_wifi_zephyr_tcp_tx_tcp_rx_c792355(wifi_dut, wifi_access_point,
                                           wifi_sniffer, sniffer_filter,
                                           zephyr_wifi_collections, request,
                                           utf_constants, wifi_client,
                                           net_perf_clients):
    """ Verify TCP TX and TCP RX functionalities in multiple threads """

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_clients[0], wifi_client=wifi_client,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                            power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        device_ip = wifi_obj.dut_addr['device_ip']
        dut_mac_address = wifi_obj.dut_addr['dut_mac_address']
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid

        socket1_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="TX", protocol="TCP", net_perf_client=net_perf_clients[0], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=4
                                     )
        socket2_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="RX", protocol="TCP", net_perf_client=net_perf_clients[1], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=4

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
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C792357')
def test_wifi_zephyr_udp_tx_udp_rx_c792357(wifi_dut, wifi_access_point,
                                           wifi_sniffer, sniffer_filter,
                                           zephyr_wifi_collections, request,
                                           utf_constants, wifi_client,
                                           net_perf_clients):
    """ Verify UDP TX and UDP RX functionalities in multiple threads """

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_clients[0], wifi_client=wifi_client,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                            power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        device_ip = wifi_obj.dut_addr['device_ip']
        dut_mac_address = wifi_obj.dut_addr['dut_mac_address']
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid

        socket1_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[0], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=4
                                     )
        socket2_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=4

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
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C792356')
def test_wifi_zephyr_tcp_tx_udp_rx_c792356(wifi_dut, wifi_access_point,
                                           wifi_sniffer, sniffer_filter,
                                           zephyr_wifi_collections, request,
                                           utf_constants, wifi_client,
                                           net_perf_clients):
    """ Verify TCP TX and UDP RX functionalities in multiple threads """

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_clients[0], wifi_client=wifi_client,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                            power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        device_ip = wifi_obj.dut_addr['device_ip']
        dut_mac_address = wifi_obj.dut_addr['dut_mac_address']
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid

        socket1_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="TX", protocol="TCP", net_perf_client=net_perf_clients[0], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=4
                                     )
        socket2_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=4

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
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.test_src_map_id('C792361')
def test_wifi_zephyr_tcp_rx_udp_rx_c792361(wifi_dut, wifi_access_point,
                                           wifi_sniffer, sniffer_filter,
                                           zephyr_wifi_collections, request,
                                           utf_constants, wifi_client,
                                           net_perf_clients):
    """ Verify TCP RX and UDP RX functionalities in multiple threads """

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_clients[0], wifi_client=wifi_client,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                            power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        device_ip = wifi_obj.dut_addr['device_ip']
        dut_mac_address = wifi_obj.dut_addr['dut_mac_address']
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid

        socket1_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="RX", protocol="TCP", net_perf_client=net_perf_clients[0], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=4
                                     )
        socket2_thread = IperfThraed(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=zephyr_wifi_collections,
                                     test_name=capture_filename, wifi_client=wifi_client,
                                     traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=60,
                                     device_ip=device_ip, remote_ip=host_ip,
                                     ip_version=4

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
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.test_src_map_id('C792358')
def test_wifi_zephyr_icmp_tx_icmp_rx_c792358(wifi_dut, wifi_access_point,
                                             wifi_sniffer, sniffer_filter,
                                             zephyr_wifi_collections, request,
                                             utf_constants, wifi_client,
                                             ):
    """ Verify ICMP TX AND IMCP RX functionality in multiple threads """

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                            power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        device_ip = wifi_obj.dut_addr['device_ip']
        dut_mac_address = wifi_obj.dut_addr['dut_mac_address']
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid

        target_ip = host_ip
        packet_count = 1000
        timeout_ms = 1000
        success_threshold = 70
        ping_count_rx = 20
        byte_size_rx = 20
        icmp_tx = ICMPTX(wifi_dut, target_ip, packet_count, timeout_ms, success_threshold)
        icmp_rx = ICMPRX(zephyr_wifi_collections, device_ip, ping_count_rx, byte_size_rx)
        icmp_tx.start()
        icmp_rx.start()
        time.sleep(5)
        icmp_tx.wait_for_exit()
        icmp_rx.wait_for_exit()
        time.sleep(5)
        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.test_src_map_id('C792359')
def test_wifi_zephyr_sntp_mqtt_operations_in_multiple_threads_c792359(wifi_dut, wifi_access_point,
                                                                      wifi_sniffer, sniffer_filter,
                                                                      zephyr_wifi_collections, request,
                                                                      utf_constants, wifi_client,
                                                                      mqtt_client, mqtt_server
                                                                      ):
    """ Verify SNTP and MQTT operations in multiple threads """

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                            power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        dut_mac_address = wifi_obj.dut_addr['dut_mac_address']
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        query_count = 300
        sntp_thread = SNTPTHREAD(wifi_dut, query_count)
        mqtt_thread = MQTTTHREAD(wifi_dut, mqtt_client, mqtt_server, iteration_count=20)
        sntp_thread.start()
        mqtt_thread.start()
        time.sleep(5)
        sntp_thread.wait_for_exit()
        mqtt_thread.wait_for_exit()

        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.test_src_map_id('C792364')
def test_wifi_zephyr_dns_mqtt_operations_in_multiple_threads_c792364(wifi_dut, wifi_access_point,
                                                                     wifi_sniffer, sniffer_filter,
                                                                     zephyr_wifi_collections, request,
                                                                     utf_constants, wifi_client,
                                                                     mqtt_client, mqtt_server
                                                                     ):
    """ Verify SNTP and MQTT operations in multiple threads """

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                            power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        dut_mac_address = wifi_obj.dut_addr['dut_mac_address']
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        query_count = 300
        dns_thread = DNSTHREAD(wifi_dut, query_count)
        mqtt_thread = MQTTTHREAD(wifi_dut, mqtt_client, mqtt_server, iteration_count=20)
        dns_thread.start()
        mqtt_thread.start()
        time.sleep(5)
        dns_thread.wait_for_exit()
        mqtt_thread.wait_for_exit()

        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.test_src_map_id('C792363')
def test_wifi_zephyr_http_client_icmp_in_multiple_threads_c792363(wifi_dut, wifi_access_point,
                                                                  wifi_sniffer, sniffer_filter,
                                                                  zephyr_wifi_collections, request,
                                                                  utf_constants, wifi_client, http_server,
                                                                  index_path, http_client
                                                                  ):
    """ Verify HTTP CLIENT and ICMP rx in multiple threads """

    capture_filename = request.node.name
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections,
                            power_save=power_save)
        device_ip = wifi_obj.dut_addr['device_ip']
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        dut_mac_address = wifi_obj.dut_addr['dut_mac_address']
        logger().info(f"DUT MAC ADDRESS: {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        iteration_count = 20

        target_ip = host_ip
        packet_count = 1000
        timeout_ms = 1000
        success_threshold = 70
        icmp_tx = ICMPTX(wifi_dut, target_ip, packet_count, timeout_ms, success_threshold)

        http_thread = HTTP_CLIENT_THREAD(wifi_dut, http_client, device_ip=device_ip, port=80, server_ip=host_ip,
                                         url="/" + index_path,
                                         method=ZephyrHttpMethods.GET, payload="", iteration_count=iteration_count)

        http_thread.start()
        icmp_tx.start()
        time.sleep(5)
        http_thread.wait_for_exit()
        icmp_tx.wait_for_exit()

        logger().info("Disconnect to AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
