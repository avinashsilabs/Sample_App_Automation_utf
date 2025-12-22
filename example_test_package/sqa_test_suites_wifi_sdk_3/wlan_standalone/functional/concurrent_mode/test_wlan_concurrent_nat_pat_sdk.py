import re
import uuid
from datetime import datetime
import time
from typing import Dict
from random import randint
from threading import Thread
from retry import retry
from example_test_package.sqa_test_suites.bt_classic.functional.bt_profiles.test_bt_a2dp import timeout
from utf.interfaces.aws_iot.fixtures import aws_iot_client
from utf.interfaces.aws_iot.fixtures import aws_iot_clients
from utf.interfaces.http.fixtures import http_client, http_server, http_servers
from utf.interfaces.socket.fixtures import remote_socket_factory
from utf.interfaces.wifi.fixtures import remote_wiseconnect
from utf.utils.time_measurer import TimeMeasurer
from utf.utf_config import UtfConfig
from utf.interfaces.wifi import SecurityMode
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
import pytest as pytest
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf import UtfDatabaseProperties
from utf_wifi_zephyr.sl_status import SLStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xAwsQos
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
import string
import random


"""
    setup requirement:
        1. DUT(RS9117SOC)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
    Test Steps:
        1. Configure the DUT in concurrent mode
        2. create DUT as access point and join DUT to 3rd party access point
        3. Enable the NAT-PAT feature and connect 4 client/Stations to APUT
        4. Varify the ICMP connection with inbound and outbound traffic
        5. Verify the data transfer with inbound and outbound traffic
        4. Disable the NAT-PAT feature
    Author: Sakshi Agrawal
"""


def logger():
    return get_logger(__name__)
class tcp_tx_thread(ThreadBase):
    def __init__(self, remote_socket, remote_wiseconnect3, AP_backend_ip, sta_ip, local_port, sock):
        super().__init__()
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.remote_socket = remote_socket
        self.local_port = local_port
        self.AP_backend_ip = AP_backend_ip
        self.sta_ip = sta_ip
        self.socket_id = sock

    def run(self):
        tx_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=90))
        self.remote_wiseconnect3.interfaces.wifi.bsdSocketConnect(
            socket_fd=self.socket_id, server_ip=self.AP_backend_ip, server_port=self.local_port)
        i = 0
        start_time = time.time()
        while time.time() - start_time < 30:
            i = i + 1# Run for 5 minutes (300 seconds)
            logger().info(f"\n ****** Sending data from STA to AP_Backend: time left: {time.time() - start_time} and iteration: {i} ******* \n")
            self.remote_wiseconnect3.interfaces.wifi.bsdSocketSend(socket_fd=self.socket_id, data=tx_data)
            time.sleep(2)
            rx_data = self.remote_socket.recv_data_tcp(data_size=len(tx_data))

            assert tx_data == rx_data, f"Data Mismatch: Sent data: {tx_data}, Received data: {rx_data}"
            logger().info(f"Data packet received iteration {i+1}")
            time.sleep(2)

        logger().info(f"Data transfer from STA{i + 1} to AP_Backend is successful")

        logger().info("Closing the BSD socket and remote socket")
        self.remote_wiseconnect3.interfaces.wifi.bsdSockClose(socket_fd=self.socket_id)
        self.remote_socket.stop()

class tcp_rx_thread(ThreadBase):
    def __init__(self, remote_socket, remote_wiseconnect3, AP_backend_ip, sta_ip, local_port, sock):
        super().__init__()
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.remote_socket = remote_socket
        self.local_port = local_port
        self.AP_backend_ip = AP_backend_ip
        self.sta_ip = sta_ip
        self.socket_id = sock

    def run(self):
        tx_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=90))
        self.remote_wiseconnect3.interfaces.wifi.bsdSocketConnect(
            socket_fd=self.socket_id, server_ip=self.AP_backend_ip, server_port=self.local_port)

        i = 0
        start_time = time.time()
        while time.time() - start_time < 300:
            i = i + 1# Run for 5 minutes (300 seconds)
            logger().info(f"\n ****** Sending data from AP_Backend to STA: time left {time.time() - start_time} and iteration: {i}******* \n")
            self.remote_socket.send_data_tcp(tx_data, True)
            time.sleep(2)
            rx_data = self.remote_wiseconnect3.interfaces.wifi.bsdSocketReceive(socket_fd=self.socket_id)

            assert tx_data == rx_data, f"Data Mismatch: Sent data: {tx_data}, Received data: {rx_data}"
            logger().info(f"Data packet received iteration {i+1}")
            time.sleep(2)

        logger().info(f"Data transfer from AP backend to STA{i + 1} is successful")

        logger().info("Closing the BSD socket and remote socket")
        self.remote_wiseconnect3.interfaces.wifi.bsdSockClose(socket_fd=self.socket_id)
        self.remote_socket.stop()


class udp_tx_thread(ThreadBase):
    def __init__(self, remote_socket, remote_wiseconnect3, AP_backend_ip, sta_ip, local_port, sock):
        super().__init__()
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.remote_socket = remote_socket
        self.local_port = local_port
        self.AP_backend_ip = AP_backend_ip
        self.sta_ip = sta_ip
        self.socket_id = sock

    def run(self):
        tx_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=90))
        i = 0
        start_time = time.time()
        while time.time() - start_time < 300:
            i = i + 1
            logger().info(f"\n ****** Sending data from STA to AP_Backend: time left {time.time() - start_time} and iteration: {i} ******* \n")
            send_bytes = self.remote_wiseconnect3.interfaces.wifi.bsdSocketSendTo(socket_fd=self.socket_id,
                                                                                  data=tx_data,
                                                                                  ip_addr=self.AP_backend_ip,
                                                                                  ip_len=4, port=self.local_port)

            rx_data, client_addr = self.remote_socket.recv_data_udp(data_size=len(tx_data))
            logger().info(f"data received : {rx_data}, {client_addr[0]}, {client_addr[1]}")
            assert tx_data == rx_data, f"Data Mismatch: Sent data: {tx_data}, Received data: {rx_data}"
            logger().info(f"Data packet received iteration {i + 1}")
            time.sleep(2)

        logger().info(f"Data transfer from STA{i + 1} to AP backend is successful")

        logger().info("Closing the BSD socket and remote socket")
        self.remote_wiseconnect3.interfaces.wifi.bsdAsyncSockClose(socket_fd=self.socket_id)
        self.remote_socket.stop()

class udp_rx_thread(ThreadBase):
    def __init__(self, remote_socket, remote_wiseconnect3, AP_backend_ip, sta_ip, local_port, sock):
        super().__init__()
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.remote_socket = remote_socket
        self.local_port = local_port
        self.AP_backend_ip = AP_backend_ip
        self.sta_ip = sta_ip
        self.socket_id = sock

    def run(self):
        tx_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=90))
        logger().info("Step 1: Send initial message to trigger server")
        data = "Thisisfromclient"
        send_bytes = self.remote_wiseconnect3.interfaces.wifi.bsdSocketSendTo(socket_fd=self.socket_id, data=data,
                                                                                  ip_addr=self.AP_backend_ip,
                                                                                  ip_len=4, port=self.local_port)

        recv_data, client_addr = self.remote_socket.recv_data_udp(data_size=len(data))
        logger().info(f"data received : {recv_data}, {client_addr[0]}, {client_addr[1]}")
        assert data == recv_data, f"Data Mismatch: Sent data: {data}, Received data: {recv_data}"

        logger().info(f"Step 2: Data transfer from AP b"
                      f"ackend server to station")
        start_time = time.time()
        while time.time() - start_time < 300:
            logger().info(f"\n ****** Sending data from AP_Backend to STA: time left {time.time() - start_time} ******* \n")
            self.remote_socket.send_data_udp(tx_buffer=tx_data, server_ip=client_addr[0], port=client_addr[1], sock_id=self.socket_id)
            rx_data = self.remote_wiseconnect3.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=self.socket_id)

            assert tx_data == rx_data, f"Data Mismatch: Sent data: {tx_data}, Received data: {rx_data}"
            logger().info(f"Data packet received iteration {i+1}")
            time.sleep(10)

        logger().info(f"Data transfer from AP backend to STA{i + 1} is successful")

        logger().info("Closing the BSD socket and remote socket")
        self.remote_wiseconnect3.interfaces.wifi.bsdAsyncSockClose(socket_fd=self.socket_id)
        self.remote_socket.stop()

class SocketThread(ThreadBase):
    def __init__(self, remote_wiseconnect3s, remote_socket_factory, protocol, traffic_type, AP_backend_ip, sta_ip):
        super().__init__()
        self.remote_wiseconnect3s = remote_wiseconnect3s
        self.protocol = protocol
        self.traffic_type = traffic_type
        self.AP_backend_ip = AP_backend_ip
        self.sta_ip = sta_ip
        self.sta_ips = ["192.168.100.77", "192.168.100.78", "192.168.100.79", "192.168.100.80"]
        self.remote_socket_factory = remote_socket_factory
        self.server_sockets = []
        self.client_sockets = []
        self.client_threads = []

    def socket_creation_and_data_transfer(self):
        logger().info(f"\n ********* Open the client sockets on the stations and server socket at AP Backend ********* \n")

        for i in range(0, len(self.remote_wiseconnect3s)):
            if self.protocol == "TCP":
                base_port = 5001
                local_port = base_port + i
                sock = self.remote_wiseconnect3s[i].interfaces.wifi.socket()
                self.client_sockets.append(sock)

            else:
                base_port = 8001
                local_port = base_port + i
                sock = self.remote_wiseconnect3s[i].interfaces.wifi.Asyncsocket(domain="AF_INET",
                                                                                stream_type="SOCK_DGRAM",
                                                                                protocol="IPPROTO_UDP")
                self.client_sockets.append(sock)
            server_socket = self.remote_socket_factory.interfaces.socket.create_socket()
            self.server_sockets.append(server_socket)

            if self.protocol == "TCP" and self.traffic_type == "RX":
                server_socket.start_server(port=local_port)
                self.client_threads.append(
                    tcp_rx_thread(server_socket, self.remote_wiseconnect3s[i], self.AP_backend_ip, self.sta_ips[i],
                                  local_port, sock))

            elif self.protocol == "UDP" and self.traffic_type == "RX":
                server_socket.start_server(port=local_port, socket_type=1)
                self.client_threads.append(
                    udp_rx_thread(server_socket, self.remote_wiseconnect3s[i], self.AP_backend_ip, self.sta_ips[i],
                                  local_port, sock))

            elif self.protocol == "TCP" and self.traffic_type == "TX":
                server_socket.start_server(port=local_port)
                self.client_threads.append(
                    tcp_tx_thread(server_socket, self.remote_wiseconnect3s[i], self.AP_backend_ip, self.sta_ips[i],
                                  local_port, sock))

            else:
                server_socket.start_server(port=local_port, socket_type=1)
                self.client_threads.append(
                    udp_tx_thread(server_socket, self.remote_wiseconnect3s[i], self.AP_backend_ip, self.sta_ips[i],
                                  local_port, sock))

        for th in self.client_threads:
            th.start()
        for th in self.client_threads:
            th.wait_for_exit()

class ConcurrentThread(ThreadBase):
    def __init__(self, wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants, wifi_access_point, testcase_no = None, capture_filename = None,  ping=True, stop_sniffer=True, leave=False,
                 ht_caps=0, remote_wiseconnect3s=None):
        super().__init__()
        self.ap_mac_address = None
        self.wifi_dut = wifi_dut
        self.sl_collections = sl_collections
        self.wifi_sniffer = wifi_sniffer
        self.remote_wiseconnect3s = remote_wiseconnect3s
        self.sniffer_filter = sniffer_filter
        self.wifi_client = wifi_client
        self.utf_constants = utf_constants
        self.wifi_access_point = wifi_access_point
        self.testcase_no = testcase_no
        self.capture_filename = capture_filename
        self.ping = ping
        self.stop_sniffer = stop_sniffer
        self.leave = leave
        self.no_of_clients = len(self.remote_wiseconnect3s)
        self.channel = "3"
        self.ssid = "SILABS_AP_MODE"
        self.security = "open"
        self.password = "None"
        self.dtim_count = "1"
        self.beacon_interval = "100"
        self.ht_caps = ht_caps
        self.AP_backend_ip = None
        self.ping_count = 10
        self.sta_ips = ["192.168.100.77", "192.168.100.78", "192.168.100.79", "192.168.100.80"]

    def disconnect_stations(self):
        for i in range(0, len(self.remote_wiseconnect3s)):
            self.remote_wiseconnect3s[i].interfaces.wifi.leave()

    def verify_icmp_connection(self, ping_size=64):
        for i in range(0, len(self.remote_wiseconnect3s)):
            logger().info(f"********* Start Ping from station {i+1} to AP backend ip: {self.AP_backend_ip} *********")
            self.remote_wiseconnect3s[i].interfaces.sapi.ping(server_ip=self.AP_backend_ip,
                                                          num_ping_attempts=self.ping_count,
                                                          ping_timeout=10, ip_version='ipv4', ping_size=ping_size)

            if self.testcase_no == 793739:
                logger().info(f"********* Start Ping from station {i + 1} to AP backend ip: {self.AP_backend_ip} with ping size more than 300 bytes *********")
                try:
                    self.remote_wiseconnect3s[i].interfaces.sapi.ping(server_ip=self.AP_backend_ip,
                                                                  num_ping_attempts=5,
                                                                  ping_timeout=10, ip_version='ipv4',
                                                                  ping_size=310)
                except Exception as Ex:
                    events = self.remote_wiseconnect3s[i].interfaces.wifi.get_async_events()
                    ping_events = [event for event in events if event.event_type == AsyncEventIdentifiers.PING]
                    if "Ping request failed with status 0x1002F" in ping_events[-1].event_data:
                        logger().info(f"\n Ping more than 300 bytes failed as expected with SL_STATUS_SI91X_ICMP_DATA_SIZE_EXCEED_MAX_LIMIT: 0x1002F from STA{i+1} to AP backend \n")
                    else:
                        logger().info(f"\n Ping more than 300 bytes did not fail as expected from STA{i+1} to AP backend \n")
                        raise Ex

            if self.testcase_no == 793734:
                logger().info(f"********* ICMP connection with inbound traffic *********")
                logger().info(f"\n ********* Start Ping from AP backend ip: {self.AP_backend_ip} to station {i+1} ********* \n")
                rc, stdout, stderr = self.wifi_client.interfaces.wifi.shell.execute(
                    f"sudo ping -c 5 {self.sta_ips[i]}")
                assert rc != 0, f"AP backend passed to ping Station {i+1}: {self.sta_ips[i]}"
                logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                logger().info(f"AP backend failed to ping station {self.sta_ips[i]} as expected")


    def disable_NAT(self):
        self.wifi_dut.interfaces.wifi.nat_disable()

    def run(self):
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ip_version = 'ipv4'
        ping_count = self.utf_constants.get("ping_count")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")

        self.dut_addr = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            power_save=False,
            ping_after_power_save=True, retry_count=3,
            associated=self.wifi_dut.interfaces.wifi.associated
        )
        device_ip = self.dut_addr['device_ip']

        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap_bssid : {self.ap_mac_address}")

        self.sl_collections.configure_dut_in_static_ip(
            self.wifi_dut, static_ip=static_gateway,
            static_subnet=static_subnet,
            static_gateway=static_gateway
        )

        self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security=self.security, channel=self.channel, psk=self.password,
                                               dtim_beacon_count=self.dtim_count,
                                               beacon_interval=self.beacon_interval, encryption=None,
                                               ht_caps=self.ht_caps)

        time.sleep(2)

        for i in range(0,len(self.remote_wiseconnect3s)):
            self.remote_wiseconnect3s[i].interfaces.sapi.scan(channel=self.channel, ssid=self.ssid)
            time.sleep(2)

            self.remote_wiseconnect3s[i].interfaces.sapi.join(ssid=self.ssid,
                                                          security=self.security,
                                                          passphrase=self.password,
                                                          channel=self.channel, timeout=60)
            self.remote_wiseconnect3s[i].interfaces.sapi.start_ip(ip_version=ip_version, static_ip=self.sta_ips[i],
                                                              static_subnet=static_subnet,
                                                              static_gateway=static_gateway, timeout=10)

            self.remote_wiseconnect3s[i].interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=self.ping_count,
                                                      ping_timeout=10, ip_version='ipv4', ping_size=64)

        logger().info(f"********* start the NAT ENABLE *********")
        self.wifi_dut.interfaces.wifi.nat_enable()
        self.AP_backend_ip = self.wifi_client.interfaces.wifi.get_ip_address()  # AP backend
        logger().info(f"AP backend IP address: {self.AP_backend_ip}")

        logger().info(f"********* Start Ping from all STAs to AP backend  *********")
        self.verify_icmp_connection()

        if self.testcase_no == 793738:
            for i in range(len(self.remote_wiseconnect3s)):
                logger().info("\n==DNS address command is given when both primary and secondary DNS server ip addresses are given NULL ==\n")
                self.remote_wiseconnect3s[i].interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",
                                                                             secondary_dns_server_address="10.8.4.10",
                                                                             timeout=50)

                self.remote_wiseconnect3s[i].interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000,
                                                                     ip_version="ipv4", timeout=50)
    def verify_data_transfer_sniffer_validation(self):
        if self.testcase_no == 793729:
            for i, ip in enumerate(self.sta_ips):
                packet_filter1 = f"ip.src == {ip} && ip.dst == {self.AP_backend_ip} && tcp"
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                    'packet_count'], \
                    f'Unable to find the TCP TX packet from STA{i}: {ip} to AP backend: {self.AP_backend_ip}'
        if self.testcase_no == 793730:
            for i, ip in enumerate(self.sta_ips):
                packet_filter1 = f"ip.src == {self.AP_backend_ip} && ip.dst == {ip} && tcp"
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                    'packet_count'], \
                    f'Unable to find the TCP RX packet from AP backend: {self.AP_backend_ip} to STA{i}: {ip}'

        if self.testcase_no == 793731:
            for i, ip in enumerate(self.sta_ips):
                packet_filter1 = f"ip.src == {ip} && ip.dst == {self.AP_backend_ip} && udp"
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                    'packet_count'], \
                    f'Unable to find the UDP TX packet from STA{i}: {ip} to AP backend: {self.AP_backend_ip}'

    def concurrent_sniffer_validation(self):

        self.sl_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer,
                                                    self.dut_addr['dut_mac_address'],
                                                    self.ap_mac_address, self.sniffer_filter,
                                                    power_save=False)
        if self.testcase_no != 793739 and self.testcase_no != 793734:
            logger().info(f"********* Sniffer validation for Ping packets *********")
            for i, ip in enumerate(self.sta_ips):
                packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=ip,
                    da_addr=self.AP_backend_ip,
                    filter_name='ping_request')
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                    'packet_count'], \
                    f'Unable to find the ping request from STA{i}: {ip} to AP backend: {self.AP_backend_ip}'
                logger().info(
                    f'Ping request from STA{i + 1}: {ip} to AP backend: {self.AP_backend_ip} is validated in sniffer')

                packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.AP_backend_ip,
                    da_addr=ip,
                    filter_name='ping_response')
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
                    'packet_count'], \
                    f'Unable to find the ping response from AP backend: {self.AP_backend_ip} to STA{i + 1}: {ip}'
                logger().info(
                    f'Ping response from AP backend: {self.AP_backend_ip} to STA{i + 1}: {ip}  is validated in sniffer')

class AWSConnection(ThreadBase):
    def __init__(self, remote_wiseconnect3=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None, test_name=None,
                 aws_iot_client=None, topic=None, qos=Si91xAwsQos.QOS1, port=8883, sleep=None, client_id=None):
        super().__init__()
        self.client_id = None
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.timeout = 120
        self.aws_iot_client = aws_iot_client
        self.messages = "sakshi agrawal from aws_iot_client"
        self.topic = topic
        self.qos = qos
        self.port = port
        self.sleep = sleep
        self.client_id = client_id
        self.qos = Si91xAwsQos.QOS1
        self.timeout = 120
        self.messages = []

    @retry(Exception, delay=25, tries=3)
    def connect_to_aws_server_from_dut(self, iscleansession=True, keep_alive=1200, isWillMsgPresent=None, expected_status=SLStatus.SL_STATUS_OK,
                                       port=8883, aws_iot_mqtt_rx_buf_len=1024):
        self.remote_wiseconnect3.interfaces.wifi.aws_iot_mqtt_init(client_id=self.client_id, iscleansession=iscleansession,
                                                   keep_alive_interval=keep_alive, timeout=self.timeout,
                                                   port=port, isWillMsgPresent=isWillMsgPresent)
        time.sleep(2)
        self.remote_wiseconnect3.interfaces.wifi.aws_iot_mqtt_connect(timeout=self.timeout, expected_status=expected_status)

    @retry(Exception, delay=15, tries=5)
    def subscribe_from_dut(self):
        logger().info(f"DUT is Subscribing on topic '{self.topic}' and QOS:'{self.qos}'")
        self.remote_wiseconnect3.interfaces.wifi.aws_iot_mqtt_subscribe(topic_name=self.topic, qos=self.qos, timeout=self.timeout)

    @retry(Exception, delay=10, tries=3)
    def connect_to_aws_server_from_raspi(self):
        logger().info("Connecting to aws server from aws_iot_client")
        self.aws_iot_client.interfaces.aws_iot.aws_iot_connect()
        time.sleep(5)
        status = self.aws_iot_client.interfaces.aws_iot.client._mqtt_core._client_status.get_status()
        assert status == ClientStatus.STABLE, "Connecting to AWS server from aws_iot_client is failed"

    @retry(Exception, delay=10, tries=3)
    def subscribe_from_raspi(self):
        logger().info(f"\n\n *** aws_iot_client is Subscribing on topic '{self.topic}' and QOS:'{self.qos}'*** \n\n")
        self.aws_iot_client.interfaces.aws_iot.received_messages.clear()
        self.aws_iot_client.interfaces.aws_iot.aws_iot_subscribe(self.topic, qos=self.qos)
        status = self.aws_iot_client.interfaces.aws_iot.client._mqtt_core._client_status.get_status()
        assert status == ClientStatus.STABLE, f"Subscribe on topic:'{self.topic}' is failed from aws_iot_client"

    def validate_aws_messages_from_raspi(self, topic_1=None, topic_2=None, wait_time=10):
        logger().info("\n *** Validating received AWS messages ***")
        time.sleep(wait_time)

        # Retrieve received messages from AWS IoT client
        recv_messages = self.aws_iot_client.interfaces.aws_iot.get_received_messages()

        # Validate each received message
        for count, msg in enumerate(self.messages):
            # Determine the expected topic based on the presence of topic_1 and topic_2
            if topic_1 is not None and topic_2 is not None:
                expected_topic = topic_1 if count % 2 == 0 else topic_2
            else:
                expected_topic = self.topic

            # Log details of the received message
            logger().info(f"Received message {count + 1} is: '{recv_messages[count].payload.decode()}'")
            logger().info(f"Received message {count + 1} topic is: '{recv_messages[count].topic}'")
            logger().info(f"Received message {count + 1} qos is: '{recv_messages[count].qos}'")

            # Validate the payload, topic, and QoS
            assert recv_messages[count].payload.decode() == self.messages[count], "Received wrong message in aws_iot_client"
            assert recv_messages[count].topic == expected_topic, "Received wrong topic in aws_iot_client"
            assert recv_messages[count].qos == self.qos, "Received wrong qos in aws_iot_client"

        logger().info("AWS messages validated successfully")


    def run(self):
        for _ in range(10):
            self.messages.append(''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10)))
        logger().info(f"Messages are:{self.messages}")

        self.remote_wiseconnect3.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",
                                                                 secondary_dns_server_address="10.8.4.10",
                                                                 timeout=50)
        self.remote_wiseconnect3.interfaces.wifi.test_agent_thread_enabled = False
        self.connect_to_aws_server_from_dut()
        self.subscribe_from_dut()
        self.connect_to_aws_server_from_raspi()
        self.subscribe_from_raspi()
        start_time = time.time()
        while time.time() - start_time < 300:
            logger().info(f"\n\n ****************** Time Left for the Publish messages from Private network to Public network {time.time() - start_time}***************** \n\n")
            for count, msg in enumerate(self.messages):
                logger().info(f"\nDUT is publishing message{count + 1} on topic:'{self.topic}' \nQOS:'{self.qos}'"
                              f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
                logger().info(f"\nDUT is publishing message on topic:'{self.topic}' \nQOS:'{self.qos}'")
                self.remote_wiseconnect3.interfaces.wifi.aws_iot_mqtt_publish(topic_name=self.topic, qos=self.qos,
                                                                              payload=msg, timeout=120)
                time.sleep(3)

            self.validate_aws_messages_from_raspi()
            time.sleep(3)
        self.remote_wiseconnect3.interfaces.wifi.test_agent_thread_enabled = True

class HttpConnection(ThreadBase):
    def __init__(self, http_client, http_server, remote_wiseconnect3, index_path, station_id, port):
        super().__init__()
        self.http_client = http_client
        self.http_server = http_server
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.http_client_initialized = False
        self.index_path = index_path
        self.station_id = station_id
        self.port = port
        self.post_address = None
        self.put_address = None

    def run(self):
        # self.http_server.interfaces.http.stop_server()
        # self.http_server.interfaces.http.start_server(port=self.port)
        logger().info(f"\n\n*** Started the http server on station {self.station_id} at port {self.port} *** \n\n")

        status_client, content_client = self.http_client.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path)
        assert status_client, "failed to load the http data"
        for i in range(10):
            if not self.http_server.interfaces.http.started:
                logger().info(f"\n\n*** Restarting the http server on station {self.station_id} at port {self.port} *** \n\n")
                self.http_server.interfaces.http.stop_server()
                time.sleep(2)
                self.http_server.interfaces.http.start_server(port=self.port)
                time.sleep(2)
            logger().info(f"\n\n********************** Verify HTTP Client Functionality for http get, put and post. Iteration: {i+1} **************************** \n\n")

            self.remote_wiseconnect3.interfaces["http"] = self.remote_wiseconnect3.interfaces.wifi
            self.remote_wiseconnect3.interfaces.wifi.http_client_init()
            logger().info(f"\n\n*** Initialized the http client for station {self.station_id} *** \n\n")

            status_dut, content_dut = self.remote_wiseconnect3.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path, server_port=self.port)
            assert not status_dut, "failed to fetch the http data"
            logger().info(status_dut)
            logger().info(content_dut)
            assert content_dut == content_client, "fetched data is not same as expected data"
            logger().info(f"\n\n*** Verified the http get method for station {self.station_id} *** \n\n")

            status_dut, content_dut = self.remote_wiseconnect3.interfaces.http.http_put(
                self.http_server.interfaces.http, server_port=self.port, resource_path="cgi-bin/cgi_example.py")
            logger().info(status_dut)
            logger().info(content_dut)
            logger().info(f"\n\n*** Verified the http put method for station {self.station_id} *** \n\n")

            status_dut, content_dut = self.remote_wiseconnect3.interfaces.http.http_post(
                self.http_server.interfaces.http, "cgi-bin/cgi_example.py", post_data="thismessageisfromhttpclient", server_port=self.port)

            assert status_dut == SLStatus.SL_STATUS_OK, f"failed to post data using http post request for station {self.station_id}"
            logger().info(status_dut)
            logger().info(f"\n\n*** Verified the http post method for station {self.station_id} *** \n\n")
            time.sleep(2)

            self.remote_wiseconnect3.interfaces.wifi.http_client_deinit()
            logger().info(f"\n\n*** Deinitialized the http client for station {self.station_id} *** \n\n")
            time.sleep(60)

        # Stop the HTTP server when the thread finishes
        self.http_server.interfaces.http.stop_server()
        logger().info(f"\n\n*** Stopped the http server on station {self.station_id} at port {self.port} *** \n\n")


def wifi_dut_marker():
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.DNSClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT | Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(4),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "security": SecurityMode.Open, "ssid": "SILABS_AP_MODE", "channel": 1
    }
    return pytest.mark.config("wifi_dut", wifi=config)

def wifi_remote_wiseconnect3_marker():
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.DNSClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT | Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(4),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
    return pytest.mark.config("remote_wiseconnect3", wifi=config)

def wifi_remote_wiseconnect3s_marker():
    config = {
        0: {
            "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.WPSSupportDisabled,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.DNSClient,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT | Si91xExtTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(4),
            "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        },

        1:{
            "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.WPSSupportDisabled,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.DNSClient,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT | Si91xExtTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(4),
            "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        },

        2:{
            "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.WPSSupportDisabled,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.DNSClient,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT | Si91xExtTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(4),
            "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        }
    }
    return pytest.mark.config("remote_wiseconnect3s", wifi=config)


@wifi_dut_marker()
@wifi_remote_wiseconnect3_marker()
@wifi_remote_wiseconnect3s_marker()
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={'ssid': 'Concurent_ap', 'security': SecurityMode.Open, 'channel': 3})
def test_wifi_sdk_tcp_tx_outbound_c793729(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, remote_wiseconnect3s, protocol, remote_wiseconnect3, remote_socket_factory):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        # Check if 4 remote_wiseconnect3s are present
        if len(remote_wiseconnect3s) != 4:
            pytest.skip(
                f"Test requires 4 remote_wiseconnect3s devices but only {len(remote_wiseconnect3s)} are available. Skipping test.")

        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants, wifi_access_point,
                                    capture_filename="test_c793729", remote_wiseconnect3s=remote_wiseconnect3s, testcase_no=793729)
        conc_obj.start()
        conc_obj.wait_for_exit()

        socket_thread = SocketThread(remote_wiseconnect3s=remote_wiseconnect3s, remote_socket_factory=remote_socket_factory, protocol=protocol, traffic_type="TX", AP_backend_ip=conc_obj.AP_backend_ip, sta_ip=conc_obj.sta_ips)
        socket_thread.socket_creation_and_data_transfer()

        # Disable NAT after data transfer
        conc_obj.disable_NAT()
        conc_obj.disconnect_stations()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()
        conc_obj.verify_data_transfer_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker()
@wifi_remote_wiseconnect3_marker()
@wifi_remote_wiseconnect3s_marker()
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point', wifi={'ssid': 'Concurent_ap', 'security': SecurityMode.Open, 'channel': 3})
def test_wifi_sdk_udp_tx_outbound_c793731(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, remote_wiseconnect3s, protocol, remote_wiseconnect3, remote_socket_factory):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        # Check if 4 remote_wiseconnect3s are present
        if len(remote_wiseconnect3s) != 4:
            pytest.skip(
                f"Test requires 4 remote_wiseconnect3s devices but only {len(remote_wiseconnect3s)} are available. Skipping test.")

        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants,
                                    wifi_access_point, capture_filename="test_c793731", remote_wiseconnect3s=remote_wiseconnect3s, testcase_no=793731)
        conc_obj.start()
        conc_obj.wait_for_exit()

        socket_thread = SocketThread(remote_wiseconnect3s=remote_wiseconnect3s,
                                     remote_socket_factory=remote_socket_factory, protocol=protocol, traffic_type="TX",
                                     AP_backend_ip=conc_obj.AP_backend_ip, sta_ip=conc_obj.sta_ips)
        socket_thread.socket_creation_and_data_transfer()

        # Disable NAT after data transfer
        conc_obj.disable_NAT()
        conc_obj.disconnect_stations()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()
        conc_obj.verify_data_transfer_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker()
@wifi_remote_wiseconnect3_marker()
@wifi_remote_wiseconnect3s_marker()
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={'ssid': 'Concurent_ap', 'security': SecurityMode.Open, 'channel': 3})
def test_wifi_sdk_tcp_rx_inbound_c793730(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, remote_wiseconnect3s, protocol, remote_wiseconnect3, remote_socket_factory):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        # Check if 4 remote_wiseconnect3s are present
        if len(remote_wiseconnect3s) != 4:
            pytest.skip(
                f"Test requires 4 remote_wiseconnect3s devices but only {len(remote_wiseconnect3s)} are available. Skipping test.")

        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants,
                                    wifi_access_point, capture_filename="test_c793730", remote_wiseconnect3s=remote_wiseconnect3s, testcase_no=793730)
        conc_obj.start()
        conc_obj.wait_for_exit()

        socket_thread = SocketThread(remote_wiseconnect3s=remote_wiseconnect3s,
                                     remote_socket_factory=remote_socket_factory, protocol=protocol, traffic_type="RX",
                                     AP_backend_ip=conc_obj.AP_backend_ip, sta_ip=conc_obj.sta_ips)
        socket_thread.socket_creation_and_data_transfer()

        # Disable NAT after data transfer
        conc_obj.disable_NAT()
        conc_obj.disconnect_stations()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()
        conc_obj.verify_data_transfer_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.skip(reason="Temporary skip due to UDP RX issue")
@wifi_dut_marker()
@wifi_remote_wiseconnect3_marker()
@wifi_remote_wiseconnect3s_marker()
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point', wifi={'ssid': 'Concurent_ap', 'security': SecurityMode.Open, 'channel': 3})
def test_wifi_sdk_udp_rx_inbound_c793732(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, remote_wiseconnect3s, protocol, remote_wiseconnect3, remote_socket_factory):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        # Check if 4 remote_wiseconnect3s are present
        if len(remote_wiseconnect3s) != 4:
            pytest.skip(
                f"Test requires 4 remote_wiseconnect3s devices but only {len(remote_wiseconnect3s)} are available. Skipping test.")

        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants,
                                    wifi_access_point, capture_filename="test_c793732", remote_wiseconnect3s=remote_wiseconnect3s, testcase_no=793732)
        conc_obj.start()
        conc_obj.wait_for_exit()

        socket_thread = SocketThread(remote_wiseconnect3s=remote_wiseconnect3s, remote_socket_factory=remote_socket_factory,
                                     protocol=protocol, traffic_type="RX", AP_backend_ip=conc_obj.AP_backend_ip, sta_ip=conc_obj.sta_ips)
        socket_thread.socket_creation_and_data_transfer()

        # Disable NAT after data transfer
        conc_obj.disable_NAT()
        conc_obj.disconnect_stations()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()
        conc_obj.verify_data_transfer_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker()
@wifi_remote_wiseconnect3_marker()
@wifi_remote_wiseconnect3s_marker()
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={'ssid': 'Concurent_ap', 'security': SecurityMode.Open, 'channel': 3})
def test_wifi_sdk_icmp_conn_outbound_c793733(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, remote_wiseconnect3s, remote_wiseconnect3):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        # Check if 4 remote_wiseconnect3s are present
        if len(remote_wiseconnect3s) != 4:
            pytest.skip(
                f"Test requires 4 remote_wiseconnect3s devices but only {len(remote_wiseconnect3s)} are available. Skipping test.")

        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants,
                                    wifi_access_point, capture_filename="test_c793733", remote_wiseconnect3s=remote_wiseconnect3s, testcase_no=793733)
        conc_obj.start()
        conc_obj.wait_for_exit()

        # Disable NAT after data transfer
        conc_obj.disable_NAT()
        conc_obj.disconnect_stations()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker()
@wifi_remote_wiseconnect3_marker()
@wifi_remote_wiseconnect3s_marker()
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={'ssid': 'Concurent_ap', 'security': SecurityMode.Open, 'channel': 3})
def test_wifi_sdk_icmp_conn_outbound_310_bytes_c793739(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, remote_wiseconnect3s, remote_wiseconnect3):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        # Check if 4 remote_wiseconnect3s are present
        if len(remote_wiseconnect3s) != 4:
            pytest.skip(
                f"Test requires 4 remote_wiseconnect3s devices but only {len(remote_wiseconnect3s)} are available. Skipping test.")

        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants,
                                    wifi_access_point, testcase_no=793739, capture_filename="test_c793739", remote_wiseconnect3s=remote_wiseconnect3s)
        conc_obj.start()
        conc_obj.wait_for_exit()

        # Disable NAT after data transfer
        conc_obj.disable_NAT()
        conc_obj.disconnect_stations()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker()
@wifi_remote_wiseconnect3_marker()
@wifi_remote_wiseconnect3s_marker()
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={'ssid': 'Concurent_ap', 'security': SecurityMode.Open, 'channel': 3})
def test_wifi_sdk_icmp_conn_inbound_c793734(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, remote_wiseconnect3s, remote_wiseconnect3):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        # Check if 4 remote_wiseconnect3s are present
        if len(remote_wiseconnect3s) != 4:
            pytest.skip(
                f"Test requires 4 remote_wiseconnect3s devices but only {len(remote_wiseconnect3s)} are available. Skipping test.")

        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants,
                                    wifi_access_point, testcase_no=793734,
                                    capture_filename="test_c793734", remote_wiseconnect3s=remote_wiseconnect3s)
        conc_obj.start()
        conc_obj.wait_for_exit()

        # Disable NAT after data transfer
        conc_obj.disable_NAT()
        conc_obj.disconnect_stations()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
        wifi=
        {
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                                  | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.HTTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                                       | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(4),
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT
                                      | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                                   | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "security": SecurityMode.Open, "ssid": "SILABS_AP_MODE", "channel": 3
    },
)
@pytest.mark.config(
    "remote_wiseconnect3",
        wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                                  | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.HTTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                                       | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(4),
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT
                                      | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                                   | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    }
)
@pytest.mark.config(
    "remote_wiseconnect3s",
        wifi={
        0:{
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                                  | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.HTTPClient,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                                       | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(4),
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT
                                      | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                                   | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
            "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
            "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
            "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        },

        1:{
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                                  | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.HTTPClient,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                                       | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(4),
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT
                                      | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                                   | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
            "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
            "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
            "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        },

        2:{
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                                  | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.HTTPClient,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                                       | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(4),
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT
                                      | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                                   | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
            "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
            "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
            "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        }
    }
)
@pytest.mark.config('wifi_access_point', wifi={'ssid': 'Concurent_ap', 'security': SecurityMode.Open, 'channel': 3})
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={'ssid': 'Concurent_ap', 'security': SecurityMode.Open, 'channel': 3})
def test_wifi_sdk_mqtt_client_with_nat_c793737(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, remote_wiseconnect3, aws_iot_clients, remote_wiseconnect3s):
    """ To verify the DNS client functionality in concurrent mode with NAT ENABLED """
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        # Check if 4 remote_wiseconnect3s and 4 aws_iot_clients are present
        if len(remote_wiseconnect3s) != 4 and len(aws_iot_clients) !=4:
            pytest.skip(
                f"Test requires 4 remote_wiseconnect3s devices and 4 aws_iot_clients but only {len(remote_wiseconnect3s)} and {len(aws_iot_clients)} are available. Skipping test.")

        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants,
                                    wifi_access_point, capture_filename="test_c793737", remote_wiseconnect3s=remote_wiseconnect3s)
        conc_obj.start()
        conc_obj.wait_for_exit()

        aws_obj_thread = []
        topic = ["topic_C793737_1", "topic_C793737_2", "topic_C793737_3", "topic_C793737_4"]
        client_id = ["client_C793737_1", "client_C793737_2", "client_C793737_3", "client_C793737_4"]
        for i in range(len(remote_wiseconnect3s)):
            aws_obj = AWSConnection(remote_wiseconnect3=remote_wiseconnect3s[i], aws_iot_client=aws_iot_clients[i], topic=topic[i], client_id = client_id[i])
            aws_obj_thread.append(aws_obj)

        for thread in aws_obj_thread:
            thread.start()

        for thread in aws_obj_thread:
            thread.wait_for_exit()

        # Disable NAT after data transfer
        conc_obj.disable_NAT()
        conc_obj.disconnect_stations()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker()
@wifi_remote_wiseconnect3_marker()
@wifi_remote_wiseconnect3s_marker()
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={'ssid': 'Concurent_ap', 'security': SecurityMode.Open, 'channel': 3})
def test_wifi_sdk_dns_client_functionality_NAT_c793738(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, remote_wiseconnect3s, remote_wiseconnect3):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        # Check if 4 remote_wiseconnect3s are present
        if len(remote_wiseconnect3s) != 4:
            pytest.skip(
                f"Test requires 4 remote_wiseconnect3s devices but only {len(remote_wiseconnect3s)} are available. Skipping test.")

        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants,
                                    wifi_access_point, capture_filename="test_c793738", remote_wiseconnect3s=remote_wiseconnect3s, testcase_no=793738)
        conc_obj.start()
        conc_obj.wait_for_exit()

        # Disable NAT after data transfer
        conc_obj.disable_NAT()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.skip(reason="Temporary skip due to server issues")
@wifi_dut_marker()
@wifi_remote_wiseconnect3_marker()
@wifi_remote_wiseconnect3s_marker()
@pytest.mark.config('wifi_access_point', wifi={'ssid': 'Concurent_ap', 'security': SecurityMode.Open, 'channel': 3})
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.config('wifi_access_point', wifi={'ssid': 'Concurent_ap', 'security': SecurityMode.Open, 'channel': 3})
def test_wifi_sdk_http_client_functionality_NAT_c793736(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, http_client, http_servers, index_path, remote_wiseconnect3, remote_wiseconnect3s):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        # Check if 4 remote_wiseconnect3s are present
        if len(remote_wiseconnect3s) != 4:
            pytest.skip(
                f"Test requires 4 remote_wiseconnect3s devices but only {len(remote_wiseconnect3s)} are available. Skipping test.")

        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants,
                                    wifi_access_point, capture_filename="test_c793736", remote_wiseconnect3s=remote_wiseconnect3s)
        conc_obj.start()
        conc_obj.wait_for_exit()

        http_obj_thread = []
        port = [8080, 8081, 8082, 8083]

        for i in range(len(remote_wiseconnect3s)):
            http_obj = HttpConnection(http_client=http_client, http_server=http_servers[i], remote_wiseconnect3=remote_wiseconnect3s[i], index_path=index_path, station_id=i+1, port=port[i])
            http_obj_thread.append(http_obj)

        for thread in http_obj_thread:
            thread.start()

        for thread in http_obj_thread:
            thread.wait_for_exit()

        # Disable NAT after data transfer
        conc_obj.disable_NAT()
        conc_obj.disconnect_stations()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()