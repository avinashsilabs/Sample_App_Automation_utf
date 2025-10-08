import re
import uuid
from datetime import datetime
import time
from typing import Dict
from random import randint
from threading import Thread
from utf.interfaces.socket.fixtures import remote_socket_factory
from utf.utils.time_measurer import TimeMeasurer
from utf.utf_config import UtfConfig
from utf.interfaces.wifi import SecurityMode
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
import pytest as pytest
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf import UtfDatabaseProperties
from utf_wifi_zephyr.tests.sl_status import SLStatus
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
from AWSIoTPythonSDK.core.protocol.internal.clients import ClientStatus
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.cloud_connectivity.test_aws_iot_wifi_sqa_sdk import AwsConnection


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

        for i in range(5):
            logger().info(f"\n ****** Sending data from STA to AP_Backend: iteration {i + 1} ******* \n")
            self.remote_wiseconnect3.interfaces.wifi.bsdSocketSend(socket_fd=self.socket_id, data=tx_data)
            time.sleep(2)
            rx_data = self.remote_socket.recv_data_tcp(data_size=len(tx_data))

            assert tx_data == rx_data, f"Data Mismatch: Sent data: {tx_data}, Received data: {rx_data}"
            logger().info(f"Data packet received iteration {i+1}")
            time.sleep(10)

        logger().info(f"Data transfer from SSTA{i + 1} to AP_Backend is successful")

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

        for i in range(5):
            logger().info(f"\n ****** Sending data from AP_Backend to STA: iteration {i + 1} ******* \n")
            self.remote_socket.send_data_tcp(tx_data, True)
            time.sleep(2)
            rx_data = self.remote_wiseconnect3.interfaces.wifi.bsdSocketReceive(socket_fd=self.socket_id)

            assert tx_data == rx_data, f"Data Mismatch: Sent data: {tx_data}, Received data: {rx_data}"
            logger().info(f"Data packet received iteration {i+1}")
            time.sleep(10)

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
        for i in range(5):
            logger().info(f"\n ****** Sending data from STA to AP_Backend: iteration {i + 1} ******* \n")
            send_bytes = self.remote_wiseconnect3.interfaces.wifi.bsdSocketSendTo(socket_fd=self.socket_id,
                                                                                  data=tx_data,
                                                                                  ip_addr=self.AP_backend_ip,
                                                                                  ip_len=4, port=self.local_port)

            rx_data, client_addr = self.remote_socket.recv_data_udp(data_size=len(tx_data))
            logger().info(f"data received : {rx_data}, {client_addr[0]}, {client_addr[1]}")
            assert tx_data == rx_data, f"Data Mismatch: Sent data: {tx_data}, Received data: {rx_data}"
            logger().info(f"Data packet received iteration {i + 1}")
            time.sleep(10)

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
        for i in range(5):
            logger().info(f"\n ****** Sending data from AP_Backend to STA: iteration {i + 1} ******* \n")
            self.remote_socket.send_data_udp(tx_buffer=tx_data, server_ip=client_addr[0], port=client_addr[1])
            time.sleep(2)
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
        self.logger.info(f"\n ********* Open the client sockets on the stations and server socket at AP Backend ********* \n")

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
        self.channel = "1"
        self.ssid = "SILABS_AP_MODE"
        self.security = "open"
        self.password = "None"
        self.dtim_count = "1"
        self.beacon_interval = "100"
        self.ht_caps = ht_caps
        self.AP_backend_ip = None
        self.ping_count = 2
        self.sta_ips = ["192.168.100.77", "192.168.100.78", "192.168.100.79", "192.168.100.80"]

    def verify_icmp_connection(self, ping_size=64):
        for i in range(0, len(self.remote_wiseconnect3s)):
            self.logger.info(f"********* Start Ping from station {i+1} to AP backend ip: {self.AP_backend_ip} *********")
            self.remote_wiseconnect3s[i].interfaces.sapi.ping(server_ip=self.AP_backend_ip,
                                                          num_ping_attempts=self.ping_count,
                                                          ping_timeout=10, ip_version='ipv4', ping_size=ping_size)

            if self.testcase_no == 793739:
                self.logger.info(f"********* Start Ping from station {i + 1} to AP backend ip: {self.AP_backend_ip} with ping size more than 300 bytes *********")
                self.remote_wiseconnect3s[i].interfaces.sapi.ping(server_ip=self.AP_backend_ip,
                                                                  num_ping_attempts=self.ping_count,
                                                                  ping_timeout=10, ip_version='ipv4',
                                                                  ping_size=310, expected_status=SLStatus.SL_STATUS_SI91X_ICMP_DATA_SIZE_EXCEED_MAX_LIMIT)
                self.logger.info(f"Expected behaviour: Ping more than 300 bytes is failed from STA{i+1} to AP backend")

            if self.testcase_no == 793734:
                self.logger.info(f"********* ICMP connection with inbound traffic *********")
                self.logger.info(f"\n ********* Start Ping from AP backend ip: {self.AP_backend_ip} to station {i+1} ********* \n")
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
            self.remote_wiseconnect3s[i].interfaces.sapi.scan(channel=1, ssid=self.ssid)
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

        self.logger.info(f"********* start the NAT ENABLE *********")
        self.wifi_dut.interfaces.wifi.nat_enable()
        self.AP_backend_ip = self.wifi_client.interfaces.wifi.get_ip_address()  # AP backend
        self.logger.info(f"AP backend IP address: {self.AP_backend_ip}")

        self.logger.info(f"********* Start Ping from all STAs to AP backend  *********")
        self.verify_icmp_connection()


    def concurrent_sniffer_validation(self):

        self.sl_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer,
                                                    self.dut_addr['dut_mac_address'],
                                                    self.ap_mac_address, self.sniffer_filter,
                                                    power_save=False)
        if self.testcase_no != 793739 and self.testcase_no != 793734:
            self.logger.info(f"********* Sniffer validation for Ping packets *********")
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

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
            "oper_mode": Si91xOperatingMode.ConcurrentMode,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(4),
            "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
            "security": SecurityMode.Open, "ssid": "SILABS_AP_MODE", "channel": 1
        }) ,

    pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(
                4),
            "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        }
    ) ,

    pytest.mark.config(
        "remote_wiseconnect3s",
        wifi={
            0:{
                "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
                "oper_mode": Si91xOperatingMode.WiFiClient,
                "coex_mode": Si91xCoexMode.WLANOnly,
                "features": Si91xFeatureBitMap.WPSSupportDisabled,
                "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping,
                "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT,
                "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(
                    4),
                "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
            },

            1:{
                "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
                "oper_mode": Si91xOperatingMode.WiFiClient,
                "coex_mode": Si91xCoexMode.WLANOnly,
                "features": Si91xFeatureBitMap.WPSSupportDisabled,
                "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping,
                "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT,
                "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(
                    4),
                "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
            },

            2:{
                "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
                "oper_mode": Si91xOperatingMode.WiFiClient,
                "coex_mode": Si91xCoexMode.WLANOnly,
                "features": Si91xFeatureBitMap.WPSSupportDisabled,
                "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping,
                "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_NAT_SUPPORT,
                "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.CUSTOM_FEAT_MAX_NUM_OF_CLIENTS(
                    4),
                "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
            }
        }) ,

    pytest.mark.config(
        'wifi_access_point',
        wifi={
            'ssid': 'Concurent_ap',
            'security': SecurityMode.Open,
            'channel': 1,
        }
    )
]


@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_tcp_tx_outbound_c793729(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, remote_wiseconnect3s, protocol, remote_wiseconnect3, remote_socket_factory):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants, wifi_access_point,
                                    capture_filename="test_c793729", remote_wiseconnect3s=remote_wiseconnect3s)
        conc_obj.start()
        conc_obj.wait_for_exit()

        socket_thread = SocketThread(remote_wiseconnect3s=remote_wiseconnect3s, remote_socket_factory=remote_socket_factory, protocol=protocol, traffic_type="TX", AP_backend_ip=conc_obj.AP_backend_ip, sta_ip=conc_obj.sta_ips)
        socket_thread.socket_creation_and_data_transfer()

        # Disable NAT after data transfer
        conc_obj.disable_NAT()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_sdk_udp_tx_outbound_c793731(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, remote_wiseconnect3s, protocol, remote_wiseconnect3, remote_socket_factory):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants,
                                    wifi_access_point, capture_filename="test_c793731", remote_wiseconnect3s=remote_wiseconnect3s)
        conc_obj.start()
        conc_obj.wait_for_exit()

        socket_thread = SocketThread(remote_wiseconnect3s=remote_wiseconnect3s,
                                     remote_socket_factory=remote_socket_factory, protocol=protocol, traffic_type="TX",
                                     AP_backend_ip=conc_obj.AP_backend_ip, sta_ip=conc_obj.sta_ips)
        socket_thread.socket_creation_and_data_transfer()

        # Disable NAT after data transfer
        conc_obj.disable_NAT()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_tcp_rx_inbound_c793730(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, remote_wiseconnect3s, protocol, remote_wiseconnect3, remote_socket_factory):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants,
                                    wifi_access_point, capture_filename="test_c793730", remote_wiseconnect3s=remote_wiseconnect3s)
        conc_obj.start()
        conc_obj.wait_for_exit()

        socket_thread = SocketThread(remote_wiseconnect3s=remote_wiseconnect3s,
                                     remote_socket_factory=remote_socket_factory, protocol=protocol, traffic_type="RX",
                                     AP_backend_ip=conc_obj.AP_backend_ip, sta_ip=conc_obj.sta_ips)
        socket_thread.socket_creation_and_data_transfer()

        # Disable NAT after data transfer
        conc_obj.disable_NAT()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_sdk_udp_rx_inbound_c793732(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, remote_wiseconnect3s, protocol, remote_wiseconnect3, remote_socket_factory):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants,
                                    wifi_access_point, capture_filename="test_c793732", remote_wiseconnect3s=remote_wiseconnect3s)
        conc_obj.start()
        conc_obj.wait_for_exit()

        socket_thread = SocketThread(remote_wiseconnect3s=remote_wiseconnect3s, remote_socket_factory=remote_socket_factory,
                                     protocol=protocol, traffic_type="RX", AP_backend_ip=conc_obj.AP_backend_ip, sta_ip=conc_obj.sta_ips)
        socket_thread.socket_creation_and_data_transfer()

        # Disable NAT after data transfer
        conc_obj.disable_NAT()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        conc_obj.concurrent_sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
def test_wifi_sdk_icmp_conn_outbound_c793733(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, remote_wiseconnect3s, remote_wiseconnect3):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants,
                                    wifi_access_point, capture_filename="test_c793733", remote_wiseconnect3s=remote_wiseconnect3s)
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

@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
def test_wifi_sdk_icmp_conn_outbound_310_bytes_c793739(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, remote_wiseconnect3s, remote_wiseconnect3):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants,
                                    wifi_access_point, testcase_no=793739, capture_filename="test_c793739", remote_wiseconnect3s=remote_wiseconnect3s)
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


@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_1", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_2", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3_3", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_dut", wifi="init")
def test_wifi_sdk_icmp_conn_inbound_c793734(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, sniffer_filter, utf_constants, sl_collections, remote_wiseconnect3s, remote_wiseconnect3):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        remote_wiseconnect3s.insert(0, remote_wiseconnect3)
        conc_obj = ConcurrentThread(wifi_dut, sl_collections, wifi_sniffer, sniffer_filter, wifi_client, utf_constants,
                                    wifi_access_point, testcase_no=793734,
                                    capture_filename="test_c793734", remote_wiseconnect3s=remote_wiseconnect3s)
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
