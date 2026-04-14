import threading
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xExtCustomFeatureBitMap, Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap
from utf.interfaces.wifi import WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.stopwatch import Stopwatch
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.defaults import defaults
import string
import random
from random import randint
from utf.utils.iperf.iperf_utils import ping

# from utf_wifi.utf_core.src.utf.interfaces.wifi.fixtures import remote_wiseconnect3


def logger():
    return get_logger(__name__)


""" Test Steps:
        1. Configure the DUT in Wlan & coex mode for 2.4Ghz.
        2. Initiate the Scan from DUT.
        3. Initiate the connection with third party Access Point.
        4. Run the traffic TCP/UDP TX & RX.
        5. Verify the throughput of values TCP/UDP TX & RX values.  

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Benazeer K 
"""


class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi connectivity ,powersave ,data transfer"""

    def __init__(self, wifi_sniffer=None, wifi_dut=None, \
                 wifi_access_point=None, wifi_client=None, \
                 net_perf_client=None, protocol=None, iteration_count=None, sl_collections=None, ping_count=None,
                 sniffer_filter=None, data_transfer=None, traffic_type=None, testcase=None, bt_dut=None,
                 test_case_no=None, ble_client=None, ble_conn=None, utf_constants=None, mode=None, ble_dut=None,
                 ble_data_transfer=None, ssl_server=None, ssl_data_transfer=None, ble_client_address=None,
                 remote_wiseconnect3=None, net_perf_clients=None, ble_adv_128=None, setting_phy=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.testcase = testcase
        self.wifi_client = wifi_client
        self.iteration_count = iteration_count
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.data_transfer = data_transfer
        self.ssl_data_transfer = ssl_data_transfer
        self.traffic_type = traffic_type
        self.test_case_no = test_case_no
        self.bt_dut = bt_dut
        self.ble_client = ble_client
        self.ble_conn = ble_conn
        self.utf_constants = utf_constants
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.dut_addr = None
        self.mode = mode
        self.setting_phy = setting_phy
        self.ble_adv_128 = ble_adv_128
        self.ble_client_address = ble_client_address
        self.ble_data_transfer = ble_data_transfer
        self.ssl_server = ssl_server
        self.net_perf_clients = net_perf_clients
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.ble_dut = ble_dut

    def run(self):
        if self.test_case_no == 20740 or self.test_case_no == 20750:
            transfer_type = 1
            protocol = 6
            throughput_type = 1
            size = 1460

        if self.test_case_no == 20741 or self.test_case_no == 20751:
            transfer_type = 1
            protocol = 6
            throughput_type = 3
            size = 1460

        if self.test_case_no == 20738 or self.test_case_no == 20748:
            transfer_type = 2
            protocol = 17
            throughput_type = 2
            size = 1470

        if self.test_case_no == 20739 or self.test_case_no == 20749:
            transfer_type = 2
            protocol = 17
            throughput_type = 4
            size = 1470

        logger().info("starting the sniffer again")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

        self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                 wifi_access_point=self.wifi_access_point,
                                                                 associated=self.wifi_dut.interfaces.wifi.associated,
                                                                 retry_count=3, ping_after_power_save=False,
                                                                 ping_count=self.ping_count, power_save=False)
        self.remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        time.sleep(2)
        self.remote_wiseconnect3.interfaces.sapi.join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                                      security="wpa2",
                                                      passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                                      channel=self.wifi_access_point.interfaces.wifi.channel, timeout=60)
        time.sleep(2)
        ip_config = self.remote_wiseconnect3.interfaces.sapi.start_ip(ip_version='ipv4', timeout=60)
        time.sleep(2)
        sec_device_ip = self.remote_wiseconnect3.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f'Secondary DUT IP Address: {sec_device_ip}')
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.switch_host_frequency()
        time.sleep(2)
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        time.sleep(2)
        self.remote_wiseconnect3.interfaces.wifi.switch_host_frequency()

        if self.data_transfer:
            if self.traffic_type == "TX":
                self.iteration_count = self.iteration_count
                for i in range(0, self.iteration_count):
                    # starting iperf
                    self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=self.dut_addr['device_ip'],
                                                                         protocol=self.protocol)
                    self.net_perf_client.interfaces.net_perf.start()
                    logger().info("sending data from DUT")
                    timeout = 40
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                        local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        size=size, ttl=15, throughput_type=throughput_type, qos=0,
                                                        timeout=timeout+2)
                    # # get and print throughput
                    tp = self.net_perf_client.interfaces.net_perf.process_output()
                    assert tp is not None, "Throughput not found"
                    logger().info("data transfer successful")
                    time.sleep(5)
            if self.traffic_type == "RX":
                logger().info("#######=========>>>>>>>>>in RX")
                self.iteration_count = self.iteration_count
                for i in range(0, self.iteration_count):
                    # Iperf Client Started
                    if self.protocol == "UDP":
                        bandwidth = "68M"
                        self.net_perf_clients[0].interfaces.net_perf.init_client(host_ip=host_ip,
                                                                             device_ip=self.dut_addr['device_ip'],
                                                                            protocol=self.protocol, bandwidth=bandwidth)
                        logger().info(f"***** start listening server-1  ******")
                        self.net_perf_clients[0].interfaces.net_perf.start()
                        time.sleep(2)
                        self.net_perf_clients[1].interfaces.net_perf.init_client(host_ip=host_ip,
                                                                                 device_ip=sec_device_ip,
                                                                                 protocol=self.protocol,
                                                                                 bandwidth=bandwidth)
                        time.sleep(2)
                        logger().info(f"***** start listening server-2 ******")
                        self.net_perf_clients[1].interfaces.net_perf.start()
                        time.sleep(2)
                        iperf_exceptions = [None, None]

                        def run_iperf_dut():
                            try:
                                logger().info("receiving data from server-1")
                                timeout = 40
                                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type,
                                                                    protocol=protocol,
                                                                    local_port=self.net_perf_clients[
                                                                        0].interfaces.net_perf.client_port,
                                                                    local_ip=self.dut_addr['device_ip'],
                                                                    remote_ip=host_ip,
                                                                    remote_port=self.net_perf_clients[
                                                                        0].interfaces.net_perf.client_port,
                                                                    size=size, ttl=30, throughput_type=throughput_type,
                                                                    qos=0,
                                                                    async_socket=1, timeout=timeout + 2)
                                logger().info("data received is successful ####=====>>>>>> DUT-1")
                                time.sleep(3)
                            except Exception as e:
                                iperf_exceptions[0] = e

                        def run_iperf_remote():
                            try:
                                logger().info("receiving data from server-2")
                                timeout = 40
                                self.remote_wiseconnect3.interfaces.wifi.iperf(family=2, transfer_type=transfer_type,
                                                                               protocol=protocol,
                                                                               local_port=1236,
                                                                               local_ip=sec_device_ip,
                                                                               remote_ip=host_ip,
                                                                               remote_port=1236,
                                                                               size=size, ttl=30,
                                                                               throughput_type=throughput_type, qos=0,
                                                                               async_socket=1, timeout=timeout + 2)
                                time.sleep(2)
                                logger().info("data received is successful ####====>>>> DUT-2")
                                time.sleep(3)

                            except Exception as e:
                                iperf_exceptions[1] = e

                        iperf_thread_dut = threading.Thread(target=run_iperf_dut)
                        iperf_thread_remote = threading.Thread(target=run_iperf_remote)
                        iperf_thread_dut.start()
                        iperf_thread_remote.start()
                        iperf_thread_dut.join()
                        iperf_thread_remote.join()

                    elif self.protocol == "TCP":
                        def run_tcp_dut():
                            try:
                                logger().info("receiving data from remote server-1")
                                self.net_perf_clients[0].interfaces.net_perf.init_client(host_ip=host_ip,
                                                                                         device_ip=self.dut_addr[
                                                                                             'device_ip'],
                                                                                         protocol=self.protocol)
                                time.sleep(2)

                                def start_client():
                                    time.sleep(1)
                                    logger().info(f"***** start listening  ******")
                                    self.net_perf_clients[0].interfaces.net_perf.start()
                                    time.sleep(3)

                                client_thread1 = Thread(target=start_client, args=(), )
                                client_thread1.start()

                                # open socket and listen for data
                                timeout = 40
                                self.wifi_dut.interfaces.wifi.set_socket_config()
                                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type,
                                                                    protocol=protocol,
                                                                    local_port=self.net_perf_clients[
                                                                        0].interfaces.net_perf.client_port,
                                                                    local_ip=self.dut_addr['device_ip'],
                                                                    remote_ip=host_ip,
                                                                    remote_port=self.net_perf_clients[
                                                                        0].interfaces.net_perf.client_port,
                                                                    size=size, ttl=30, throughput_type=throughput_type,
                                                                    qos=0,
                                                                    async_socket=1, timeout=timeout + 2)
                                time.sleep(2)
                                client_thread1.join()
                                logger().info("data received is successful")

                                time.sleep(2)
                            except Exception as e:
                                iperf_exceptions[0] = e

                        def run_tcp_remote():
                            try:
                                logger().info("receiving data from remote server-2")
                                time.sleep(3)
                                self.net_perf_clients[1].interfaces.net_perf.init_client(host_ip=host_ip,
                                                                                         device_ip=sec_device_ip,
                                                                                         protocol=self.protocol)

                                def start_client1():
                                    time.sleep(3)
                                    logger().info(f"Starting the secondary iperf server#####======>>>>>>")
                                    self.net_perf_clients[1].interfaces.net_perf.start()

                                client_thread1 = Thread(target=start_client1, args=(), )
                                client_thread1.start()

                                # open socket and listen for data
                                timeout = 40
                                self.remote_wiseconnect3.interfaces.wifi.set_socket_config()
                                self.remote_wiseconnect3.interfaces.wifi.iperf(family=2, transfer_type=transfer_type,
                                                                               protocol=protocol,
                                                                               # local_port=self.net_perf_clients[
                                                                               #     0].interfaces.net_perf.client_port,
                                                                               local_port=4321,
                                                                               local_ip=sec_device_ip,
                                                                               remote_ip=host_ip,
                                                                               # remote_port=self.net_perf_clients[
                                                                               #     0].interfaces.net_perf.client_port,
                                                                               remote_port=4321,
                                                                               size=size, ttl=30,
                                                                               throughput_type=throughput_type, qos=0,
                                                                               async_socket=1, timeout=timeout + 2)
                                client_thread1.join()
                                logger().info("data received is successful")
                                time.sleep(3)

                            except Exception as e:
                                iperf_exceptions[1] = e

                        iperf_thread_dut = threading.Thread(target=run_tcp_dut)
                        iperf_thread_remote = threading.Thread(target=run_tcp_remote)
                        iperf_thread_dut.start()
                        iperf_thread_remote.start()
                        iperf_thread_dut.join()
                        iperf_thread_remote.join()

                        # self.net_perf_clients[0].interfaces.net_perf.init_client(host_ip=host_ip,
                        #                                                          device_ip=self.dut_addr['device_ip'],
                        #                                                          protocol=self.protocol)
                        # time.sleep(2)
                        # def start_client():
                        #     time.sleep(1)
                        #     logger().info(f"***** start listening  ******")
                        #     self.net_perf_clients[0].interfaces.net_perf.start()
                        #     time.sleep(3)
                        #
                        # client_thread1 = Thread(target=start_client, args=(), )
                        # client_thread1.start()
                        #
                        # # open socket and listen for data
                        # timeout = 40
                        # self.wifi_dut.interfaces.wifi.set_socket_config()
                        # self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                        #                                     local_port=self.net_perf_clients[
                        #                                         0].interfaces.net_perf.client_port,
                        #                                     local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                        #                                     remote_port=self.net_perf_clients[
                        #                                         0].interfaces.net_perf.client_port,
                        #                                     size=size, ttl=30, throughput_type=throughput_type, qos=0,
                        #                                     async_socket=1, timeout=timeout + 2)
                        # time.sleep(2)
                        # client_thread1.join()
                        # logger().info("data received is successful")
                        # time.sleep(3)
                        # self.net_perf_clients[1].interfaces.net_perf.init_client(host_ip=host_ip,
                        #                                                          # device_ip=self.dut_addr['device_ip'],
                        #                                                          device_ip=sec_device_ip,
                        #                                                          protocol=self.protocol)
                        # def start_client1():
                        #     time.sleep(3)
                        #     logger().info(f"Starting the secondary iperf server#####======>>>>>>")
                        #     self.net_perf_clients[1].interfaces.net_perf.start()
                        #
                        # client_thread1 = Thread(target=start_client1, args=(), )
                        # client_thread1.start()
                        #
                        # # open socket and listen for data
                        # timeout = 40
                        # self.remote_wiseconnect3.interfaces.wifi.set_socket_config()
                        # self.remote_wiseconnect3.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                        #                                     # local_port=self.net_perf_clients[
                        #                                     #     0].interfaces.net_perf.client_port,
                        #                                    local_port=4321,
                        #                                     local_ip=sec_device_ip, remote_ip=host_ip,
                        #                                     # remote_port=self.net_perf_clients[
                        #                                     #     0].interfaces.net_perf.client_port,
                        #                                    remote_port=4321,
                        #                                     size=size, ttl=30, throughput_type=throughput_type, qos=0,
                        #                                     async_socket=1, timeout=timeout + 2)
                        # client_thread1.join()
                        # logger().info("data received is successful")
                        # time.sleep(3)

        if self.ssl_data_transfer:
            if self.traffic_type == "TX":
                buffer_length = 1370
                port1 = self.ssl_server.interfaces.ssl.config['device_port1']
                # Open ssl client socket in the DUT
                sock = self.wifi_dut.interfaces.wifi.socket()
                assert sock == 0, "Socket id received is wrong. expected is 0"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP")
                local_port = randint(5001, 60000)
                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=self.dut_addr['device_ip'], server_port=local_port,
                                                   timeout=15)
                self.ssl_server.interfaces.ssl.start_server()
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                time.sleep(3)
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                               server_port=port1)
                pkt_count = 50000
                time.sleep(1)
                server_socket_no = 1
                if self.ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                    self.ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
                result = self.wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
                logger().info(f"Number of bytes sent by dut {result}")
                bytes_sent = result
                bytes_received = self.ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
                logger().info(
                    f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
                self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                logger().info("Successfully closed opened socket in the DUT")
                self.ssl_server.interfaces.ssl.stop_server()
                time.sleep(5)
            if self.traffic_type == "RX":
                buffer_length = 1370
                port1 = self.ssl_server.interfaces.ssl.config['device_port1']
                port2 = self.ssl_server.interfaces.ssl.config['device_port2']
                # self.ssl_server.interfaces.ssl.start_server()
                # server_ip = self.ssl_server.interfaces.ssl.server_ip
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.set_socket_config()
                time.sleep(2)
                self.remote_wiseconnect3.interfaces.sapi.set_socket_config()
                # Open ssl client socket in the DUT
                time.sleep(2)
                sock = self.wifi_dut.interfaces.wifi.async_sdk_socket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                                      protocol="IPPROTO_TCP")
                assert sock == 0, "Socket id received is wrong. expected is 0"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")

                sock1 = self.remote_wiseconnect3.interfaces.sapi.async_sdk_socket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                                      protocol="IPPROTO_TCP")
                assert sock1 == 0, "Socket id received is wrong. expected is 0"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock1} using rsi_setsockopt API")

                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP")
                self.remote_wiseconnect3.interfaces.sapi.bsdSetSocketOpt(sock, option_name="TCP_ULP")
                local_port = randint(5001, 60000)
                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=self.dut_addr['device_ip'], server_port=local_port,
                                                   timeout=15)
                time.sleep(2)
                local_port1 = randint(5002, 60000)
                self.remote_wiseconnect3.interfaces.sapi.bind(socket_fd=sock, device_ip=sec_device_ip,
                                                   server_port=local_port1,
                                                   timeout=15)
                self.ssl_server.interfaces.ssl.start_server()
                time.sleep(2)
                self.ssl_server.interfaces.ssl.start_server(port2)
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                time.sleep(3)
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                               server_port=port1)
                self.remote_wiseconnect3.interfaces.sapi.bsdSocketConnect(socket_fd=sock1, server_ip=server_ip,
                                                               server_port=port2)
                socket_no = 1
                socket_num = 2
                pkt_count = 50000
                duration = 60

                iperf_exceptions = [None, None]

                def run_ssl_dut():
                    try:
                        logger().info("sending data from remote server-1")
                        self.ssl_server.interfaces.ssl.send_data(socket_no, pkt_count, msg_length=buffer_length,
                                                                 duration=duration)
                        time.sleep(2)
                    except Exception as e:
                        iperf_exceptions[0] = e

                def run_ssl_remote():
                    try:
                        logger().info("sending data from remote server-2")
                        self.ssl_server.interfaces.ssl.send_data(socket_num, pkt_count, msg_length=buffer_length,
                                                                 duration=duration)
                    except Exception as e:
                        iperf_exceptions[1] = e

                iperf_thread_dut = threading.Thread(target=run_ssl_dut)
                iperf_thread_remote = threading.Thread(target=run_ssl_remote)
                iperf_thread_dut.start()
                iperf_thread_remote.start()
                iperf_thread_dut.join()
                iperf_thread_remote.join()
                time.sleep(80)
                bytes_sent = self.ssl_server.interfaces.ssl.data_send_stats(socket_no)
                result = self.wifi_dut.interfaces.wifi.get_socket_rx_stats(sock, no_of_pkts="pkt_count", ttl=30)
                logger().info(f"*** result of rx_stats in wifidut {result}")
                bytes_received = int(result)
                logger().info(f"bytes sent by remote peer -> {bytes_sent}")
                logger().info(f"bytes received on socket {sock} -> {bytes_received}")
                logger().info(f"SSL rx throughput ->  {((bytes_received * 8) / (1000 * 1000 * duration))} Mbps")
                time.sleep(2)

                bytes_sent = self.ssl_server.interfaces.ssl.data_send_stats(socket_num)
                result = self.remote_wiseconnect3.interfaces.sapi.get_socket_rx_stats(sock1, no_of_pkts="pkt_count", ttl=30)
                logger().info(f"*** result of rx_stats in wifidut {result}")
                bytes_received = int(result)
                logger().info(f"bytes sent by remote peer -> {bytes_sent}")
                logger().info(f"bytes received on socket {sock} -> {bytes_received}")
                logger().info(f"SSL rx throughput ->  {((bytes_received * 8) / (1000 * 1000 * duration))} Mbps")
                time.sleep(2)

                self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                self.remote_wiseconnect3.interfaces.sapi.bsdSockClose(socket_fd=sock1)
                logger().info("Successfully closed opened socket in the DUT")
                self.ssl_server.interfaces.ssl.stop_server()
                time.sleep(5)

        self.wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        self.wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}
    }
)
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}
    }
)
@pytest.mark.test_src_map_id('C401890')
def test_wlan_mu_mimo_tcp_rx_C401890(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, protocol,
                                                net_perf_clients, request, utf_constants, sl_collections,
                                                remote_wiseconnect3):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_clients=net_perf_clients,
                              protocol=protocol, sl_collections=sl_collections, remote_wiseconnect3=remote_wiseconnect3,
                              ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=20741,
                              iteration_count=iter_count)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}
    }
)
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}
    }
)
@pytest.mark.test_src_map_id('C401891')
def test_wlan_mu_mimo_udp_rx_C401891(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, sl_collections,
                                                net_perf_clients, protocol, utf_constants, request, remote_wiseconnect3):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_clients=net_perf_clients,
                              protocol=protocol, sl_collections=sl_collections, remote_wiseconnect3=remote_wiseconnect3,
                              ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=20739,
                              iteration_count=iter_count, ble_adv_128=True)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}
    }
)
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}
    }
)
@pytest.mark.test_src_map_id('C401892')
def test_wlan_mu_mimo_rtt_tcp_rx_C401892(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                                    net_perf_clients, protocol, utf_constants, request, sl_collections,
                                                    remote_wiseconnect3):
    logger().info("Enabling the **** RTT 40 Command ****")
    wifi_client.interfaces.tc.add_delay(40)
    time.sleep(2)
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_clients=net_perf_clients,
                              protocol=protocol, sl_collections=sl_collections, remote_wiseconnect3=remote_wiseconnect3,
                              ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=20741,
                              iteration_count=iter_count)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay(0)
        time.sleep(2)


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}
    }
)
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}
    }
)
@pytest.mark.test_src_map_id('C401893')
def test_wlan_mu_mimo_rtt_udp_rx_C401893(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                                    net_perf_clients, protocol, utf_constants, request, sl_collections,
                                                    remote_wiseconnect3):
    wifi_client.interfaces.tc.add_delay(0)
    time.sleep(5)
    wifi_client.interfaces.tc.add_delay(40)
    time.sleep(5)
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_clients=net_perf_clients,
                              protocol=protocol, sl_collections=sl_collections, remote_wiseconnect3=remote_wiseconnect3,
                              ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=20739,
                              iteration_count=iter_count)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.add_delay(0)
        time.sleep(2)


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
    }
)
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
    }
)
@pytest.mark.test_src_map_id('C401894')
def test_wlan_standalone_mu_mimo_ssl_rx_C401894(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                                ssl_server, request, utf_constants, sl_collections,
                                                remote_wiseconnect3):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, ssl_server=ssl_server,
                              sl_collections=sl_collections, remote_wiseconnect3=remote_wiseconnect3,
                              ping_count=ping_count, ssl_data_transfer=True, traffic_type="RX",
                              iteration_count=iter_count,
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
    }
)
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
    }
)
@pytest.mark.test_src_map_id('C401895')
def test_wlan_standalone_mu_mimo_rtt_ssl_rx_C401895(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                                    ssl_server, utf_constants, request, sl_collections,
                                                    remote_wiseconnect3):
    logger().info("Enabling the **** RTT 40 Command ****")
    wifi_client.interfaces.tc.add_delay(40)
    time.sleep(2)
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, ssl_server=ssl_server,
                              sl_collections=sl_collections, remote_wiseconnect3=remote_wiseconnect3,
                              ping_count=ping_count, ssl_data_transfer=True, traffic_type="RX",
                              iteration_count=iter_count
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay(0)
        time.sleep(2)