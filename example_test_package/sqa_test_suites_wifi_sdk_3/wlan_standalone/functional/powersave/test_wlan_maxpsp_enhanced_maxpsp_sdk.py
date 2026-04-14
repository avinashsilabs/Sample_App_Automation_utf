import re
import time
from utf.utils.stopwatch import Stopwatch
from utf.utils.time_measurer import TimeMeasurer
import pytest as pytest
from utf import UtfDatabaseProperties
from utf.utils.iperf.iperf_utils import ping
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.tcp_udp.test_wlan_data_rates_sdk \
    import SocketDataTransfer
import threading
from threading import Thread, Event
from utf.utils.thread_base import ThreadBase
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
from utf.interfaces.wifi import SecurityMode
from utf.interfaces.shell.ssh_shell import SSHShell
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils import print_dict
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xJoinFeatureBitMap,
    IEEE802_11W,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes
)
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.bsd_errors import BSDErrnoStatus


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)


"""Author : Vivek"""

"""This test plan runs below test steps for validation of DUT-RS917 for Max-psp/Enhanced max psp.
        1. Configuration of DUT in 2G : BGN
        2. Configure AP as per test case requirement(DTIM/Beacon interval)
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Verification of basic power save/pm bit enable or not
        6. Validation of DTIM interval/Listen Interval/Monitor interval for different power save category(PS 1/2/3) in LP/ULP mode.
        7. Validation of power save enable/disable test cases for long duration(12 hours).
        8. Validation of power save in different traffic category.
        9. Validation of power save mode with different AP(Netgear WNR1000,TP-LINK(TL-WDR5620),ASUS-LYRA, Xfinity XB3 
           ,Xfinity XB6 & Belkin AP). Note -  User need to configure the AP manually and update in harness file for test execution. 
        10. Power save 3 test cases are still need assistance, configuration not clear. 


    setup requirement:
        1. DUT(RS917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's-ASUS-RTAX3000)
        4. Sniffer(NUC device)
"""


class DataTransfer:
    def __init__(self):
        self.thread_lock = threading.Lock()
        self.sent_data = 0
        self.rcv_data = 0

    def send_and_receive_data_socket(
            self, thread_no, remote_socket, no_of_pkts, data_size, time_interval, wifi_dut, server_sock, local_port,
            server_ip,
            proto_type=0):

        bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(
            socket_id=server_sock, pkt_length=data_size, no_of_pkts=no_of_pkts, time_interval=time_interval,
            server_ip=server_ip, server_port=local_port)

        logger().info(f"\n **** Sending {bytes_sent} on Thread {thread_no} \n")
        timeout = 2
        if proto_type == 0:
            remote_socket.set_recv_timeout(socket_type=0, timeout=timeout)
        else:
            remote_socket.set_recv_timeout(socket_type=1, use_client_socket=True, timeout=timeout)
        for i in range(0, no_of_pkts):
            if proto_type == 0:
                data = remote_socket.recv_data_tcp(data_size, timeout=timeout)
                logger().info(f' ---- TCP RX on Thread {thread_no} is : {data} ---- ')
            else:
                data, address = remote_socket.recv_data_udp(data_size, timeout=timeout)
                logger().info(f' ---- UDP RX on Thread {thread_no} is : {data} ---- ')
            if not isinstance(data, str):
                logger().info(f"\n **** Unable to Receive on Socket: {server_sock} **** \n")
                break
            self.rcv_data = self.rcv_data + len(data)
            if self.rcv_data == len(bytes_sent):
                break

        remote_socket.socket_close_indication(1)
        logger().info(
            f"Total bytes received on Socket {server_sock} and Thread {thread_no} opened remotely is -> {self.rcv_data}")
        if proto_type == 0:
            assert self.rcv_data == int(
                bytes_sent), f"Data transfer failed. Expected {bytes_sent} bytes but received {self.rcv_data} bytes"
        else:
            logger().info(
                f"Data transfer Successful. Sent {bytes_sent} bytes and received {self.rcv_data} bytes on thread : {thread_no}, "
                f"the observed UDP packet loss is {100 - (int(self.rcv_data) * 100 / int(bytes_sent))}%")


class WLanThread(ThreadBase):
    def __init__(self, wifi_sniffer=None, wifi_dut=None, wifi_access_point=None, wifi_client=None, net_perf_client=None, \
                 protocol=None, sl_collections=None, test_case_no=None, time_period=None, data_transfer=True,
                 test_name=None):

        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.time_period = time_period
        self.dut_addr = None
        self.wifi_sniffer = wifi_sniffer
        self.test_case_no = test_case_no
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.stream_type = 'stream'

    def run(self):
        try:
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
            if self.test_case_no == 19678:
                listen_interval = 1100
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                      Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
                self.wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval)

                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , ping_after_power_save=False,
                                                                         mode='power_save',
                                                                         listen_interval=1100)

                status = ping(self.dut_addr['device_ip'], 60, size="300")
                assert status == 1, "Ping failed"

            if self.test_case_no == 19679:
                listen_interval = 1100
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                      Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
                self.wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , ping_after_power_save=False,
                                                                         mode='power_save',
                                                                         dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0, listen_interval=1100)

                status = ping(self.dut_addr['device_ip'], 60, size="300")
                assert status == 1, "Ping failed"

            if self.test_case_no == 19680:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , ping_after_power_save=False,
                                                                         mode='power_save',
                                                                         dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0)

                status = ping(self.dut_addr['device_ip'], 60, size="300")
                assert status == 1, "Ping failed"
                time.sleep(60)

            if self.test_case_no == 19682:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , ping_after_power_save=False)

            if self.test_case_no == 19693 or self.test_case_no == 19705 or self.test_case_no == 19171:
                listen_interval = 1000
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                      Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
                self.wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval)
                time.sleep(3)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         power_save=False)
                time.sleep(2)

            if self.test_case_no == 19694 or self.test_case_no == 19706:
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                    join_feature_bitmap=Si91xJoinFeatureBitMap.Default)
                time.sleep(2)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         power_save=False)
                time.sleep(2)

            if self.test_case_no == 19695:
                listen_interval = 1100
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                      Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
                self.wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval)
                time.sleep(2)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         power_save=False)
                time.sleep(2)

            if self.test_case_no == 19696:
                listen_interval = 1200
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                      Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
                self.wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval)
                time.sleep(2)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         power_save=False)
                time.sleep(2)

            if self.test_case_no == 19697 or self.test_case_no == 19173:
                listen_interval = 1000
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                      Si91xJoinFeatureBitMap.ListenIntervalFromPowerSave)
                self.wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval)
                time.sleep(2)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         power_save=False)
                time.sleep(3)

            if self.test_case_no == 19698:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0,
                                                                         ping_after_power_save=False)

                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                '''Send traffic RX for 2 min '''
                self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
                self.dut_addr['device_ip'], protocol="TCP", time_out=120)

                def start_client():
                    time.sleep(1)
                    logger().info(f"***** start listening  ******")
                    self.net_perf_client.interfaces.net_perf.start()

                client_thread1 = Thread(target=start_client, args=(), )
                client_thread1.start()

                # open socket and listen for data
                timeout = 130
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                    local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    size=1460, ttl=120, throughput_type=3, qos=0,
                                                    async_socket=1, timeout=timeout + 2)
                client_thread1.join()
                logger().info("data received is successful")
                time.sleep(10)

            if self.test_case_no == 19699:
                listen_interval = 1000
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                      Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
                self.wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval)
                time.sleep(2)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         power_save=False)
                time.sleep(2)

            if self.test_case_no == 19700:
                qos_value = ['0x00', '0x20', '0x80', '0xC8']
                traffic = '0x00'
                protocol = 'TCP'
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0, listen_interval=1200,
                                                                         mode='power_save')

                for qos in qos_value:
                    host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                    logger().info(f"Remote device ip :{host_ip}")
                    self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                                         device_ip=self.dut_addr['device_ip'],
                                                                         protocol=protocol, time_out=120)
                    logger().info(
                        f"Host IP: {host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {protocol}, "
                        f"tos_value: {traffic}")
                    logger().info(f"***** starting iperf ******")

                    def start_client():
                        time.sleep(1)
                        logger().info(f"***** start listening  ******")
                        self.net_perf_client.interfaces.net_perf.start()

                    client_thread1 = Thread(target=start_client, args=(), )
                    client_thread1.start()

                    timeout = 130
                    logger().info(f"***** send traffic  ******")
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                                        local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        size=1460, ttl=120, throughput_type=2, qos=qos,
                                                        timeout=timeout + 2)
                    logger().info("data received is successful")
                    time.sleep(5)

            if self.test_case_no == 19703:
                self.wifi_dut.interfaces.wifi.set_transmit_rate(rate_protocol="802.11n", data_rate='72.2Mbps',
                                                                expected_status=SLStatus.SL_STATUS_OK)

                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0, listen_interval=1200,
                                                                         mode='power_save')

                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")

                '''Send traffic RX for 2 min '''
                self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
                self.dut_addr['device_ip'], protocol="TCP", time_out=120)

                def start_client():
                    time.sleep(1)
                    logger().info(f"***** start listening  ******")
                    self.net_perf_client.interfaces.net_perf.start()

                client_thread1 = Thread(target=start_client, args=(), )
                client_thread1.start()

                # open socket and listen for data
                timeout = 130
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                    local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    size=1460, ttl=120, throughput_type=3, qos=0,
                                                    async_socket=1, timeout=timeout + 2)
                client_thread1.join()
                logger().info("data received is successful")
                time.sleep(10)

            if self.test_case_no == 19704:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , dtim_aligned_type=0, monitor_interval=50,
                                                                         num_of_dtim_skip=0, listen_interval=1200,
                                                                         mode='power_save')

                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")

                '''Send traffic RX for 2 min '''
                self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
                self.dut_addr['device_ip'], protocol="TCP", time_out=120)

                def start_client():
                    time.sleep(1)
                    logger().info(f"***** start listening  ******")
                    self.net_perf_client.interfaces.net_perf.start()

                client_thread1 = Thread(target=start_client, args=(), )
                client_thread1.start()

                # open socket and listen for data
                timeout = 130
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                    local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    size=1460, ttl=120, throughput_type=3, qos=0,
                                                    async_socket=1, timeout=timeout + 2)
                client_thread1.join()
                logger().info("data received is successful")
                time.sleep(10)

            if self.test_case_no == 19167:
                listen_interval = 2000
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                      Si91xJoinFeatureBitMap.ListenIntervalFromPowerSave)
                self.wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , ping_after_power_save=False,
                                                                         num_of_dtim_skip=0, listen_interval=600)

                status = ping(self.dut_addr['device_ip'], 60, size="300")
                assert status == 1, "Ping failed"

            if self.test_case_no == 19174:
                listen_interval = 2000
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                      Si91xJoinFeatureBitMap.ListenIntervalFromPowerSave)
                self.wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval)
                time.sleep(2)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         power_save=False)
                time.sleep(2)

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e

    def tcp_single_socket_dut_client(self):
        no_of_pkts = 100
        pkt_length = 1460
        client_sockets = []
        server_port_base = 5001
        server_socks = []

        server_ip = self.wifi_client.interfaces.wifi.get_ip_address()

        for count in range(0, 1):
            local_port = server_port_base + count
            logger().info(f'Server port = {local_port}')

            client_socket = self.remote_socket_factory.interfaces.socket.create_socket()
            client_sockets.append(client_socket)
            client_socket.start_server(port=local_port)

            sock = self.wifi_dut.interfaces.wifi.Asyncsocket(
                domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP")
            logger().info(f"Socket open successfully : {sock}")
            server_socks.append(sock)

            self.wifi_dut.interfaces.wifi.bind(
                socket_fd=sock, device_ip=self.dut_addr['device_ip'], server_port=local_port, timeout=5, asynch=1)

            logger().info("********** DUT connecting to server **********")
            for count in range(3):
                connect_status = False
                try:
                    self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                        socket_fd=sock, server_ip=server_ip, server_port=local_port)
                    connect_status = True
                    break
                except:
                    logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                    assert connect_status, "Socket connection failed in DUT"
            logger().info("*********** Socket connection is successful ************")
            time.sleep(1)

        server_port = 5001
        time_interval = 5
        data_transfer_objs = []
        socket_threads = []
        for count in range(0, 1):
            logger().info(f"Iteration: {count}")
            local_port = server_port + count
            data_transfer_objs.append(DataTransfer())

            socket_threads.append(Thread(target=data_transfer_objs[count].send_and_receive_data_socket,
                                         args=(
                                             client_sockets[count], no_of_pkts, pkt_length, time_interval,
                                             self.wifi_dut,
                                             server_socks[count], local_port, server_ip, 0), daemon=True))

            socket_threads[count].start()
            socket_threads[count].join()

        for sock in server_socks:
            logger().info(f"Closing socket_id->{sock}")
            self.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)


class FilterPacket:
    """
    WiFi Power Save Frame Analysis and Validation Class

    This class provides comprehensive analysis of WiFi power save behavior by processing
    captured wireless frames from a network sniffer. It validates Enhanced Max PSP
    (Power Save Poll) functionality and various power save timing requirements.

    Key Responsibilities:
    ==================
    1. Parse and analyze captured wireless frames (beacons, PS-polls, data frames)
    2. Validate DTIM-based power save behavior
    3. Validate Listen Interval-based power save timing
    4. Monitor Enhanced Max PSP entry/exit timing
    5. Track power save protocol violations and timing failures

    Core Validation Functions:
    =========================
    - validation_of_enh_max_psp(): Validates 20ms exit and monitor interval enable timing
    - validate_pspoll_data_packet_with_more_bit_enable(): Analyzes PS-poll/data sequences
    - dtim_based_validation(): Ensures proper DTIM beacon PS-poll behavior
    - listen_interval_based_validation(): Validates listen interval timing accuracy

    Frame Processing Flow:
    =====================
    [Capture File] → [Parse Frames] → [Find Start Point] → [Analyze Sequences] → [Validate Timing] → [Report Results]

    Author: Vivek
    """

    def get_association_id(self):
        # This function will parse the pacap file and find & return the association id
        packet_filter = "= Association ID:"
        association_id = None
        count = 0

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter in x:
                association_id = x.strip().split(':')[1].strip()
                print(f'Association id = {association_id}')
                break
        filter_file.close()
        return association_id

    def delta_between_ps_poll_packet(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff_list = []

        '''This function is responsible to create a list for PS-Poll packet time delta between 12 consecutive beacon '''

        filter_file = open(f'./reports/filter2_file.txt', 'r')

        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter in x:
                time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                    'seconds', '')
                if (time_delta_from_previous_packet >= str(1)) and (time_delta_from_previous_packet <= str(2)):
                    logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')
                    time_diff_list.append(float(time_delta_from_previous_packet))

        filter_file.close()
        return time_diff_list

    def parse_sniffer_packets(self):
        packet_type = "    Type/Subtype:"
        packet_filter_frame = '    Frame Number:'
        packet_filter_beacon = '    Type/Subtype: Beacon frame (0x0008)'
        packet_filter_data = '    Type/Subtype: QoS Data (0x0028)'
        packet_filter_ps_poll = '    Type/Subtype: Power-Save poll (0x001a)'
        sniffer_dict = dict()

        """This function takes the filter2_file.txt as a input and parse all captured sniffer packet and convert into 
        dictionary as per given input"""
        filter_file = open(f'./reports/filter2_file.txt', 'r')

        file_line_list = filter_file.readlines()

        for line in file_line_list:
            if packet_filter_frame in line:
                frame_num = line.split(':')[1].strip()

            if packet_type in line:
                if packet_filter_beacon.strip() == line.strip():
                    sniffer_dict[frame_num] = 'beacon'
                if packet_filter_ps_poll.strip() == line.strip():
                    sniffer_dict[frame_num] = 'PS-Poll'
                if packet_filter_data.strip() == line.strip():
                    sniffer_dict[frame_num] = 'Data'
        logger().info("---------Printing sniffer parse dictionary------------\n")
        # logger().info(sniffer_dict)
        return sniffer_dict

    def match_packet_sequence(self, sniffer_dict):
        ps_status = False
        data_status = False
        ps_key = 0
        data_key = 0
        count = 0
        """This function validates the packet sequence for DTIM count reaches 0(As per test case requirement need to validate 
        Beacon-> Ps-Poll-> Data packets sequentially"""

        for key, value in sniffer_dict.items():
            # logger().info(key, '=', value)
            if value == 'beacon':
                beacon_key = key
            if value == 'PS-Poll':
                # logger().info(key, '=', value)
                if int(key) == int(beacon_key) + 1:
                    ps_key = key
                    ps_status = True
                else:
                    ps_status = False
            if value == 'Data':
                # logger().info(key, '=', value)
                if int(key) == int(ps_key) + 1:
                    data_key = key
                    data_status = True
                else:
                    data_status = False
            if ps_status and data_status:
                # logger().info(ps_status, data_status)
                logger().info(f'Sequence of TIM Beacon frame = {beacon_key}, PS-Poll = {ps_key}, Data = {data_key}\n')
                ps_status = False
                data_status = False
                count = count + 1

        return False if count == 0 else True

    def parse_sniffer_packet_more_data(self):
        packet_type = "    Type/Subtype:"
        packet_filter_frame = '    Frame Number:'
        packet_filter_beacon = '    Type/Subtype: Beacon frame (0x0008)'
        packet_filter_data = '    Type/Subtype: QoS Data (0x0028)'
        packet_filter_ps_poll = '    Type/Subtype: Power-Save poll (0x001a)'
        packet_filter_more_data_enable = '            ..1. .... = More Data: Data is buffered for STA at AP'
        packet_filter_more_data_disable = '            ..0. .... = More Data: No data buffered'

        sniffer_dict = dict()
        frame_num = 0
        filter_file = open(f'./reports/filter2_file.txt', 'r')

        file_line_list = filter_file.readlines()

        for line in file_line_list:
            if packet_filter_frame in line:
                frame_num = line.split(':')[1].strip()
            if packet_type in line:
                if packet_filter_ps_poll.strip() == line.strip():
                    sniffer_dict[frame_num] = 'PS-Poll'
            if packet_filter_more_data_enable in line:
                sniffer_dict[frame_num] = 'More Data'
            if packet_filter_more_data_disable in line:
                sniffer_dict[frame_num + 'N'] = 'No Data'
            if packet_filter_beacon in line:
                sniffer_dict[frame_num] = 'beacon'

        filter_file.close()
        # logger().info("---------Printing sniffer parse dictionary------------\n")
        # logger().info(sniffer_dict)
        return sniffer_dict

    def validate_data_packet_with_more_bit_enable(self, sniffer_dict):
        ps_status = False
        no_more_data_status = False
        beacon_status = False
        ps_key = 0
        more_key = 0
        beacon_key = 0
        no_more_data_key = 0
        status_more_data = 0
        status_beacon = 0
        more_key_status = False
        status = True

        for key, value in sniffer_dict.items():
            if value == 'More Data' or ((value == 'More Data') and (int(key) == int(ps_key) + 1)):
                more_key = key
                more_key_status = True
            if value == 'PS-Poll':
                if (int(key) == int(more_key) + 1) and (more_key_status is True):
                    ps_key = key
                    ps_status = True
            if (value == 'No Data') and (key == str(ps_key) + 'N'):
                # this is More data filed 0 belongs to PS-Poll packet no wouldn't count
                pass
            if (value == 'No Data') and (key != str(ps_key) + 'N'):
                # this is Qos data packet with More data filed 0 and we are expecting next packet should be beacon
                no_more_data_key = key
                no_more_data_status = True
            if (value == 'beacon') and (no_more_data_status is True):
                # Verifying whether beacon packet is next to QoS Data with More bit 0
                if int(key) == int(no_more_data_key.split('N')[0]) + 1:
                    beacon_key = key
                    beacon_status = True

            if more_key_status is True and ps_status is True:
                # if Qos Data with More data bit 1 and Ps-Poll packet comes consecutively then pass the test case
                logger().info(f'Qos Data with More data 1 = {more_key}, PS-Poll = {ps_key}')
                ps_status = False
                more_key_status = False
                status_more_data = status_more_data + 1

            if beacon_status:
                # if Qos Data with More data bit 0 and Beacon packet comes consecutively then pass the test case
                logger().info(f'Qos Data with More data 0 = {no_more_data_key}, Beacon = {beacon_key}')
                beacon_status = False
                no_more_data_status = False
                status_beacon = status_beacon + 1

        if status_beacon == 0:
            logger().info(f'Expecting Beacon after Data packet with More bit value 0(QoS + More data bit 0 -> Beacon')
            status = False
        if status_more_data == 0:
            logger().info(f'Expecting PS-Poll after Data packet with More bit enable(QoS + More data bit 1 -> Ps-Poll)')
            status = False
        return status

    def parse_sniffer_packet_dtim_beacon(self):
        packet_filter_frame = '    Frame Number:'
        packet_filter_data = '    Type/Subtype: QoS Data (0x0028)'
        packet_filter_ps_poll = '    Type/Subtype: Power-Save poll (0x001a)'
        packet_filter_dtim0 = '            DTIM count: 0'
        packet_filter_dtim1 = '            DTIM count: 1'
        packet_assoc_id = '            Association ID: 0x01'
        sniffer_dict = dict()
        frame_num = 0
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        file_line_list = filter_file.readlines()

        for line in file_line_list:
            if packet_filter_frame in line:
                frame_num = line.split(':')[1].strip()
            if packet_filter_dtim1 in line:
                sniffer_dict[frame_num] = 'DTIM1'
            if packet_filter_dtim0 in line:
                sniffer_dict[frame_num] = 'DTIM0'
            if packet_assoc_id in line:
                sniffer_dict[frame_num + 'A'] = 'DTIM_Beacon'
            if packet_filter_ps_poll in line:
                sniffer_dict[frame_num] = 'PS-Poll'
            if packet_filter_data in line:
                sniffer_dict[frame_num] = 'Qos Data'

        filter_file.close()
        logger().info("---------Printing sniffer parse dictionary------------\n")
        logger().info(sniffer_dict)
        return sniffer_dict

    def validate_packet_for_dtim_beacon(self, sniffer_dict, dtim_count):
        dtim1_status = False
        dtim_wake_neg = []
        dtim0_status = False
        dtim_beacon_status = False
        ps_poll_status = False
        data_status = False
        status = {'wake_up_validation': True, 'sequence': False}
        data_key = 0
        ps_poll_key = 0
        dtim1_key = 0
        dtim0_key = 0
        counter = 0
        match_key = 0

        for key, value in sniffer_dict.items():
            # Note-> DTIM1 means DTIM count = 1
            if value == 'DTIM1' or ((value == 'DTIM1') and (int(key) == int(dtim0_key) + 1)):
                dtim1_key = key
                dtim1_status = True

            # Note-> DTIM0 means DTIM count = 0
            if value == 'DTIM0':
                if (int(key) == int(dtim1_key) + 1) and (dtim1_status is True):
                    dtim0_key = key
                    dtim0_status = True
                    counter = counter + 1

            # Note-> DTIM beacon means DTIM count = 0 & association id = 0x01
            if (value == 'DTIM_Beacon') and (key == dtim0_key + 'A') and (counter == dtim_count):
                dtim_beacon_key = key
                dtim_beacon_status = True
                match_key = dtim_beacon_key.split('A')[0]
                logger().info(dtim_beacon_key)
                counter = 0
            elif (value == 'DTIM_Beacon') and (key == dtim0_key + 'A') and (counter != dtim_count):
                counter = 0
                logger().info(key)
                logger().info('Unable to wake up at specified DTIM interval')
                dtim_wake_neg.append(key)

            if value == 'PS-Poll':
                if int(key) == int(match_key) + 1:
                    ps_poll_key = key
                    ps_poll_status = True
                else:
                    pass

            if value == 'Qos Data':
                if int(key) == int(ps_poll_key) + 1:
                    data_key = key
                    data_status = True

            # if DTIM count is 0 then check TIM bit is 0(means association id should not be present in TIM bit)
            # or not if not then DUT should not send PS-POLL
            if dtim0_status is True and dtim_beacon_status is False:
                if int(ps_poll_key) == int(dtim0_key) + 1:
                    logger().info("Validating wake up indication when TIM bit is not set")
                    status['wake_up_validation'] = False

            # if DTIM count is nonzero then check DUT should not send any PS-POLL
            # Logic is DUT should not wake up or send PS-POLL packets in Non DTIM beacon intervals
            # So next packet should not be PS-POLL packet
            if dtim1_status is True:
                if int(ps_poll_key) == int(dtim1_key) + 1:
                    logger().info("Validating wake up indication at non DTIM intervals")
                    status['wake_up_validation'] = False

            if dtim0_status:
                logger().info(f'Beacon+DTIM1 = {dtim1_key}, Beacon+DTIM0 = {dtim0_key}')
                dtim1_status = False
                dtim0_status = False

            if (dtim_beacon_status is True) and (ps_poll_status is True) and (data_status is True):
                logger().info(f'DTIM Beacon = {dtim_beacon_key}, PS-Poll = {ps_poll_key}, Qos Data = {data_key}\n\n')
                dtim_beacon_status = False
                ps_poll_status = False
                data_status = False
                counter = 0
                status['sequence'] = True

        status['dtim_wakeup_packet_list'] = dtim_wake_neg
        logger().info(f'\n\n {status}')
        if status['sequence']:
            logger().info("------------------Expected packet sequence found--------------")
            return status
        else:
            logger().info("------------------Expected packet sequence not found--------------")
            return status

    def parse_sniffer_packet_for_max_psp_95(self):
        packet_filter_frame = '    Frame Number:'
        packet_filter_data = '    Type/Subtype: QoS Data (0x0028)'
        packet_filter_ps_poll = '    Type/Subtype: Power-Save poll (0x001a)'
        packet_filter_dtim0 = '            DTIM count: 0'

        """This function takes the filter2_file.txt as a input and parse all captured sniffer packet and convert into
        dictionary as per given input"""
        sniffer_dict = dict()
        frame_num = 0
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        file_line_list = filter_file.readlines()

        for line in file_line_list:
            if packet_filter_frame in line:
                frame_num = line.split(':')[1].strip()
            if packet_filter_dtim0 in line:
                sniffer_dict[frame_num] = 'DTIM0'
            if packet_filter_ps_poll.strip() == line.strip():
                sniffer_dict[frame_num] = 'PS-Poll'
            if packet_filter_data.strip() == line.strip():
                sniffer_dict[frame_num] = 'Data'
        logger().info("---------Printing sniffer parse dictionary------------\n")
        filter_file.close()
        return sniffer_dict

    def validate_packet_for_max_psp(self, sniffer_dict):
        data_status = False
        ps_key = 0
        data_key = 0
        dtim0_key = 0

        """This function validates the packet sequence for DTIM count reaches 0(As per test case requirement need to validate
        Beacon(DTIM0)-> Ps-Poll-> Data packets sequentially"""

        for key, value in sniffer_dict.items():
            pass_status = []
            if value == 'DTIM0':
                dtim0_key = key
            if value == 'PS-Poll':
                if int(key) == int(dtim0_key) + 1:
                    ps_key = key
            if value == 'Data':
                if int(key) == int(ps_key) + 1:
                    data_key = key
                    data_status = True
            if data_status:
                logger().info(
                    f'\n Sequence of DUT wake time, Beacon = {dtim0_key}, PS-Poll = {ps_key}, Data = {data_key}\n ')
                data_status = False
                ps_poll_frame = ps_key
                data_frame = data_key

                logger().info(f'ps_poll_frame = {ps_poll_frame}, data_frame = {data_frame}')

                ps_poll_status = False
                data_status = False
                time_diff_list = []
                packet_filter1 = "Arrival Time:"
                frame_no = f'Frame {ps_key}:'
                data_frame_no = f'Frame {data_key}:'
                filter_file = open(f'./reports/filter2_file.txt', 'r')
                file_line_list = filter_file.readlines()

                for line in file_line_list:
                    if frame_no in line:
                        ps_poll_status = True
                        logger().info(f'PS -poll frame -->{frame_no}')
                        pass
                    if data_frame_no in line:
                        data_status = True
                        logger().info(f'Data frame no -->{data_frame_no}')
                        pass
                    if (packet_filter1 in line and ps_poll_status is True) or (
                            packet_filter1 in line and data_status is True):
                        result = re.search('2022(.*)IST', line)
                        time_stamp = result.group(1).strip()
                        logger().info(f'time_stamp={time_stamp}')
                        ps_poll_status = False
                        data_status = False
                        size = len(time_stamp)
                        mod_time_stamp = time_stamp[:size - 3]
                        time_diff_list.append(mod_time_stamp)

                logger().info(
                    f'PS-Poll data packet time = {time_diff_list[0]}, Qos Data packet time = {time_diff_list[1]}')

                time_diff_ps_poll_and_data_frame = datetime.datetime.strptime(time_diff_list[1],
                                                                              '%H:%M:%S.%f') - datetime.datetime.strptime(
                    time_diff_list[0], '%H:%M:%S.%f')
                logger().info(f"Time difference between ps-poll and Qos data frame: {time_diff_ps_poll_and_data_frame}")
                time_diff_in_ms = str(time_diff_ps_poll_and_data_frame)[7:14]
                logger().info(f'Time difference in ms = {time_diff_in_ms}')
                expected_time_between_ps_poll_and_data_frame = 0.021
                if float(time_diff_in_ms) <= expected_time_between_ps_poll_and_data_frame:
                    actual_time_diff = expected_time_between_ps_poll_and_data_frame - float(time_diff_in_ms)
                    logger().info(
                        f"Time difference between ps-poll = {time_diff_list[0]} & Qos data frame = {time_diff_list[1]} "
                        f"is less than 20ms")
                    logger().info("\n Actual time difference = %.4f" % actual_time_diff)
                    pass_status.append(True)
                else:
                    logger().info(
                        f"Time difference between ps-poll = {time_diff_list[0]} & Qos data frame = {time_diff_list[1]} "
                        f"is greater than 20ms")
                    pass_status.append(False)
        return False if False in pass_status else True

    def parse_sniffer_packet_max_psp_95_null_frame(self):
        packet_filter_frame = '    Frame Number:'
        packet_filter_data = '    Type/Subtype: QoS Data (0x0028)'
        packet_filter_null_data = '    Type/Subtype: QoS Null function (No data) (0x002c)'
        packet_filter_ps_poll = '    Type/Subtype: Power-Save poll (0x001a)'
        packet_null = '    Type/Subtype: Null function (No data) (0x0024)'
        pmbit_0 = '            ...0 .... = PWR MGT: STA will stay up'
        pmbit_1 = '            ...1 .... = PWR MGT: STA will go to sleep'

        """This function takes the filter2_file.txt as a input and parse all captured sniffer packet and convert into
        dictionary as per given input for TC-19695"""
        """ Sequence will be PS-POLL - > Null frame + 0 -> Qos data -> Null frame + 1"""
        sniffer_dict = dict()
        frame_num = 0
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        file_line_list = filter_file.readlines()

        for line in file_line_list:
            if packet_filter_frame in line:
                frame_num = line.split(':')[1].strip()
            if packet_filter_ps_poll.strip() == line.strip():
                sniffer_dict[frame_num] = 'PS-Poll'
            if packet_null.strip() == line.strip():
                sniffer_dict[frame_num] = 'NULL'
            if packet_filter_data.strip() == line.strip():
                sniffer_dict[frame_num] = 'Data'
            if packet_filter_null_data.strip() == line.strip():
                sniffer_dict[frame_num] = 'NULL_DATA'
            if pmbit_0.strip() == line.strip():
                sniffer_dict[frame_num + 'pm0'] = 'PM0'
            if pmbit_1.strip() == line.strip():
                sniffer_dict[frame_num + 'pm1'] = 'PM1'

        # logger().info("---------Printing sniffer parse dictionary------------\n")
        # logger().info(sniffer_dict)
        filter_file.close()
        return sniffer_dict

    def validate_packet_for_max_psp_null_frame(self, sniffer_dict):
        pm1_status = False
        ps_key = 0
        data_key = 0
        null_key1 = 0
        null_key = 0
        pm0_status = False

        """This function validates the packet sequence for DTIM count reaches 0(As per test case requirement need to validate
        Beacon-> Ps-Poll-> Data packets sequentially"""

        for key, value in sniffer_dict.items():
            pass_status = []
            if value == 'PS-Poll':
                ps_key = key
            if value == 'NULL':
                if int(key) == int(ps_key) + 1:
                    null_key = key
            if value == 'PM0' and (key == str(null_key) + 'pm0'):
                pm0_status = True
            if ((value == 'Data') or (value == 'NULL_DATA')) and pm0_status is True:
                if int(key) == int(null_key) + 1:
                    data_key = key
            if value == 'NULL':
                if int(key) == int(data_key) + 1:
                    null_key1 = key
            if value == 'PM1' and (key == str(null_key1) + 'pm1'):
                pm1_status = True

            if pm1_status:
                logger().info(
                    'Validation for packet sequence PS-POLL -> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1')
                logger().info(f'\n PS-POLL = {ps_key}, NULL frame with pm bit 0 = {null_key}, Qos Data = {data_key},'
                              f' NULL frame with pm bit 1 = {null_key1}\n')
                pm1_status = False

                data_frame_status = False
                null_frame_status = False
                time_diff_list = []
                packet_filter1 = "Arrival Time:"
                data_frame_no = f'Frame {data_key}:'
                null_frame_no = f'Frame {null_key1}:'
                filter_file = open(f'./reports/filter2_file.txt', 'r')
                file_line_list = filter_file.readlines()

                for line in file_line_list:
                    if data_frame_no in line:
                        data_frame_status = True
                        print(f'Data frame no -->{data_frame_no}--->')
                        pass
                    if null_frame_no in line:
                        null_frame_status = True
                        print(f'NUll Frame no -->{null_frame_no}--->')
                        pass
                    if (packet_filter1 in line and data_frame_status is True) or (
                            packet_filter1 in line and null_frame_status is True):
                        result = re.search('2022(.*)IST', line)
                        time_stamp = result.group(1).strip()
                        print(f'time_stamp={time_stamp}')
                        data_frame_status = False
                        null_frame_status = False
                        size = len(time_stamp)
                        mod_time_stamp = time_stamp[:size - 3]
                        time_diff_list.append(mod_time_stamp)

                time_diff_ps_poll_and_data_frame = datetime.datetime.strptime(time_diff_list[1],
                                                                              '%H:%M:%S.%f') - datetime.datetime.strptime(
                    time_diff_list[0], '%H:%M:%S.%f')
                logger().info(f"Time difference between Qos data and NUll frame: {time_diff_ps_poll_and_data_frame}")
                time_diff_in_ms = str(time_diff_ps_poll_and_data_frame)[7:14]
                logger().info(f'Time difference in ms = {time_diff_in_ms}')
                expected_time_between_ps_poll_and_data_frame = 0.070
                if float(time_diff_in_ms) <= expected_time_between_ps_poll_and_data_frame:
                    logger().info(
                        f"\nTime difference between Qos data frame = {time_diff_list[0]} & NUll frame with pm bit 1 = "
                        f"{time_diff_list[1]} is less than 70ms \n")
                    pass_status.append(True)
                else:
                    logger().info(
                        f"Time difference between Qos data frame = {time_diff_list[0]} & NUll frame with pm bit 1 = "
                        f"{time_diff_list[1]} is greater than 50ms")
                    pass_status.append(False)
            else:
                '''************ No packet sequence found ************'''
                pass_status.append(False)
        # return False if False in pass_status else True
        if False in pass_status:
            logger().info(f'********* No packet sequence found ************')
            return False
        else:
            return True

    def validate_time_delta(self, ps_poll_packets_time_delta_list, time_delta_for_listen_interval):
        """
         Validates DUT is waking at listen inteval time or not and it returns the count of when DUT didn't send the
         ps_poll at listen interval
        """

        unable_to_send_ps_poll_at_li = 0
        listen_interval_beacon = int(time_delta_for_listen_interval / 100)
        for time_diff in ps_poll_packets_time_delta_list:
            is_between = time_diff in range(time_delta_for_listen_interval - 20, time_delta_for_listen_interval + 90)
            logger().info(f'is_between = {is_between}')
            if is_between is True:
                logger().info(
                    f'DUT sends PS-poll after {listen_interval_beacon} consecutive beacon frame and time diff is = {time_diff / 1000}')
            else:
                logger().info(
                    f'DUT unable to send PS-poll after {listen_interval_beacon} consecutive beacon frame and time diff is = {time_diff / 1000}')
                unable_to_send_ps_poll_at_li = unable_to_send_ps_poll_at_li + 1
        return unable_to_send_ps_poll_at_li

    def validation_of_enh_max_psp(self, ps_exit_interval_list, ps_enable_interval_list, monitor_interval):
        """
        Enhanced Max PSP Validation Function

        Flowchart Description:
        ┌─────────────────────────────────────────────────────────┐
        │ A[Start Enhanced Max PSP Validation]                   │
        │ ↓                                                       │
        │ B[Initialize Counters:<br/>ps_exit_interval_fail = 0    │
        │   ps_enable_interval_fail = 0]                         │
        │ ↓                                                       │
        │ C[Loop through ps_exit_interval_list]                  │
        │ ↓                                                       │
        │ D{Is time_diff != 0?}                                  │
        │ ↓ Yes                                                   │
        │ E[Check if 19.5ms <= time_diff <= 21.5ms]              │
        │ ↓                                                       │
        │ F{Within Range?}                                        │
        │ ↓ No                                                    │
        │ G[Increment ps_exit_interval_fail]                      │
        │ ↓                                                       │
        │ H[Loop through ps_enable_interval_list]                │
        │ ↓                                                       │
        │ I{Is time_diff != 0?}                                  │
        │ ↓ Yes                                                   │
        │ J[Check if monitor_interval-1 <= time_diff <=          │
        │   monitor_interval+2]                                  │
        │ ↓                                                       │
        │ K{Within Range?}                                        │
        │ ↓ No                                                    │
        │ L[Increment ps_enable_interval_fail]                    │
        │ ↓                                                       │
        │ M[Return: ps_exit_interval_fail,                       │
        │   ps_enable_interval_fail]                             │
        └─────────────────────────────────────────────────────────┘

        Purpose:
         - Validates DUT exits from powersave when no response for ps-poll in ~20ms
         - Validates DUT enables powersave if no data received from AP for monitor_interval

        Args:
            ps_exit_interval_list: List of intervals when DUT exits powersave
            ps_enable_interval_list: List of intervals when DUT enables powersave
            monitor_interval: Expected monitor interval for powersave enable

        Returns:
            tuple: (ps_exit_interval_fail_count, ps_enable_interval_fail_count)
        """

        # Step 1: Initialize failure counters for exit and enable scenarios
        ps_exit_interval_fail = 0
        ps_enable_interval_fail = 0

        # Step 2: Validate PS-Exit intervals (should be ~20ms when no response to PS-Poll)
        for time_diff in ps_exit_interval_list:
            if time_diff != 0:
                # Check if exit timing is within acceptable range (19.5ms to 21.5ms)
                is_between = 19.5 <= time_diff <= 21.5
                logger().info(f'is_between = {is_between}')
                if is_between is True:
                    logger().info(
                        f'DUT is exit from the powersave after {time_diff}ms as there is no response for ps-poll')
                else:
                    # Count failed scenarios where exit timing is outside expected range
                    logger().info(
                        f'DUT is exit from the powersave after {time_diff}ms as there is no response for ps-poll')
                    ps_exit_interval_fail = ps_exit_interval_fail + 1

        # Step 3: Validate PS-Enable intervals (should match monitor_interval when no data from AP)
        for time_diff in ps_enable_interval_list:
            if time_diff != 0:
                # Check if enable timing is within monitor interval ± tolerance
                is_between = monitor_interval - 1 <= time_diff <= monitor_interval + 2
                logger().info(f'is_between = {is_between}')
                if is_between is True:
                    logger().info(
                        f'DUT back to power save and there is no RX data from the AP for {time_diff}ms interval')
                else:
                    # Count failed scenarios where enable timing is outside expected range
                    logger().info(
                        f'DUT back to power save and there is no RX data from the AP for {time_diff}ms interval')
                    ps_enable_interval_fail = ps_enable_interval_fail + 1

        # Step 4: Return failure counts for both exit and enable scenarios
        return ps_exit_interval_fail, ps_enable_interval_fail

    def validate_pspoll_data_packet_with_more_bit_enable(self, frame_list, frame_number, listen_interval_time,
                                                         current_beacon_time, beacon_count=None, listen_interval=None):
        """
        PS-Poll Data Packet Validation with More Bit Enable Function

        Flowchart Description:
        ┌─────────────────────────────────────────────────────────┐
        │ A[Start PS-Poll Validation]                            │
        │ ↓                                                       │
        │ B[Initialize Variables:<br/>                           │
        │   - Frame types (beacon, ps_poll, qos_data, etc.)<br/> │
        │   - Timing variables<br/>                              │
        │   - Counter variables]                                 │
        │ ↓                                                       │
        │ C[Main Processing Loop: while frame_number < total]    │
        │ ↓                                                       │
        │ D{Is frame NULL with PM='0'?}                          │
        │ ↓ Yes                                                   │
        │ E[Process Active State Entry:<br/>                     │
        │   - Calculate ps_exit_interval<br/>                    │
        │   - Find corresponding NULL with PM='1']              │
        │ ↓                                                       │
        │ F{Is frame QoS/Action with more_bit='1'?}              │
        │ ↓ Yes                                                   │
        │ G[Process More Data Bit Set:<br/>                      │
        │   - Search for next beacon<br/>                        │
        │   - Check if PS-Poll follows<br/>                      │
        │   - Validate timing constraints]                       │
        │ ↓                                                       │
        │ H{Is frame PS-Poll?}                                   │
        │ ↓ Yes                                                   │
        │ I[Continue to next frame]                              │
        │ ↓                                                       │
        │ J{Is frame Beacon?}                                    │
        │ ↓ Yes                                                   │
        │ K[Process Beacon:<br/>                                 │
        │   - Update beacon count<br/>                           │
        │   - Calculate timing differences<br/>                  │
        │   - Check for data frames]                             │
        │ ↓                                                       │
        │ L[Return: frame_number, case2, first_beacon_time,      │
        │   ps_exit_interval, ps_enable_interval, beacon_count]  │
        └─────────────────────────────────────────────────────────┘

        Purpose:
         - Validates DUT can receive data after sending ps-poll
         - Tracks failed scenarios when DUT doesn't send ps-poll with more_data bit set
         - Monitors enhanced max PSP timing behavior

        Args:
            frame_list: List of captured frames from sniffer
            frame_number: Current frame index to start processing
            listen_interval_time: Expected listen interval in milliseconds
            current_beacon_time: Timestamp of current beacon
            beacon_count: Count of beacons processed
            listen_interval: Listen interval value

        Returns:
            tuple: (frame_number, failed_case_count, beacon_time,
                   ps_exit_interval, ps_enable_interval, beacon_count)
        """
        # Step 1: Initialize frame processing variables and frame type constants
        first_beacon_time = current_beacon_time
        beacon = int('0x0008', 16)  # Beacon frame type
        ps_poll = int('0x001a', 16)  # PS-Poll frame type
        qos_data = int('0x0028', 16)  # QoS Data frame type
        qos_null = int('0x002c', 16)  # QoS Null frame type
        action_frame = int('0x000d', 16)  # Action frame type
        block_req = int('0x0018', 16)  # Block ACK request frame type
        null_function = int('0x0024', 16)  # Null function frame type

        # Step 2: Initialize tracking variables for Enhanced Max PSP analysis
        no_of_filtered_packets = len(frame_list)
        ps_exit_interval = 0  # Time to exit power save mode
        ps_enable_interval = 0  # Time to re-enable power save mode
        ps_exit_interval_ignore = 0  # Ignored exit intervals
        ps_enable_interval_ignore = 0  # Ignored enable intervals
        beacon_count = 0  # Count of beacons processed
        max_beacon = int(listen_interval_time / 100)  # Max beacons in listen interval
        bmiss_listen_interval = listen_interval_time  # Handle beacon miss scenarios
        tim_diff_bw_beacon = 0  # Time difference between beacons
        case2 = 0  # Count of more_data bit related failures

        # Step 3: Main frame processing loop - analyze each captured frame
        while 1:
            if frame_number < no_of_filtered_packets - 2:  # removing last 2 frames from the capture
                frame_number = frame_number + 1
            else:
                break
            moredata_pspoll_failed = 0

            if frame_list[frame_number][2] == str(null_function) and frame_list[frame_number][4] == '0':
                logger().info(
                    "found Null frame with PM '0' and DUT is entering into active state during ENH MAX PSP mode")
                logger().info(frame_list[frame_number])
                nullframe_time = frame_list[frame_number][1]
                if frame_list[frame_number - 1][2] == str(ps_poll):
                    logger().info(frame_list[frame_number - 1])
                    current_pspoll_time = frame_list[frame_number - 1][1]
                    ps_exit_interval = (float(nullframe_time) - float(current_pspoll_time)) * 1000
                    logger().info(f'time_diff_bw_pspoll_nullframe={ps_exit_interval}')
                else:
                    if frame_list[frame_number - 1][2] == str(beacon) or (
                            frame_list[frame_number - 1][2] == str(qos_data)):
                        logger().info(frame_list[frame_number - 1])
                        current_pspoll_time = frame_list[frame_number - 1][1]
                        ps_exit_interval_ignore = (float(nullframe_time) - float(current_pspoll_time)) * 1000
                        logger().info(f'time_diff_bw_pspoll_nullframe(ignore)={ps_exit_interval_ignore}')
                while 1:
                    if frame_number < no_of_filtered_packets - 2:
                        frame_number = frame_number + 1
                    else:
                        break
                    if (frame_list[frame_number][2] == str(qos_data) or frame_list[frame_number][2] == str(
                            beacon) or
                            frame_list[frame_number][2] == str(qos_null)):
                        continue
                    else:
                        if frame_list[frame_number][2] == str(null_function) and frame_list[frame_number][4] == '1':
                            logger().info(frame_list[frame_number])
                            nullframe_time = frame_list[frame_number][1]
                            if frame_list[frame_number - 1][2] == str(qos_data) or frame_list[frame_number - 1][
                                2] == str(beacon) or \
                                    frame_list[frame_number - 1][2] == str(null_function):
                                if frame_list[frame_number - 1][2] == str(beacon):
                                    logger().info(frame_list[frame_number - 2])
                                    qos_time = frame_list[frame_number - 2][1]
                                    ps_enable_interval_ignore = (float(nullframe_time) - float(
                                        qos_time)) * 1000
                                    logger().info(
                                        f'time_diff_bw_last_qos_nullframe(ignore)={ps_enable_interval_ignore}')
                                else:
                                    logger().info(frame_list[frame_number - 1])
                                    qos_time = frame_list[frame_number - 1][1]
                                    ps_enable_interval = (float(nullframe_time) - float(
                                        qos_time)) * 1000
                                    logger().info(f'time_diff_bw_last_qos_nullframe={ps_enable_interval}')
                                first_beacon_time = float(frame_list[frame_number][1])
                                return frame_number, case2, first_beacon_time, ps_exit_interval, ps_enable_interval, beacon_count

            if ((frame_list[frame_number][2] == str(qos_data)) or (frame_list[frame_number][2] == str(qos_null)) or (
                    frame_list[frame_number][2] == str(action_frame)) or (
                    frame_list[frame_number][2] == str(block_req))):
                if (frame_list[frame_number][5]) == '1':
                    # logger().info(frame_list[frame_number])
                    # logger().info(
                    #     'Qos data/QOS Null frame/Action frame/block-ack req with more data bit is set to 1')
                    while 1:
                        if frame_number < no_of_filtered_packets - 2:
                            frame_number = frame_number + 1
                        else:
                            break
                        if frame_list[frame_number][2] == str(beacon):
                            beacon_count = beacon_count + 1
                            current_beacon_time = float(frame_list[frame_number][1])
                            tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                            logger().info(frame_list[frame_number])
                            if listen_interval_time == 0:
                                if frame_list[frame_number][6] == '0' and frame_list[frame_number + 1][2] == str(
                                        ps_poll) and len(frame_list[frame_number]) == 8:
                                    # logger().info(frame_list[frame_number])
                                    t1 = float(frame_list[frame_number][2])
                                    t0 = float(frame_list[frame_number - 1][2])
                                    time_diff = int(round((t1 - t0) * 1000))
                                    if time_diff > 100:
                                        logger().info(
                                            "DUT is sending PS-POLL at next DTIM/DTIMSKIP beacon only even though moredata bit set")
                                        case2 = case2 + 1
                                    break
                            else:
                                if tim_diff_bw_beacon > listen_interval_time or beacon_count == max_beacon:
                                    beacon_count = int(tim_diff_bw_beacon / 100)
                                    logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                    logger().info(f'beacon_count={beacon_count}')
                                    first_beacon_time = current_beacon_time
                                    logger().info(
                                        f'listen_interval_time={listen_interval_time}, max_beacon = {max_beacon}')
                                    if (beacon_count > max_beacon):
                                        listen_interval_time = bmiss_listen_interval - (beacon_count - max_beacon) * 100
                                        logger().info(f'listen_interval_time_lastbmiss={listen_interval_time}')

                                    else:
                                        listen_interval_time = bmiss_listen_interval
                                        logger().info(f'listen_interval_time={listen_interval_time}')
                                if tim_diff_bw_beacon >= (listen_interval_time - 30) and frame_list[frame_number + 1][
                                    2] == str(
                                        ps_poll):
                                    t1 = float(frame_list[frame_number][2])
                                    t0 = float(frame_list[frame_number - 1][2])
                                    time_diff = int(round((t1 - t0) * 1000))
                                    if time_diff > 100:
                                        logger().info(
                                            f'DUT is sending PS-POLL at next LI beacon only even though more data bit set-time_diff={tim_diff_bw_beacon}')
                                        case2 = case2 + 1
                                        first_beacon_time = float(frame_list[frame_number][1])
                                        break
                            continue
                        elif frame_list[frame_number][2] == str(ps_poll):
                            # logger().info(frame_list[frame_number])
                            break
                        else:
                            frame_number = frame_number - 1
                            # logger().info("PS-POLL didn't observe after data packet with more data bit set")
                            break
                    continue
                else:
                    logger().info(frame_list[frame_number])
                    if tim_diff_bw_beacon != 0:
                        if tim_diff_bw_beacon > listen_interval_time:
                            beacon_count = int(tim_diff_bw_beacon / 100) - max_beacon
                        else:
                            beacon_count = int(tim_diff_bw_beacon / 100)
                    logger().info(
                        f'Qos data/QOS Null frame/Action frame/block-ack req with more data bit is set to 0 - beacon_count:{beacon_count}')
                    break
            else:
                # logger().info(frame_list[frame_number])
                if frame_list[frame_number][2] == str(ps_poll):
                    if moredata_pspoll_failed > 1:
                        first_beacon_time = float(frame_list[frame_number][1])
                    continue
                elif frame_list[frame_number][2] == str(beacon):
                    logger().info(frame_list[frame_number])
                    beacon_count = beacon_count + 1
                    if frame_number < no_of_filtered_packets:
                        if (listen_interval_time != 0):
                            current_beacon_time = float(frame_list[frame_number][1])
                            tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                            if tim_diff_bw_beacon > listen_interval_time or beacon_count == max_beacon:
                                beacon_count = int(tim_diff_bw_beacon / 100)
                                logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                logger().info(f'beacon_count={beacon_count}')
                                first_beacon_time = current_beacon_time
                                if (beacon_count > max_beacon):
                                    listen_interval_time = bmiss_listen_interval - (beacon_count - max_beacon) * 100
                                    logger().info(f'listen_interval_time_lastbmiss={listen_interval_time}')
                                else:
                                    listen_interval_time = bmiss_listen_interval
                                    logger().info(f'listen_interval_time={listen_interval_time}')
                        frame_number = frame_number + 1
                    else:
                        break
                    if ((frame_list[frame_number][2] == str(qos_data)) or (
                            frame_list[frame_number][2] == str(qos_null)) or (
                            frame_list[frame_number][2] == str(action_frame)) or (
                            frame_list[frame_number][2] == str(block_req)) or
                            frame_list[frame_number][
                                2] == str(ps_poll)):
                        continue
                    else:
                        frame_number = frame_number - 1
                        if not (frame_list[frame_number][2] == str(null_function) and frame_list[frame_number][
                            4] == '1'):
                            logger().info("On-air data is missing")
                        break
        return frame_number, case2, first_beacon_time, ps_exit_interval, ps_enable_interval, beacon_count

    def dtim_based_validation(self, assoc_id):
        """
        DTIM-Based Power Save Validation Function

        Flowchart Description:
        ┌─────────────────────────────────────────────────────────┐
        │ A[Start DTIM Validation]                               │
        │ ↓                                                       │
        │ B[Initialize Variables:<br/>                           │
        │   - Read Powersave_capture.txt<br/>                    │
        │   - Parse frames into frame_list<br/>                  │
        │   - Set validation counters (case1-4) = 0]            │
        │ ↓                                                       │
        │ C[Trim last 10 frames from capture]                   │
        │ ↓                                                       │
        │ D[Find first NULL frame with PM='1']                  │
        │ ↓                                                       │
        │ E[Main Processing Loop: while frame_number < total]    │
        │ ↓                                                       │
        │ F{Is frame a Beacon?}                                  │
        │ ↓ Yes                                                   │
        │ G[Extract TIM information from beacon]                 │
        │ ↓                                                       │
        │ H{Is DTIM=0 AND TIM set for DUT?}                     │
        │ ↓ Yes (Positive Scenario)                              │
        │ I[Search for PS-Poll after beacon]                    │
        │ ↓                                                       │
        │ J{PS-Poll found?}                                      │
        │ ↓ Yes                                                   │
        │ K[Call validate_pspoll_data_packet_with_more_bit_enable] │
        │ ↓ No                                                    │
        │ L[Increment case3 (missed PS-Poll at DTIM)]           │
        │ ↓                                                       │
        │ M{Is DTIM!=0 AND TIM set for DUT?}                    │
        │ ↓ Yes (Negative Scenario)                              │
        │ N[Check if PS-Poll sent at non-DTIM beacon]           │
        │ ↓                                                       │
        │ O{PS-Poll found at non-DTIM?}                         │
        │ ↓ Yes                                                   │
        │ P[Increment case4 (PS-Poll at non-DTIM)]              │
        │ ↓                                                       │
        │ Q{Is TIM not set for DUT?}                            │
        │ ↓ Yes (Negative Scenario)                              │
        │ R[Check if PS-Poll sent when TIM not set]             │
        │ ↓                                                       │
        │ S{PS-Poll found when TIM not set?}                    │
        │ ↓ Yes                                                   │
        │ T[Increment case1 (PS-Poll when TIM not set)]         │
        │ ↓                                                       │
        │ U[Return: case1, case2, case3, case4,                 │
        │   ps_exit_interval_list, ps_enable_interval_list]     │
        └─────────────────────────────────────────────────────────┘

        Purpose:
         - Validates DTIM-based power save functionality
         - Ensures DUT sends PS-Poll only at DTIM beacons when TIM bit is set
         - Tracks various failure scenarios in DTIM power save behavior

        Validation Cases:
         - case1: DUT should NOT send PS-Poll when TIM is not set
         - case2: DUT should NOT wait for next DTIM when more_data bit is set
         - case3: DUT should NOT skip sending PS-Poll at DTIM beacon when TIM is set
         - case4: DUT should NOT send PS-Poll at non-DTIM beacons

        Args:
            assoc_id: Association ID of the DUT in hex format

        Returns:
            tuple: (case1_count, case2_count, case3_count, case4_count,
                   ps_exit_interval_list, ps_enable_interval_list)
        """
        # Step 1: Initialize tracking variables and data structures
        beacon_count = 0
        frame_list = []  # Will store parsed capture frames
        ps_exit_interval_list = []  # Track power save exit timings
        ps_enable_interval_list = []  # Track power save enable timings
        count = 0  # Frame counter for initial scan
        assoc_id = int(assoc_id, 16)  # Convert association ID to integer
        tim_aid = 0  # TIM association ID from beacon

        # Step 2: Define frame type constants for pattern matching
        beacon = int('0x0008', 16)  # Beacon frame type
        null_frame = int('0x0024', 16)  # Null frame type
        ps_poll = int('0x001a', 16)  # PS-Poll frame type

        # Step 3: Initialize validation case counters for different failure scenarios
        case1 = 0  # VIOLATION: DUT sends PS-POLL when TIM is NOT set
        case2 = 0  # VIOLATION: DUT waits for next DTIM beacon despite more_data bit set
        case3 = 0  # VIOLATION: DUT skips PS-POLL at DTIM beacon when TIM IS set
        case4 = 0  # VIOLATION: DUT sends PS-POLL at non-DTIM beacons

        # Step 4: Read and parse the captured frame data from sniffer
        filter_file = open(f'./reports/Powersave_capture.txt', 'r')
        lines = filter_file.readlines()
        for line in lines:
            frame_list.append(line.strip().split('\t'))  # Parse tab-separated frame data
        filter_file.close()

        # Step 5: Prepare frame list for processing (remove last 10 frames for stability)
        no_of_filtered_packets = len(frame_list)
        if no_of_filtered_packets > 10:
            no_of_filtered_packets = no_of_filtered_packets - 10

        # Step 6: Find the starting point - first NULL frame with PM='1' (power save enabled)
        if no_of_filtered_packets > 1:
            for frame_number in range(no_of_filtered_packets):
                if (frame_list[frame_number][2] == str(null_frame)) and (frame_list[frame_number][4] == '1'):
                    logger().info("found Null frame with PM '1'")
                    logger().info(frame_list[frame_number])
                    frame_number = count + 1
                    break
                else:
                    count = count + 1

        while frame_number < no_of_filtered_packets:
            if frame_list[frame_number][2] == str(beacon):
                if len(frame_list[frame_number]) == 8:
                    if len(frame_list[frame_number][7]) == 10:
                        # get the assoc id from beacon frame when TIM set
                        tim_aid = int(frame_list[frame_number][7], 16)
                    else:
                        tim_aid = frame_list[frame_number][7].split(',')
                        for j in range(len(tim_aid)):
                            if int(tim_aid[j], 16) == assoc_id:
                                tim_aid = int(tim_aid[j], 16)
                if frame_list[frame_number][6] == '0' and len(frame_list[frame_number]) == 8:
                    '''Validation of ps_poll when DTIM beacon with TIM set condition'''
                    logger().info(f'{frame_list[frame_number]}: Positive scenario')
                    dtim_flag = 0  # if TIM set at DTIM beacon and it is unable to send ps_poll to retrieve the data
                    if tim_aid == assoc_id:
                        '''Comparing  the DUT assoc id from beacon with assoc id from assoc response'''
                        while 1:
                            if frame_number < no_of_filtered_packets:
                                frame_number = frame_number + 1
                            else:
                                break
                            if frame_list[frame_number][2] == str(ps_poll):
                                if dtim_flag == 1:
                                    case3 = case3 + 1
                                    logger().info(
                                        "DUT is not sending PS-POLL to retrieve the DATA at DTIM beacon even though "
                                        "TIM is set")
                                logger().info(frame_list[frame_number])
                                packet_number, failed_case, beacon_time, ps_exit_interval, ps_enable_interval, beacon_count = self.validate_pspoll_data_packet_with_more_bit_enable(
                                    frame_list, frame_number,
                                    listen_interval_time=0,
                                    current_beacon_time=0)
                                ps_enable_interval_list.append(ps_enable_interval)
                                ps_exit_interval_list.append(ps_exit_interval)
                                case2 = case2 + failed_case
                                frame_number = packet_number
                                break
                            else:
                                if frame_list[frame_number][2] == str(beacon):
                                    logger().info(frame_list[frame_number])
                                    dtim_flag = 1
                                    continue
                                else:
                                    frame_number = frame_number - 1
                                    logger().info(
                                        "On-air ps-poll miss at DTIM beacon")
                                    packet_number, failed_case, beacon_time, ps_exit_interval, ps_enable_interval, beacon_count = self.validate_pspoll_data_packet_with_more_bit_enable(
                                        frame_list, frame_number,
                                        listen_interval_time=0,
                                        current_beacon_time=0)
                                    ps_enable_interval_list.append(ps_enable_interval)
                                    ps_exit_interval_list.append(ps_exit_interval)
                                    case2 = case2 + failed_case
                                    frame_number = packet_number
                                    break
                elif frame_list[frame_number][6] != '0' and len(frame_list[frame_number]) == 8:
                    '''-ve scenario: Validation of ps_poll at non dtim beacons with TIM set condition'''
                    logger().info(f'{frame_list[frame_number]}: Negative scenario')
                    current_beacon_time = float(frame_list[frame_number][1])
                    before_beacon_time = float(frame_list[frame_number - 1][1])
                    time_diff = int((current_beacon_time - before_beacon_time) * 1000)
                    if tim_aid == assoc_id:
                        if frame_number < no_of_filtered_packets:
                            frame_number = frame_number + 1
                        else:
                            break
                        if frame_list[frame_number][2] == str(ps_poll):

                            logger().info(frame_list[frame_number])
                            if time_diff > 100:
                                '''If the time difference between before beacon and current beacon is more than 100ms
                                                                    then only we are counting as failed scenario'''
                                case4 = case4 + 1
                                logger().info("DUT is sending PS-POLL at non DTIM beacons")
                            packet_number, failed_case, beacon_time, ps_exit_interval, ps_enable_interval, beacon_count = self.validate_pspoll_data_packet_with_more_bit_enable(
                                frame_list, frame_number,
                                listen_interval_time=0,
                                current_beacon_time=0)
                            ps_enable_interval_list.append(ps_enable_interval)
                            ps_exit_interval_list.append(ps_exit_interval)
                            case2 = case2 + failed_case
                            frame_number = packet_number
                        else:
                            if frame_list[frame_number][2] != str(beacon):
                                # ps_poll_time = float(frame_list[frame_number][1])
                                # time_diff = int((beacon_time - ps_poll_time) * 1000)
                                frame_number = frame_number - 1
                                if time_diff > 100:
                                    '''If the time difference between before beacon and current beacon is more than 100ms 
                                    then only we are counting as failed scenario'''
                                    case4 = case4 + 1
                                    logger().info(
                                        "On-air ps-poll miss at non DTIM beacon")
                                packet_number, failed_case, beacon_time, ps_exit_interval, ps_enable_interval, beacon_count = self.validate_pspoll_data_packet_with_more_bit_enable(
                                    frame_list, frame_number,
                                    listen_interval_time=0,
                                    current_beacon_time=0)
                                ps_enable_interval_list.append(ps_enable_interval)
                                ps_exit_interval_list.append(ps_exit_interval)
                                case2 = case2 + failed_case
                                frame_number = packet_number
                            else:
                                frame_number = frame_number - 1
                else:
                    '''-ve scenario: Validation of ps_poll when TIM is not set condition'''
                    if len(frame_list[frame_number]) != 8:
                        beacon_time = float(frame_list[frame_number][1])
                        logger().info(frame_list[frame_number])
                        if frame_number < no_of_filtered_packets:
                            frame_number = frame_number + 1
                        else:
                            break
                        if frame_list[frame_number][2] == str(ps_poll):
                            ps_poll_time = float(frame_list[frame_number][1])
                            time_diff = int((beacon_time - ps_poll_time) * 1000)
                            logger().info(frame_list[frame_number])
                            if time_diff > 100:
                                '''If the time difference between before beacon and current beacon is more than 100ms 
                                                                    then only we are counting as failed scenario'''
                                case1 = case1 + 1
                                logger().info("DUT is sending PS-POLL even though TIM is not set")
                            packet_number, failed_case, beacon_time, ps_exit_interval, ps_enable_interval, beacon_count = self.validate_pspoll_data_packet_with_more_bit_enable(
                                frame_list, frame_number,
                                listen_interval_time=0,
                                current_beacon_time=0)
                            ps_enable_interval_list.append(ps_enable_interval)
                            ps_exit_interval_list.append(ps_exit_interval)
                            case2 = case2 + failed_case
                            frame_number = packet_number
                        else:
                            frame_number = frame_number - 1

            if frame_number < no_of_filtered_packets:
                frame_number = frame_number + 1
        return case1, case2, case3, case4, ps_exit_interval_list, ps_enable_interval_list

    def listen_interval_based_validation(self, listen_interval_period, assoc_id):
        """
        Listen Interval Based Power Save Validation Function

        Flowchart Description:
        ┌─────────────────────────────────────────────────────────┐
        │ A[Start Listen Interval Validation]                    │
        │ ↓                                                       │
        │ B[Initialize Variables:<br/>                           │
        │   - Read Powersave_capture.txt<br/>                    │
        │   - Parse frames into frame_list<br/>                  │
        │   - Calculate max_beacon = listen_interval/100<br/>    │
        │   - Initialize tracking lists and counters]           │
        │ ↓                                                       │
        │ C[Trim last 10 frames from capture]                   │
        │ ↓                                                       │
        │ D[Find first NULL frame with PM='1'<br/>              │
        │   Set as starting point]                              │
        │ ↓                                                       │
        │ E[Set first_beacon_time as reference]                 │
        │ ↓                                                       │
        │ F[Main Processing Loop: while frame_number < total]    │
        │ ↓                                                       │
        │ G{Is frame a Beacon?}                                  │
        │ ↓ Yes                                                   │
        │ H[Extract TIM info & increment beacon_count]           │
        │ ↓                                                       │
        │ I[Calculate tim_diff_bw_beacon = current_time -        │
        │   first_beacon_time]                                  │
        │ ↓                                                       │
        │ J{Is TIM set for DUT assoc_id?}                       │
        │ ↓ Yes                                                   │
        │ K{Is tim_diff within listen_interval ± 30ms?}         │
        │ ↓ Yes (Expected PS-Poll Time)                          │
        │ L[Search for PS-Poll after beacon]                    │
        │ ↓                                                       │
        │ M{PS-Poll found?}                                      │
        │ ↓ Yes                                                   │
        │ N[Record wake interval<br/>                            │
        │   Call validate_pspoll_data_packet_with_more_bit_enable] │
        │ ↓ No                                                    │
        │ O[Record missed PS-Poll scenario]                     │
        │ ↓                                                       │
        │ P{Is tim_diff outside expected range?}                 │
        │ ↓ Yes (Early/Late Wake)                                │
        │ Q[Check for PS-Poll at unexpected time]               │
        │ ↓                                                       │
        │ R{PS-Poll found at unexpected time?}                  │
        │ ↓ Yes                                                   │
        │ S[Record early/late wake scenario]                    │
        │ ↓                                                       │
        │ T{Is TIM NOT set for DUT?}                            │
        │ ↓ Yes (Negative Scenario)                              │
        │ U[Check if PS-Poll sent when TIM not set]             │
        │ ↓                                                       │
        │ V{PS-Poll found when TIM not set?}                    │
        │ ↓ Yes                                                   │
        │ W[Increment case1 & record violation]                 │
        │ ↓                                                       │
        │ X[Update timing references for next iteration]        │
        │ ↓                                                       │
        │ Y{More frames to process?}                             │
        │ ↓ No                                                    │
        │ Z[Return: dut_wake_interval_list, case1, case2,       │
        │   ps_exit_interval_list, ps_enable_interval_list]     │
        └─────────────────────────────────────────────────────────┘

        Purpose:
         - Validates listen interval based power-save functionality
         - Ensures DUT wakes up at correct listen interval timing
         - Tracks timing accuracy and protocol violations

        Key Validations:
         - DUT should wake at listen_interval ± tolerance
         - DUT should only send PS-Poll when TIM is set
         - Timing accuracy within expected beacon intervals
         - Proper handling of beacon miss scenarios

        Args:
            listen_interval_period: Expected listen interval in milliseconds
            assoc_id: Association ID of the DUT in hex format

        Returns:
            tuple: (wake_interval_list, case1_violations, case2_violations,
                   ps_exit_interval_list, ps_enable_interval_list)
        """
        # Step 1: Initialize core timing and tracking variables
        beacon_count = 0
        bmiss_listen_interval = listen_interval_period  # Handle beacon miss scenarios
        max_beacon = int(listen_interval_period) / 100  # Max beacons in one listen interval

        # Step 2: Initialize data structures for frame processing and result tracking
        frame_list = []  # Will store parsed capture frames
        dut_wake_interval = []  # Track actual DUT wake intervals
        ps_exit_interval_list = []  # Track power save exit timings
        ps_enable_interval_list = []  # Track power save enable timings
        count = 0  # Frame counter for initial positioning

        # Step 3: Setup association and frame type identifiers
        assoc_id = int(assoc_id, 16)  # Convert association ID to integer
        tim_aid = 0  # TIM association ID extracted from beacons
        beacon = int('0x0008', 16)  # Beacon frame type constant
        null_frame = int('0x0024', 16)  # Null frame type constant
        ps_poll = int('0x001a', 16)  # PS-Poll frame type constant

        # Step 4: Initialize validation case counters for different violation scenarios
        case1 = 0  # VIOLATION: DUT sends PS-POLL when TIM is NOT set for its AID
        case2 = 0  # VIOLATION: DUT waits for next LI beacon despite more_data bit set

        # Step 5: Read and parse the captured wireless frames from sniffer
        filter_file = open(f'./reports/Powersave_capture.txt', 'r')
        lines = filter_file.readlines()
        for line in lines:
            frame_list.append(line.strip().split('\t'))  # Parse tab-separated frame data
        filter_file.close()

        # Step 6: Prepare frame processing window (remove last 10 frames for stability)
        no_of_filtered_packets = len(frame_list)
        no_of_filtered_packets = no_of_filtered_packets - 10

        # Step 7: Find starting point - locate first NULL frame with PM='1' (power save mode enabled)
        for frame_number in range(no_of_filtered_packets):
            if (frame_list[frame_number][2] == str(null_frame)) and (frame_list[frame_number][4] == '1'):
                logger().info("found Null frame with PM '1'")
                logger().info(frame_list[frame_number])
                frame_number = count + 1
                break
            else:
                count = count + 1

        first_beacon_time = float(frame_list[frame_number][1])
        while frame_number < no_of_filtered_packets:
            if frame_list[frame_number][2] == str(beacon):
                logger().info(f'beacon_count={beacon_count}')
                beacon_count = beacon_count + 1
                if beacon_count == 1:
                    logger().info(frame_list[frame_number])
                '''To get the DUT assoc id from beacon frame'''
                if len(frame_list[frame_number]) == 8:
                    if len(frame_list[frame_number][7]) == 10:
                        tim_aid = int(frame_list[frame_number][7], 16)
                    else:
                        tim_aid = frame_list[frame_number][7].split(',')
                        for j in range(len(tim_aid)):
                            if int(tim_aid[j], 16) == assoc_id:
                                tim_aid = int(tim_aid[j], 16)
                current_beacon_time = float(frame_list[frame_number][1])
                tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                '''Comparison of DUT assoc id from beacon and assoc response'''
                if tim_aid == assoc_id:
                    current_beacon_time = float(frame_list[frame_number][1])
                    tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                    # logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                    '''Validation of PS-POLL at listen interval beacon with TIM set'''
                    if ((tim_diff_bw_beacon >= (listen_interval_period - 30)) and (
                            tim_diff_bw_beacon <= listen_interval_period + 30)) and len(
                        frame_list[frame_number]) == 8:
                        while 1:
                            if frame_number < no_of_filtered_packets:
                                frame_number = frame_number + 1
                                listen_interval_time = bmiss_listen_interval
                            else:
                                break
                            if frame_list[frame_number][2] == str(ps_poll):
                                current_beacon_time = float(frame_list[frame_number][1])
                                tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                                dut_wake_interval.append(tim_diff_bw_beacon)
                                logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                packet_number, failed_case, beacon_time, ps_exit_interval, ps_enable_interval, beacon_count = self.validate_pspoll_data_packet_with_more_bit_enable(
                                    frame_list, frame_number,
                                    listen_interval_period,
                                    current_beacon_time)
                                ps_enable_interval_list.append(ps_enable_interval)
                                ps_exit_interval_list.append(ps_exit_interval)
                                case2 = case2 + failed_case
                                if beacon_time == current_beacon_time:
                                    first_beacon_time = current_beacon_time
                                else:
                                    first_beacon_time = beacon_time
                                    listen_interval_time = bmiss_listen_interval - beacon_count * 100
                                    logger().info(
                                        f'listen_interval_time_validate_pspoll_data_packet_with_more_bit_enable={listen_interval_time}')
                                    tim_diff_bw_beacon = 0
                                frame_number = packet_number
                                break
                            else:
                                if frame_list[frame_number][2] == str(beacon):
                                    current_beacon_time = float(frame_list[frame_number][1])
                                    tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                                    dut_wake_interval.append(tim_diff_bw_beacon)
                                    logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                    logger().info(
                                        "DUT wake at more than the LI beacon-tb")
                                    continue
                                else:
                                    frame_number = frame_number - 1
                                    tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                                    dut_wake_interval.append(tim_diff_bw_beacon)
                                    logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                    logger().info(
                                        "On-air ps-poll miss at LI beacon-time difference")
                                    packet_number, failed_case, beacon_time, ps_exit_interval, ps_enable_interval, beacon_count = self.validate_pspoll_data_packet_with_more_bit_enable(
                                        frame_list, frame_number,
                                        listen_interval_period,
                                        current_beacon_time)
                                    ps_enable_interval_list.append(ps_enable_interval)
                                    ps_exit_interval_list.append(ps_exit_interval)
                                    case2 = case2 + failed_case
                                    if beacon_time == current_beacon_time:
                                        first_beacon_time = current_beacon_time
                                    else:
                                        first_beacon_time = beacon_time
                                        listen_interval_time = bmiss_listen_interval - beacon_count * 100
                                        logger().info(
                                            f'listen_interval_time_validate_pspoll_data_packet_with_more_bit_enable={listen_interval_time}')
                                        tim_diff_bw_beacon = 0
                                    frame_number = packet_number
                                    break
                        beacon_count = 0
                        tim_aid = 0
                    else:
                        if frame_number < no_of_filtered_packets:
                            frame_number = frame_number + 1
                            if frame_list[frame_number][2] == str(ps_poll):
                                beacon_count = 0
                                tim_aid = 0
                                current_beacon_time = float(frame_list[frame_number][1])
                                tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                                dut_wake_interval.append(tim_diff_bw_beacon)
                                logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                # logger().info("DUT is sending PS-POLL at before/after LI beacon-time-difference")
                                packet_number, failed_case, beacon_time, ps_exit_interval, ps_enable_interval, beacon_count = self.validate_pspoll_data_packet_with_more_bit_enable(
                                    frame_list, frame_number,
                                    listen_interval_period,
                                    current_beacon_time)
                                ps_enable_interval_list.append(ps_enable_interval)
                                ps_exit_interval_list.append(ps_exit_interval)
                                case2 = case2 + failed_case
                                if beacon_time == current_beacon_time:
                                    first_beacon_time = current_beacon_time
                                else:
                                    first_beacon_time = beacon_time
                                    listen_interval_time = bmiss_listen_interval - beacon_count * 100
                                    logger().info(
                                        f'listen_interval_time_validate_pspoll_data_packet_with_more_bit_enable={listen_interval_time}')
                                    tim_diff_bw_beacon = 0
                                frame_number = packet_number
                            else:
                                if frame_list[frame_number][2] != str(beacon):
                                    beacon_count = 0
                                    tim_aid = 0
                                    dut_wake_interval.append(tim_diff_bw_beacon)
                                    logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                    logger().info(
                                        "DUT is waking at before LI beacon-time-difference & on-air ps-poll miss ")
                                    packet_number, failed_case, beacon_time, ps_exit_interval, ps_enable_interval, beacon_count = self.validate_pspoll_data_packet_with_more_bit_enable(
                                        frame_list, frame_number,
                                        listen_interval_period,
                                        current_beacon_time)
                                    ps_enable_interval_list.append(ps_enable_interval)
                                    ps_exit_interval_list.append(ps_exit_interval)
                                    case2 = case2 + failed_case
                                    if beacon_time == current_beacon_time:
                                        first_beacon_time = current_beacon_time
                                    else:
                                        first_beacon_time = beacon_time
                                        listen_interval_time = bmiss_listen_interval - beacon_count * 100
                                        logger().info(
                                            f'listen_interval_time_validate_pspoll_data_packet_with_more_bit_enable={listen_interval_time}')
                                        tim_diff_bw_beacon = 0
                                    frame_number = packet_number
                                else:
                                    frame_number = frame_number - 1
                else:
                    '''Validation of -ve scenario where DUT is sending ps-poll even though TIM is not set'''
                    if frame_number < no_of_filtered_packets:
                        frame_number = frame_number + 1
                    else:
                        break
                    if frame_list[frame_number][2] == str(ps_poll):
                        beacon_count = 0
                        current_beacon_time = float(frame_list[frame_number][1])
                        tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                        dut_wake_interval.append(tim_diff_bw_beacon)
                        logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                        logger().info("DUT is sending PS-POLL even though tim is not set")
                        case1 = case1 + 1
                        packet_number, failed_case, beacon_time, ps_exit_interval, ps_enable_interval, beacon_count = self.validate_pspoll_data_packet_with_more_bit_enable(
                            frame_list, frame_number,
                            listen_interval_period,
                            current_beacon_time)
                        ps_enable_interval_list.append(ps_enable_interval)
                        ps_exit_interval_list.append(ps_exit_interval)
                        case2 = case2 + failed_case
                        if beacon_time == current_beacon_time:
                            first_beacon_time = current_beacon_time
                        else:
                            first_beacon_time = beacon_time
                            listen_interval_time = bmiss_listen_interval - beacon_count * 100
                            logger().info(
                                f'listen_interval_time_validate_pspoll_data_packet_with_more_bit_enable={listen_interval_time}')
                            tim_diff_bw_beacon = 0
                        frame_number = packet_number
                    else:
                        frame_number = frame_number - 1
            else:
                if (frame_list[frame_number][2] == str(null_frame)) and (
                        (frame_list[frame_number][4] == '1') and (frame_list[frame_number][3] == '1')):
                    logger().info("found Retried Null frame with PM '1'")
                    first_beacon_time = float(frame_list[frame_number][1])
                frame_number = frame_number + 1
                continue
            if frame_number < no_of_filtered_packets:
                '''We are setting to zero for 1st beacon time and beacon count incase of TIM not set at Listen interval time'''
                current_beacon_time = float(frame_list[frame_number][1])
                tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                if tim_diff_bw_beacon >= listen_interval_period:
                    beacon_count = int(tim_diff_bw_beacon / 100)
                    if (beacon_count > max_beacon):
                        listen_interval_time = bmiss_listen_interval - (beacon_count - max_beacon) * 100
                        logger().info(f'listen_interval_time_lastbmiss={listen_interval_time}')

                    else:
                        listen_interval_time = bmiss_listen_interval
                        logger().info(f'listen_interval_time={listen_interval_time}')
                    first_beacon_time = current_beacon_time
                    beacon_count = 0
                frame_number = frame_number + 1
        return dut_wake_interval, case1, case2, ps_exit_interval_list, ps_enable_interval_list

    def ping_to_dut(self, dut_ip, ping_count=10):
        logger().info("Pinging to DUT")
        status = ping(dut_ip, ping_count)
        assert status, "Failed to ping to DUT"
        return status


@pytest.mark.skip("Test case marked as manual")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.test_src_map_id('C19678')
def test_wifi_sdk_max_psp_ulp_c19678(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter, sl_collections,
                                     request, utf_constants, wifi_client, net_perf_client, protocol):
    time_delta_for_listen_interval = 1100
    test_name = request.node.name
    test_case_no = 19678
    time_period = utf_constants.get("time_period")
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'

    '''Validate listen interval from DUT side, DUT should wake up and send data after 12 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '2'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client,
                          protocol=protocol)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info('\n\n Time sleep ! Wait for 60 seconds......')
        time.sleep(60)
        wifi_sniffer.interfaces.capture.stop_capture()

        #  DUT Assoc ID from Assoc resp frame in sniffer
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter10)[
            'packet_count']

        time.sleep(5)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        # Power save mode 1
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        da_addr=ap_bssid,
                                                                                        filter_name='power_mgmt_bit')
        logger().info(f'\n\n *** FILTER 3 ={packet_filter3} *** \n')

        # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive
        # beacon packets)
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (ta_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name='ps_poll_delta')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find PM bit 1 in packets'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter11)[
            'packet_count'], 'Unable to find PS-Poll packet'

        time.sleep(5)
        # Validate the time delta between PS-poll packet
        ps_poll_packets_time_delta_list = ps_poll_time_delta_obj.delta_between_ps_poll_packet()
        logger().info(ps_poll_packets_time_delta_list)

        # Validate the time delta between PS-poll packet
        assert ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list,
                                                          time_delta_for_listen_interval)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip("Test case marked as manual")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.test_src_map_id('C19679')
def test_wifi_sdk_maxpsp_listen_interval_11ms_c19679(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                                     sl_collections, request, utf_constants, wifi_client,
                                                     net_perf_client, protocol):
    test_name = request.node.name
    test_case_no = 19679
    time_period = utf_constants.get("time_period")
    time_delta_for_listen_interval = 1100
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'
    list_status = []
    '''Verify whether RSI_STA is wake up and receive data based on configured listen interval when enable power save
       2 & MAX PSP mode and set listen_interval_dtim is 0'''
    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    time.sleep(5)
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client,
                          protocol=protocol)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()
        # Assoc resp frame in sniffer
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter10)[
            'packet_count']

        time.sleep(5)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.
        # (for manual QA ref.)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_bssid, association_id=association_id,
            filter_name='beacon_assoc_id_ps_poll_with_pm_bit_enable_assoc_id')

        logger().info(f'\n\n *** FILTER 3 ={packet_filter3} *** \n')

        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (ta_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name='ps_poll_delta')
        logger().info(f'\n\n *** FILTER 4 ={packet_filter4} *** \n')

        # Applying PS-poll filter to find the time delta between 2 PS-poll packets(in between 12 consecutive
        # beacon packets)
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count']
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter11)[
            'packet_count']

        # Validate the time delta between PS-poll packet
        ps_poll_packets_time_delta_list = ps_poll_time_delta_obj.delta_between_ps_poll_packet()
        logger().info(ps_poll_packets_time_delta_list)

        # Validate the time delta between PS-poll packet
        assert ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list,
                                                          time_delta_for_listen_interval)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip("Test case marked as manual")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.test_src_map_id('C19680')
def test_wifi_sdk_max_psp_dtim_3_c19680(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter, sl_collections,
                                        request, utf_constants):
    test_name = request.node.name
    test_case_no = 19680
    time_period = utf_constants.get("time_period")
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'
    packet_filter10 = '    Type/Subtype: Association Response (0x0001)'
    ps_packet_exchange_obj = FilterPacket()
    assoc_obj = FilterPacket()

    '''Configure the AP DTIM count=3 and validate when DTIM count reach 0 DUT should wake up and send PS poll & data
    packet, second validation is check Qos data will send again after Ps-Poll if More data bit is set to 1'''
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.start_ap()

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()

        # Assoc resp frame in sniffer
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter10)[
            'packet_count']

        time.sleep(5)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable -> Qos
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            association_id=association_id,
            filter_name='beacon_assoc_id_ps_poll_with_pm_bit_enable_qos_dtim_3')

        # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            da_addr=ap_bssid, filter_name='beacon_assoc_id_dtim_count_ps_poll_with_pm_bit_enable')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count'], 'Unable to find any packet from beacon with association-id and PS-poll packet'

        # Validate beacon DTIM count=0
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter11)[
            'packet_count'], 'Unable to find beacon DTIM count 0'

        logger().info('-----------Validation for DTIM count = 0 sequence---------------- ')
        sniffer_dict = ps_packet_exchange_obj.parse_sniffer_packets()
        assert ps_packet_exchange_obj.match_packet_sequence(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                           'Beacon(DTIM count=0)-> Ps-Poll-> Data'

        logger().info('-----------Validation for More data bit sequence---------------- ')
        sniffer_dict = ps_packet_exchange_obj.parse_sniffer_packet_more_data()
        assert ps_packet_exchange_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
            'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.test_src_map_id('C19682')
def test_wifi_sdk_max_psp_enable_disable_c19682(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                                sl_collections,
                                                request, utf_constants):
    test_name = request.node.name
    test_case_no = 19682
    count = 0
    time_period = utf_constants.get("time_period")
    '''Verify the power save mode2 functionality enable and disable while doing data transfer for overnight'''
    wifi_access_point.interfaces.wifi.config['dtim'] = '2'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    mode = 'power_save'

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, data_transfer=False)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='enable_maxpsp_C19682')

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            da_addr=ap_bssid, filter_name='power_mgmt_bit')

        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=
                                                                                        wlan_obj.dut_addr[
                                                                                            'dut_mac_address'],
                                                                                        da_addr=ap_bssid,
                                                                                        filter_name='power_mgmt_bit_disable')
        end_time = time_period
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        sw = Stopwatch()
        while sw.elapsed_sec < end_time:
            logger().info(f"\n\n EL time = {sw.elapsed_sec}, END time = {end_time} *\n")
            logger().info(f"\n\n *****Enable Max PSP in DUT******\n")
            logger().info(f"....Applying performance profile mode : {mode}")
            wifi_dut.interfaces.wifi.set_performance_profile(mode=mode, monitor_interval=50)
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            status = ping(device_ip, 20, size=300)
            assert status == 1

            '''Disable the Power save mode'''
            time.sleep(10)
            logger().info(f"\n\n *****Disable Max PSP in DUT******\n")
            wifi_dut.interfaces.wifi.set_performance_profile(mode="high_performance")
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            time.sleep(25)
            status = ping(device_ip, 20, size=300)
            assert status == 1
            count = count + 1
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'No packet found for pwmt bit enable'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count'], 'No packet found for pwmt bit disable'
        logger().info(f"\n\n *** NO of iteration = {count}\n\n")

    except Exception as e:
        logger().info(f"\n\n *** NO of iteration = {count}\n\n")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C19693')
def test_wifi_sdk_enhanced_max_psp_ulp_c19693(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                              sl_collections, request, utf_constants, wifi_client, net_perf_client):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19693
    listen_interval = 1000
    monitor_interval = 50
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    validation = True
    powersave_validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'

    '''Verify the DUT functionality when ULP POWER SAVE MODE 2,Enhanced MAX PSP and LISTEN INTERVAL based power
    save feature enabled.'''
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"***** Enabling Max PSP in DUT ******")
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
                                                         dtim_aligned_type=0,
                                                         num_of_dtim_skip=0,
                                                         listen_interval=listen_interval,
                                                         monitor_interval=monitor_interval)
        time.sleep(2)
        logger().info("Pinging to DUT to with byte size 300")
        status = sl_collections.ping_with_custom_size(wlan_obj.dut_addr["device_ip"], ping_counts=60, byte_size=300)
        time.sleep(10)
        status = sl_collections.ping_with_custom_size(wlan_obj.dut_addr["device_ip"], ping_counts=60, byte_size=300)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        dut_mac_address = wlan_obj.dut_addr['dut_mac_address']
        # Assoc resp frame in sniffer to get the DUT assoc id
        packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(1)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        packet_filter2 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) &&' \
                         f' (wlan.da == {ap_bssid}))'

        packet_filter3 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                         f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                         f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                         f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
        assert \
            wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, None, powersave_validation)[
                'packet_count']
        ps_poll_packets_time_delta_list, case1, case2, ps_exit_interval, ps_enable_interval = ps_poll_time_delta_obj.listen_interval_based_validation(
            listen_interval,
            association_id)
        case3 = ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list, listen_interval)
        case4, case5 = ps_poll_time_delta_obj.validation_of_enh_max_psp(ps_exit_interval, ps_enable_interval,
                                                                        monitor_interval)
        if case1 != 0:
            logger().info(
                f'Observed {case1} times DUT is sending PS-POLL to retrieve the data even though TIM is not set')
        if case2 != 0:
            logger().info(
                f'Observed {case2} times DUT is sending the PS-POLL to retrieve the data after post listen interval beacon only even though more data bit is set')
        if case3 != 0:
            logger().info(
                f'Observed {case3} times DUT is unable to send PS-POLL at listen interval')
        if case4 != 0:
            logger().info(
                f'Observed {case4} times DUT is unable to exit from powersave at 20ms')
        if case5 != 0:
            logger().info(
                f'Observed {case5} times DUT is unable to enable from powersave afer there is no data from {monitor_interval}ms')
        if case1 > 12 or case3 > 12 or case2 != 0 or case4 != 0 or case5 != 0:
            assert False
        else:
            assert True, "DUT is sending PS-POLL to retrieve the data at Listen interval beacon only"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C19694')
def test_wifi_sdk_enhanced_max_psp_c19694(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                          sl_collections, request, utf_constants, wifi_client, net_perf_client):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19694
    mode = 'power_save'
    monitor_interval = 50
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    validation = True
    powersave_validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'

    '''Verify the DUT functionality when ULP POWER SAVE MODE 2,Enhanced MAX PSP and DTIM based power
    save feature enabled.'''
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"***** Enabling Max PSP in DUT ******")
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
                                                         dtim_aligned_type=0,
                                                         num_of_dtim_skip=0,
                                                         listen_interval=0,
                                                         monitor_interval=50)

        time.sleep(2)
        logger().info("Pinging to DUT to with byte size 300")
        status = sl_collections.ping_with_custom_size(wlan_obj.dut_addr["device_ip"], ping_counts=60, byte_size=300)
        time.sleep(10)
        status = sl_collections.ping_with_custom_size(wlan_obj.dut_addr["device_ip"], ping_counts=60, byte_size=300)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        dut_mac_address = wlan_obj.dut_addr['dut_mac_address']
        # Assoc resp frame in sniffer to get the DUT assoc id
        packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(1)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        packet_filter2 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) &&' \
                         f' (wlan.da == {ap_bssid}))'

        packet_filter3 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                         f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                         f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                         f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
        assert \
            wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, None, powersave_validation)[
                'packet_count']

        case1, case2, case3, case4, ps_exit_interval, ps_enable_interval = ps_poll_time_delta_obj.dtim_based_validation(
            association_id)
        case5, case6 = ps_poll_time_delta_obj.validation_of_enh_max_psp(ps_exit_interval, ps_enable_interval,
                                                                        monitor_interval)
        if case1: logger().info(
            f'Observed {case1} times DUT is sending PS-POLL to retrieve the data even though TIM is not set')
        if case2: logger().info(
            f'Observed {case2} times DUT is sending PS-POLL at next DTIM beacon even though more data bit set')
        if case3: logger().info(
            f'Observed {case3} times DUT is not sending PS-POLL at DTIM beacon even though TIM is set')
        if case4: logger().info(
            f'Observed {case4} times DUT is sending PS-POLL at non-DTIM beacons')
        if case5 != 0:
            logger().info(
                f'Observed {case5} times DUT is unable to exit from powersave at 20ms')
        if case6 != 0:
            logger().info(
                f'Observed {case6} times DUT is unable to enable from powersave afer there is no data from {monitor_interval}ms')
        if case1 > 6 or case3 > 6 or case4 > 6 or case2 != 0 or case5 != 0 or case6 != 0:
            assert False
        else:
            assert True, "DUT is sending PS-POLL to retrieve the data at DTIM beacon only"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C19695')
def test_wifi_sdk_enhanced_max_psp_ulp_c19695(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                              sl_collections, request, utf_constants, wifi_client, net_perf_client):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19695
    mode = 'power_save'
    listen_interval = 1100
    monitor_interval = 70
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    validation = True
    powersave_validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'

    '''Verify the DUT functionality when ULP POWER SAVE MODE 2, Enhanced MAX PSP with monitor interval 70 and LISTEN
       INTERVAL based power save features are enabled.(TC_2).			'''
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"***** Enabling Max PSP in DUT ******")
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
                                                         dtim_aligned_type=0,
                                                         num_of_dtim_skip=0,
                                                         listen_interval=listen_interval,
                                                         monitor_interval=monitor_interval)
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        time.sleep(5)
        for i in range(0, 2):
            sl_collections.run_traffic(
                wifi_dut=wifi_dut,
                net_perf_client=net_perf_client,
                protocol='TCP',
                device_ip=wlan_obj.dut_addr["device_ip"],
                host_ip=host_ip,
                timeout=60,
                traffic_type="TX",
            )
            time.sleep(5)

        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        dut_mac_address = wlan_obj.dut_addr['dut_mac_address']
        # Assoc resp frame in sniffer to get the DUT assoc id
        packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(1)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        packet_filter2 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) &&' \
                         f' (wlan.da == {ap_bssid}))'

        packet_filter3 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                         f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                         f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                         f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
        assert \
            wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, None, powersave_validation)[
                'packet_count']
        ps_poll_packets_time_delta_list, case1, case2, ps_exit_interval, ps_enable_interval = ps_poll_time_delta_obj.listen_interval_based_validation(
            listen_interval,
            association_id)
        case3 = ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list, listen_interval)
        case4, case5 = ps_poll_time_delta_obj.validation_of_enh_max_psp(ps_exit_interval, ps_enable_interval,
                                                                        monitor_interval)
        if case1 != 0:
            logger().info(
                f'Observed {case1} times DUT is sending PS-POLL to retrieve the data even though TIM is not set')
        if case2 != 0:
            logger().info(
                f'Observed {case2} times DUT is sending the PS-POLL to retrieve the data after post listen interval beacon only even though more data bit is set')
        if case3 != 0:
            logger().info(
                f'Observed {case3} times DUT is unable to send PS-POLL at listen interval')
        if case4 != 0:
            logger().info(
                f'Observed {case4} times DUT is unable to exit from powersave at 20ms')
        if case5 != 0:
            logger().info(
                f'Observed {case5} times DUT is unable to enable from powersave afer there is no data from {monitor_interval}ms')
        if case1 > 6 or case3 > 6 or case2 != 0 or case4 != 0 or case5 != 0:
            assert False
        else:
            assert True, "DUT is sending PS-POLL to retrieve the data at Listen interval beacon only"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C19696')
def test_wifi_sdk_enhanced_max_psp_ulp_c19696(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                              sl_collections, request, utf_constants, wifi_client, net_perf_client):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19696
    mode = 'power_save'
    listen_interval = 1200
    monitor_interval = 100
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    validation = True
    powersave_validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'

    '''Verify the DUT functionality when ULP POWER SAVE MODE 2, Enhanced MAX PSP with monitor interval 100 and LISTEN
       INTERVAL based power save features are enabled.(TC_2).			'''
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"***** Enabling Max PSP in DUT ******")
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
                                                         dtim_aligned_type=0,
                                                         num_of_dtim_skip=0,
                                                         listen_interval=listen_interval,
                                                         monitor_interval=monitor_interval)
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        time.sleep(5)
        for i in range(0, 2):
            sl_collections.run_traffic(
                wifi_dut=wifi_dut,
                net_perf_client=net_perf_client,
                protocol='TCP',
                device_ip=wlan_obj.dut_addr["device_ip"],
                host_ip=host_ip,
                timeout=60,
                traffic_type="TX",
            )
            time.sleep(2)

        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        dut_mac_address = wlan_obj.dut_addr['dut_mac_address']
        # Assoc resp frame in sniffer to get the DUT assoc id
        packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(1)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        packet_filter2 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) &&' \
                         f' (wlan.da == {ap_bssid}))'

        packet_filter3 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                         f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                         f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                         f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
        assert \
            wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, None, powersave_validation)[
                'packet_count']
        ps_poll_packets_time_delta_list, case1, case2, ps_exit_interval, ps_enable_interval = ps_poll_time_delta_obj.listen_interval_based_validation(
            listen_interval,
            association_id)
        case3 = ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list, listen_interval)
        case4, case5 = ps_poll_time_delta_obj.validation_of_enh_max_psp(ps_exit_interval, ps_enable_interval,
                                                                        monitor_interval)
        if case1 != 0:
            logger().info(
                f'Observed {case1} times DUT is sending PS-POLL to retrieve the data even though TIM is not set')
        if case2 != 0:
            logger().info(
                f'Observed {case2} times DUT is sending the PS-POLL to retrieve the data after post listen interval beacon only even though more data bit is set')
        if case3 != 0:
            logger().info(
                f'Observed {case3} times DUT is unable to send PS-POLL at listen interval')
        if case4 != 0:
            logger().info(
                f'Observed {case4} times DUT is unable to exit from powersave at 20ms')
        if case5 != 0:
            logger().info(
                f'Observed {case5} times DUT is unable to enable from powersave afer there is no data from {monitor_interval}ms')
        if case1 > 6 or case3 > 3 or case2 != 0 or case4 != 0 or case5 != 0:
            assert False
        else:
            assert True, "DUT is sending PS-POLL to retrieve the data at Listen interval beacon only"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C19697')
def test_wifi_sdk_enhanced_max_psp_ulp_c19697(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                              sl_collections, request, utf_constants, wifi_client, net_perf_client):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19697
    mode = 'power_save'
    listen_interval = 600
    monitor_interval = 50
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    validation = True
    powersave_validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'

    '''Verify the functionality of DUT when ULP POWER SAVE MODE 2, FAST PSP and listen interval is changed in power
       save command to 600 msec'''
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"***** Enabling Max PSP in DUT ******")
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
                                                         dtim_aligned_type=0,
                                                         num_of_dtim_skip=0,
                                                         listen_interval=listen_interval,
                                                         monitor_interval=monitor_interval)
        time.sleep(2)
        logger().info("Pinging to DUT to with byte size 300")
        status = sl_collections.ping_with_custom_size(wlan_obj.dut_addr["device_ip"], ping_counts=60, byte_size=300)
        assert status, "DUT is not responding to ping request after powersave"
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        dut_mac_address = wlan_obj.dut_addr['dut_mac_address']
        # Assoc resp frame in sniffer to get the DUT assoc id
        packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(1)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        packet_filter2 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) &&' \
                         f' (wlan.da == {ap_bssid}))'

        packet_filter3 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                         f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                         f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                         f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
        assert \
            wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, None, powersave_validation)[
                'packet_count']
        ps_poll_packets_time_delta_list, case1, case2, ps_exit_interval, ps_enable_interval = ps_poll_time_delta_obj.listen_interval_based_validation(
            listen_interval,
            association_id)
        case3 = ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list, listen_interval)
        case4, case5 = ps_poll_time_delta_obj.validation_of_enh_max_psp(ps_exit_interval, ps_enable_interval,
                                                                        monitor_interval)
        if case1 != 0:
            logger().info(
                f'Observed {case1} times DUT is sending PS-POLL to retrieve the data even though TIM is not set')
        if case2 != 0:
            logger().info(
                f'Observed {case2} times DUT is sending the PS-POLL to retrieve the data after post listen interval beacon only even though more data bit is set')
        if case3 != 0:
            logger().info(
                f'Observed {case3} times DUT is unable to send PS-POLL at listen interval')
        if case4 != 0:
            logger().info(
                f'Observed {case4} times DUT is unable to exit from powersave at 20ms')
        if case5 != 0:
            logger().info(
                f'Observed {case5} times DUT is unable to enable from powersave afer there is no data from {monitor_interval}ms')
        if case1 > 3 or case3 > 3 or case2 != 0 or case4 != 0 or case5 != 0:
            assert False
        else:
            assert True, "DUT is sending PS-POLL to retrieve the data at Listen interval beacon only"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.test_src_map_id('C19698')
def test_wifi_sdk_max_psp_enable_disable_c19698(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                                sl_collections, request, utf_constants, wifi_client, net_perf_client):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19698
    mode = 'power_save'
    count = 0
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'

    '''Verify the power save mode2 functionality enable and disable while doing data transfer for overnight'''
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        # Power save mode 1
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (sa_addr=wlan_obj.dut_addr['dut_mac_address'],
             da_addr=ap_bssid, filter_name='power_mgmt_bit')

        # Power save mode 0
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (sa_addr=wlan_obj.dut_addr['dut_mac_address'],
             da_addr=ap_bssid, filter_name='power_mgmt_bit_disable')

        wifi_sniffer.interfaces.capture.start_capture(capture_file='enhance_maxpsp_C19698')

        end_time = 300
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        sw = Stopwatch()
        while sw.elapsed_sec < end_time:
            logger().info(f"\n\n *****Enable Max PSP in DUT******\n")
            wifi_dut.interfaces.wifi.set_performance_profile(mode=mode)
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            status = ping(device_ip, 20)
            assert status == 1

            '''Disable the Power save mode'''
            time.sleep(100)
            logger().info(f"\n\n *****Disable Max PSP in DUT******\n")
            wifi_dut.interfaces.wifi.set_performance_profile(mode="high_performance")
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            time.sleep(50)
            status = ping(device_ip, 20)
            assert status == 1
            count = count + 1
        logger().info(f"\n\n *** NO of iteration = {count}\n\n")
    except Exception as e:
        logger().info(f"\n\n *** NO of iteration = {count}\n\n")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'No packet found for pwmt bit enable'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count'], 'No packet found for pwmt bit disable'


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C19699')
def test_wifi_sdk_enhanced_max_psp_ulp_c19699(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                              sl_collections, request, utf_constants, wifi_client, net_perf_client):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19699
    mode = 'power_save'
    listen_interval = 1000
    monitor_interval = 50
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    validation = True
    powersave_validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'

    '''Note - Please use preconfigured different AP's, with same ssid as you mentioned in Harness file
       Netgear WNR1000,TP-LINK(TL-WDR5620),ASUS-LYRA, Xfinity XB3 ,Xfinity XB6 & Belkin AP'''

    '''Verify whether DUT is waked up before the nearest Beacon that does not exceed the specified listen interval
       time, Retrieving the buffered data by sending PS-POLL for every packet if AP sends data within 20msec of sending 
       PS-POLL(IOP)'''

    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"***** Enabling Max PSP in DUT ******")
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
                                                         dtim_aligned_type=0,
                                                         num_of_dtim_skip=0,
                                                         listen_interval=listen_interval,
                                                         monitor_interval=monitor_interval)
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        time.sleep(5)
        for i in range(0, 3):
            sl_collections.run_traffic(
                wifi_dut=wifi_dut,
                net_perf_client=net_perf_client,
                protocol='TCP',
                device_ip=wlan_obj.dut_addr["device_ip"],
                host_ip=host_ip,
                timeout=30,
                traffic_type="RX",
            )
            time.sleep(2)

        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        dut_mac_address = wlan_obj.dut_addr['dut_mac_address']
        # Assoc resp frame in sniffer to get the DUT assoc id
        packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(1)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        packet_filter2 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) &&' \
                         f' (wlan.da == {ap_bssid}))'

        packet_filter3 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                         f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                         f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                         f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
        assert \
            wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, None, powersave_validation)[
                'packet_count']
        ps_poll_packets_time_delta_list, case1, case2, ps_exit_interval, ps_enable_interval = ps_poll_time_delta_obj.listen_interval_based_validation(
            listen_interval,
            association_id)
        case3 = ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list, listen_interval)
        case4, case5 = ps_poll_time_delta_obj.validation_of_enh_max_psp(ps_exit_interval, ps_enable_interval,
                                                                        monitor_interval)
        if case1 != 0:
            logger().info(
                f'Observed {case1} times DUT is sending PS-POLL to retrieve the data even though TIM is not set')
        if case2 != 0:
            logger().info(
                f'Observed {case2} times DUT is sending the PS-POLL to retrieve the data after post listen interval beacon only even though more data bit is set')
        if case3 != 0:
            logger().info(
                f'Observed {case3} times DUT is unable to send PS-POLL at listen interval')
        if case4 != 0:
            logger().info(
                f'Observed {case4} times DUT is unable to exit from powersave at 20ms')
        if case5 != 0:
            logger().info(
                f'Observed {case5} times DUT is unable to enable from powersave afer there is no data from {monitor_interval}ms')
        if case1 > 9 or case3 > 9 or case2 != 0 or case4 != 0 or case5 != 0:
            assert False
        else:
            assert True, "DUT is sending PS-POLL to retrieve the data at Listen interval beacon only"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip("Test case marked as manual")
@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.test_src_map_id('C19700')
def test_wifi_sdk_enhanced_max_psp_with_diff_traffic_c19700(wifi_sniffer, wifi_access_point, wifi_dut, net_perf_client,
                                                            protocol, sniffer_filter, sl_collections, wifi_client,
                                                            request,
                                                            utf_constants):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19700
    frame_exchange_obj = FilterPacket()
    packet_filter2 = '    Type/Subtype: Power-Save poll (0x001a)'

    '''Verify the functionality of DUT ,when ULP POWER SAVE MODE 2, FAST PSP and LISTEN INTERVAL based power save
     features are enabled when traffic is being run from different stations with different traffic streams'''

    '''Verify whether DUT is waked up before the nearest Beacon that does not exceed the specified listen interval
       time, Retrieving the buffered data by sending PS-POLL for every packet'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, data_transfer=False, net_perf_client=net_perf_client,
                          wifi_client=wifi_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        # validate data(0x28), Null(0x24), PS-Poll(0x0A), Beacon(0x08), Qos NUll data(0x002c)
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        wlan_addr=ap_bssid,
                                                                                        filter_name='coex_enhanced_max_psp_34469')

        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2)[
            'packet_count']

        logger().info(
            '---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = frame_exchange_obj.parse_sniffer_packet_for_max_psp_95()
        result = frame_exchange_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                               'Beacon(DTIM count 0)->PS-POLL->Qos data ' \
                                                                               'packet '

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1 data '
                'packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference------------- ')
            sniffer_dict = frame_exchange_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert frame_exchange_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict), 'No sequence found for sniffer packets ' \
                               'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info(
                f'***** Validation of Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & Qos Data '
                f'packet time difference passed successfully *****')
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip("Test case marked as manual")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.test_src_map_id('C19703')
def test_wifi_sdk_enhanced_max_psp_with_high_data_rate_c19703(wifi_sniffer, wifi_access_point, wifi_dut,
                                                              sniffer_filter, sl_collections, request, utf_constants,
                                                              wifi_client, net_perf_client):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19703
    frame_exchange_obj = FilterPacket()
    assoc_obj = FilterPacket()
    packet_filter10 = '    Type/Subtype: Association Response (0x0001)'
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'

    '''Verify whether DUT is able to wake up and receive Data based on listen interval with high data rates in power
      save 2 and ULP1, Listen interval based with Enhanced MAX PSP'''

    '''Verify whether DUT is waked up before the nearest Beacon that does not exceed the specified listen interval
       time, Retrieving the buffered data by sending PS-POLL for every packet'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info('\n\n Time sleep ! Wait for 200 seconds......')
        time.sleep(200)

        # Assoc resp frame in sniffer
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')

        wifi_sniffer.interfaces.capture.stop_capture()

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(5)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        # Validation for High data rates from DUT side
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name='radio_mcs_index_7')

        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        wlan_addr=ap_bssid,
                                                                                        filter_name='coex_enhanced_max_psp_34469')

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.
        # (for manual QA ref.)
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_bssid,
                                                                                        association_id=association_id,
                                                                                        filter_name='beacon_assoc_id_ps_poll_with_pm_bit_enable_assoc_id')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'Unable to find beacon with association-id and PS-poll packet with pm bit enable'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find  High data rates packets from DUT side'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter11)['packet_count'] \
            , 'Unable to find data(0x28), Null(0x24), PS-Poll(0x0A), Beacon(0x08), Qos NUll data(0x002c)'

        logger().info('---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence----------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = frame_exchange_obj.parse_sniffer_packet_for_max_psp_95()
        result = frame_exchange_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                               'Beacon(DTIM count 0)->PS-POLL->Qos data packet'

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1 data '
                'packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference------------- ')
            sniffer_dict = frame_exchange_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert frame_exchange_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict), 'No sequence found for sniffer packets ' \
                               'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info(
                f'***** Validation of Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & Qos Data '
                f'packet time difference passed successfully *****')
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip("Test case marked as manual")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.test_src_map_id('C19704')
def test_wifi_sdk_enhanced_max_psp_with_ulp_mode_dtim_c19704(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                                             sl_collections, wifi_client, net_perf_client,
                                                             request, utf_constants):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19704
    frame_exchange_obj = FilterPacket()
    assoc_obj = FilterPacket()
    packet_filter10 = '    Type/Subtype: Association Response (0x0001)'
    packet_filter11 = '    Type/Subtype: Power-Save poll (0x001a)'

    '''Verify whether DUT is able to wake up and receive Data based on DTIM beacon with power save mode2 and ULP mode &
       DTIM Based and Enhanced MAX PSP'''

    '''Verify whether DUT is waked up before the nearest Beacon that does not exceed the specified listen interval
       time, Retrieving the buffered data by sending PS-POLL for every packet'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info('\n\n Time sleep ! Wait for 200 seconds......')
        time.sleep(200)
        wifi_sniffer.interfaces.capture.stop_capture()

        # Assoc resp frame in sniffer
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            da_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='association_response')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(5)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable.
        # (for manual QA ref.)
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_bssid,
                                                                                        association_id=association_id,
                                                                                        filter_name='beacon_assoc_id_ps_poll_with_pm_bit_enable_assoc_id')

        # Validation for High data rates from DUT side
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name='radio_mcs_index_7')

        # validate data(0x28), Null(0x24), PS-Poll(0x0A), Beacon(0x08), Qos NUll data(0x002c)
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        wlan_addr=ap_bssid,
                                                                                        filter_name='coex_enhanced_max_psp_34469')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count']
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count']
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4,
                                                                  packet_filter2=packet_filter11)[
            'packet_count']

        logger().info(
            '---------1. Validation for Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence-------------- ')
        logger().info('-----------2. Validation for PS-Poll & Qos Data packet time difference---------------- ')
        sniffer_dict = frame_exchange_obj.parse_sniffer_packet_for_max_psp_95()
        result = frame_exchange_obj.validate_packet_for_max_psp(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                               'Beacon(DTIM count 0)->PS-POLL->Qos data packet'

        if result is False:
            logger().info(
                '---------1. Validation for PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1 data '
                'packet sequence-------------- ')
            logger().info(
                '---------2. Validation for Qos Data & NULL frame with PM bit 1 packet time difference---------------- ')
            sniffer_dict = frame_exchange_obj.parse_sniffer_packet_max_psp_95_null_frame()
            assert frame_exchange_obj.validate_packet_for_max_psp_null_frame(
                sniffer_dict), 'No sequence found for sniffer packets ' \
                               'PS-POLL-> Null frame + pm bit 0 -> Qos data -> Null frame + pm bit 1'
        else:
            logger().info(
                f'***** Validation of Beacon(DTIM count 0)->PS-POLL->Qos data packet sequence & PS-Poll & Qos Data '
                f'packet time difference passed successfully *****')
            assert True
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C19705')
def test_wifi_sdk_enhanced_max_psp_listen_interval_c19705(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                                          sl_collections, request, utf_constants, wifi_client,
                                                          net_perf_client):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19705
    mode = 'power_save'
    listen_interval = 1000
    monitor_interval = 50
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    validation = True
    powersave_validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'

    '''Verify Max/ Enhanced max PSP behavior with below scenarios send data for 1 min sleep, 1 min send data for
       5 min sleep, for 2min in listen interval based and PSP mode2'''

    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"***** Enabling Max PSP in DUT ******")
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
                                                         dtim_aligned_type=0,
                                                         num_of_dtim_skip=0,
                                                         listen_interval=listen_interval,
                                                         monitor_interval=monitor_interval)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        time.sleep(5)
        for i in range(0, 4):
            if i % 2 != 0:
                time_out = 300
            else:
                time_out = 60
            sl_collections.run_traffic(
                wifi_dut=wifi_dut,
                net_perf_client=net_perf_client,
                protocol='TCP',
                device_ip=wlan_obj.dut_addr["device_ip"],
                host_ip=host_ip,
                timeout=time_out,
                traffic_type="RX",
            )
            time.sleep(time_out)

        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        dut_mac_address = wlan_obj.dut_addr['dut_mac_address']
        # Assoc resp frame in sniffer to get the DUT assoc id
        packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(1)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        packet_filter2 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) &&' \
                         f' (wlan.da == {ap_bssid}))'

        packet_filter3 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                         f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                         f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                         f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
        assert \
            wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, None, powersave_validation)[
                'packet_count']
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C19706')
def test_wifi_sdk_enhanced_max_psp_dtim_c19706(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                               sl_collections, request, utf_constants, wifi_client, net_perf_client):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19706
    mode = 'power_save'
    monitor_interval = 50
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    validation = True
    powersave_validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'

    '''Verify Max/ Enhanced max PSP behavior with below scenarios send data for 1 min sleep, 1 min send data for
       5 min sleep, for 2min in listen interval based and PSP mode2'''

    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"***** Enabling Max PSP in DUT ******")
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
                                                         dtim_aligned_type=0,
                                                         num_of_dtim_skip=0,
                                                         monitor_interval=monitor_interval)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        time.sleep(5)
        for i in range(0, 4):
            if i % 2 != 0:
                time_out = 300
            else:
                time_out = 60
            sl_collections.run_traffic(
                wifi_dut=wifi_dut,
                net_perf_client=net_perf_client,
                protocol='TCP',
                device_ip=wlan_obj.dut_addr["device_ip"],
                host_ip=host_ip,
                timeout=time_out,
                traffic_type="RX",
            )
            time.sleep(time_out)

        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        dut_mac_address = wlan_obj.dut_addr['dut_mac_address']
        # Assoc resp frame in sniffer to get the DUT assoc id
        packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(1)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        packet_filter2 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) &&' \
                         f' (wlan.da == {ap_bssid}))'

        packet_filter3 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                         f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                         f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                         f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
        assert \
            wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, None, powersave_validation)[
                'packet_count']
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C19167')
def test_wifi_sdk_maxpsp_listen_interval_11ms_c19167(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                                     sl_collections, request, wifi_client):
    test_name = request.node.name
    test_case_no = 19167

    '''Verify the power save functionality with the Power Save listen interval set to 600ms.'''

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    time.sleep(5)
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        da_addr=ap_bssid,
                                                                                        filter_name='power_mgmt_bit')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find PM bit 1 in packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.test_src_map_id('C19171')
def test_wifi_sdk_enhanced_max_psp_after_rejoin_c19171(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                                       sl_collections, request, utf_constants, wifi_client,
                                                       net_perf_client, switch):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19171
    listen_interval = 1000
    monitor_interval = 50
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    validation = True
    powersave_validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'

    '''Verify the DUT functionality after rejoined to the AP when ULP POWER SAVE MODE 2,Enhanced MAX PSP and LISTEN INTERVAL based power
    save feature enabled.'''
    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"***** Enabling Max PSP in DUT ******")
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
                                                         dtim_aligned_type=0,
                                                         num_of_dtim_skip=0,
                                                         listen_interval=listen_interval,
                                                         monitor_interval=monitor_interval)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

        time.sleep(2)

        logger().info("Pinging to DUT to with byte size 300")
        status = sl_collections.ping_with_custom_size(wlan_obj.dut_addr["device_ip"], ping_counts=20, byte_size=300)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        dut_mac_address = wlan_obj.dut_addr['dut_mac_address']
        time.sleep(2)
        for i in range(0, 2):
            if i ==1:
                wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
                wifi_sniffer.interfaces.capture.start_capture(capture_file=f'outofpower_savemode_afterrejoin')
                time.sleep(20)
                logger().info("***** Turn off Access Point *****")
                switch.interfaces.pdu_switch.turn_off(delay=10)
                logger().info("***** Turn on Access Point *****")
                switch.interfaces.pdu_switch.turn_on(delay=60)
                logger().info('******* Trying to reconnect DUT and resume data transfer **********')
                # Initiate ping from third party wifi-client to DUT
                logger().info(f"\n\n *** Initiating ping from third party wifi-client to DUT after turn "
                              f"on the AP *** \n\n")
                logger().info(f"DUT IP address: {wlan_obj.dut_addr['device_ip']}")
                logger().info("Pinging to DUT to with byte size 300")
                status = sl_collections.ping_with_custom_size(wlan_obj.dut_addr["device_ip"], ping_counts=60, byte_size=300)
                time.sleep(2)
                wifi_sniffer.interfaces.capture.stop_capture()
                # Assoc resp frame in sniffer to get the DUT assoc id
            packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
                'packet_count'], 'No packet found for Assoc resp frame'

            time.sleep(1)
            association_id = assoc_obj.get_association_id()
            if association_id is None:
                logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
                assert False
            else:
                logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

            packet_filter2 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) &&' \
                             f' (wlan.da == {ap_bssid}))'

            packet_filter3 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                             f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                             f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                             f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
            assert \
                wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, None, powersave_validation)[
                    'packet_count']
            ps_poll_packets_time_delta_list, case1, case2, ps_exit_interval, ps_enable_interval = ps_poll_time_delta_obj.listen_interval_based_validation(
                listen_interval,
                association_id)
            case3 = ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list, listen_interval)
            case4, case5 = ps_poll_time_delta_obj.validation_of_enh_max_psp(ps_exit_interval, ps_enable_interval,
                                                                            monitor_interval)
            if case1 != 0:
                logger().info(
                    f'Observed {case1} times DUT is sending PS-POLL to retrieve the data even though TIM is not set')
            if case2 != 0:
                logger().info(
                    f'Observed {case2} times DUT is sending the PS-POLL to retrieve the data after post listen interval beacon only even though more data bit is set')
            if case3 != 0:
                logger().info(
                    f'Observed {case3} times DUT is unable to send PS-POLL at listen interval')
            if case4 != 0:
                logger().info(
                    f'Observed {case4} times DUT is unable to exit from powersave at 20ms')
            if case5 != 0:
                logger().info(
                    f'Observed {case5} times DUT is unable to enable from powersave afer there is no data from {monitor_interval}ms')
        if case1 or case3 > 3 or case2 != 0:
            assert False
        else:
            assert True, "DUT is sending PS-POLL to retrieve the data at Listen interval beacon only"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.test_src_map_id('C19173')
def test_wifi_sdk_cmdbased_maxpsp_listen_interval_c19173(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                                  sl_collections, request, utf_constants, wifi_client, net_perf_client):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19173
    listen_interval = 500
    monitor_interval = 50
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    validation = True
    powersave_validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    '''Verify the Power Save functionality at different Power Save Listen Intervals'''

    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    time_delta_bw_pspol_count=0
    ps_exit_interval_count=0
    ps_enabe_interval_count=0
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"***** Enabling Command based ENH Max PSP in DUT with LI {listen_interval} ******")
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
                                                         dtim_aligned_type=0,
                                                         num_of_dtim_skip=0,
                                                         listen_interval=listen_interval,
                                                         monitor_interval=monitor_interval)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(2)
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        time.sleep(1)
        for i in range(0, 2):
            sl_collections.run_traffic(
                wifi_dut=wifi_dut,
                net_perf_client=net_perf_client,
                protocol='TCP',
                device_ip=wlan_obj.dut_addr["device_ip"],
                host_ip=host_ip,
                timeout=70,
                traffic_type="RX",
            )
            time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()

        dut_mac_address = wlan_obj.dut_addr['dut_mac_address']
        # Assoc resp frame in sniffer to get the DUT assoc id
        packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(1)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        packet_filter2 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) &&' \
                         f' (wlan.da == {ap_bssid}))'

        packet_filter3 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                         f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                         f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                         f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
        assert \
            wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, None, powersave_validation)[
                'packet_count']
        ps_poll_packets_time_delta_list, case1, case2, ps_exit_interval, ps_enable_interval = ps_poll_time_delta_obj.listen_interval_based_validation(
            listen_interval,
            association_id)
        case3 = ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list, listen_interval)
        case4, case5 = ps_poll_time_delta_obj.validation_of_enh_max_psp(ps_exit_interval, ps_enable_interval,monitor_interval)
        if case3 != 0:
            logger().info(
                f'Observed {case3} times DUT is unable to send PS-POLL at listen interval')
        if case4 != 0:
            logger().info(
                f'Observed {case4} times DUT is unable to exit from powersave at 20ms')
        if case5 != 0:
            logger().info(
                f'Observed {case5} times DUT is unable to enable from powersave afer there is no data from {monitor_interval}ms')

        if case3 > 6 or case4 != 0 or case5 != 0:
            assert False
        else:
            assert True, "DUT is sending PS-POLL to retrieve the data at Listen interval beacon only"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C19174')
def test_wifi_sdk_maxpsp_multiple_listen_interval_c19174(wifi_sniffer, wifi_access_point, wifi_dut, sniffer_filter,
                                                         sl_collections, request, utf_constants, wifi_client,
                                                         net_perf_client):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    test_case_no = 19174
    mode = 'power_save'
    listen_interval = 700
    monitor_interval = 50
    ps_poll_time_delta_obj = FilterPacket()
    assoc_obj = FilterPacket()
    validation = True
    powersave_validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    '''Verify the Power Save functionality at different Power Save Listen Intervals'''

    wifi_access_point.interfaces.wifi.start_ap()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    time_delta_bw_pspol_count = 0
    ps_exit_interval_count = 0
    ps_enabe_interval_count = 0
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections,
                          test_case_no=test_case_no, wifi_client=wifi_client, net_perf_client=net_perf_client)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(4)
        dut_mac_address = wlan_obj.dut_addr['dut_mac_address']
        # Assoc resp frame in sniffer to get the DUT assoc id
        packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter10)[
            'packet_count'], 'No packet found for Assoc resp frame'

        time.sleep(1)
        association_id = assoc_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

        for i in range(0, 3):
            if i == 1:
                listen_interval = 1000
            if i == 2:
                listen_interval = 2000
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'outofpower_savemode_{listen_interval}')
            logger().info(f"***** Enabling ENH Max PSP in DUT with LI {listen_interval} ******")
            wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
                                                             dtim_aligned_type=0,
                                                             num_of_dtim_skip=0,
                                                             listen_interval=listen_interval,
                                                             monitor_interval=monitor_interval)
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            time.sleep(2)
            logger().info("Pinging to DUT to with byte size 300")
            status = sl_collections.ping_with_custom_size(wlan_obj.dut_addr["device_ip"], ping_counts=20, byte_size=300)
            assert status, "DUT is not responding to ping request after powersave"
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter2 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) &&' \
                             f' (wlan.da == {ap_bssid}))'

            packet_filter3 = f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {dut_mac_address} && ' \
                             f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && ' \
                             f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && wlan.da == {dut_mac_address}) &&' \
                             f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
            assert \
                wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, None,
                                                                   powersave_validation)[
                    'packet_count']
            ps_poll_packets_time_delta_list, case1, case2, ps_exit_interval, ps_enable_interval = ps_poll_time_delta_obj.listen_interval_based_validation(
                listen_interval,
                association_id)
            case3 = ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list, listen_interval)
            case4, case5 = ps_poll_time_delta_obj.validation_of_enh_max_psp(ps_exit_interval, ps_enable_interval,
                                                                            monitor_interval)
            time_delta_bw_pspol_count = time_delta_bw_pspol_count + case3
            ps_exit_interval_count = ps_exit_interval_count + case4
            ps_enabe_interval_count = ps_enabe_interval_count + case5
            if case3 != 0:
                logger().info(
                    f'Observed {case3} times DUT is unable to send PS-POLL at listen interval')
            if case4 != 0:
                logger().info(
                    f'Observed {case4} times DUT is unable to exit from powersave at 20ms')
            if case5 != 0:
                logger().info(
                    f'Observed {case5} times DUT is unable to enable from powersave afer there is no data from {monitor_interval}ms')

        if time_delta_bw_pspol_count > 6 or ps_exit_interval_count or ps_enabe_interval_count != 0:
            assert False
        else:
            assert True, "DUT is sending PS-POLL to retrieve the data at Listen interval beacon only"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)