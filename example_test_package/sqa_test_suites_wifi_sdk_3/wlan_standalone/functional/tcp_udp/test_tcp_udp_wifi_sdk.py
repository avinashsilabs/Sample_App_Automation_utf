import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xPowerSaveModes,
    DeviceConstants,
    Si91xPowerSaveProcedureTypes,
    Si91xCustomFeatureBitMap,
    SocketOptions,
    Si91xOperatingMode,
    Si91xCustomSyncSockOptParms,
    Si91xJoinFeatureBitMap
)
from threading import Thread
import threading
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from random import randint
import random
import string
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.bsd_errors import BSDErrnoStatus

"""The testcases added in this file run below test steps for DUT(Soc917)
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new TCP/IP or UDP socket(Client/server) at DUT/RASPBERRY - PI
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.
        7. Send and receive the data over the socket. Verify the data integrity and packet loss checks.
        8. Verify TCP rx & tx with high performance sockets
        9. Verify data transfer with different window size and with different RSSI values.

    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. NUC device for Sniffer

    Author: Saurabh Sharma & Achal Raghav
"""


def logger():
    return get_logger(__name__)


class SnifferValidationProcess:

    def __init__(self, wifi_sniffer=None, wifi_access_point=None, dut_mac_address=None, ap_mac_address=None,
                 sniffer_filter=None, sl_collections=None, test_case=None):
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_mac_address = ap_mac_address
        self.sniffer_filter = sniffer_filter
        self.sl_collections = sl_collections
        self.test_case = test_case

    def verify_sniffer_validation(self):

        if self.test_case == 19347 or self.test_case == 19348:
            filters_name = None
            device_address = {'sa_addr': self.dut_mac_address, 'da_addr': self.ap_mac_address,
                              'ta_addr': self.dut_mac_address, 'ra_addr': self.ap_mac_address}

            if self.test_case == 19347:
                filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response', 3: 'ps_poll',
                                4: 'dhcp_4_way_handshake_packets', 5: 'tcp_syn_with_syn_ack_with_ack'}

            if self.test_case == 19348:
                filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response', 3: 'ps_poll',
                                4: 'dhcp_4_way_handshake_packets'}

            output = self.sl_collections.sniffer_validation_for_packet_filters(
                self.wifi_sniffer, self.sniffer_filter, device_address, filters_name=filters_name)

            logger().info(f'\n OUTPUT 1 = {output}\n')
            assert all(output.values()), 'Unable to find expected filter'

        if self.test_case == 19349 or self.test_case == 19350 or self.test_case == 19352:
            device_address_list = {'sa_addr': self.dut_mac_address, 'da_addr': self.ap_mac_address}

            filters_name_list = {1: 'ps_poll', 2: 'probe_req_response'}

            result = self.sl_collections.sniffer_validation_for_packet_filters(
                self.wifi_sniffer, self.sniffer_filter, device_address_list, filters_name=filters_name_list)

            logger().info(f'\n OUTPUT RESULT = {result}\n')
            assert all(result.values()), 'Unable to find expected filter'


class DataTransfer:
    def __init__(self):
        self.thread_lock = threading.Lock()
        self.sent_data = 0
        self.rcv_data = 0

    def send_and_receive_data_socket(
            self, remote_socket, no_of_pkts, data_size, time_interval, wifi_dut, server_sock, local_port, server_ip,
            proto_type=0):

        bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(
            socket_id=server_sock, pkt_length=data_size, no_of_pkts=no_of_pkts, time_interval=time_interval,
            server_ip=server_ip, server_port=local_port)

        logger().info(f"Number of bytes sent by dut {bytes_sent}")

        fail_count = 0
        if proto_type == 0:
            remote_socket.set_recv_timeout(socket_type=0)
        else:
            remote_socket.set_recv_timeout(socket_type=1, use_client_socket=True)
        for i in range(0, no_of_pkts):
            if proto_type == 0:
                data = remote_socket.recv_data_tcp(data_size)
                logger().info(f' Received TCP data : {data}')
            else:
                data, address = remote_socket.recv_data_udp(data_size)
                logger().info(f' Received UDP data : {data}')
            if not isinstance(data, str):
                fail_count = fail_count + 1
                if fail_count == 2:
                    break
                else:
                    continue
            self.rcv_data = self.rcv_data + len(data)

            if self.rcv_data == len(bytes_sent):
                break

        remote_socket.socket_close_indication(1)
        logger().info(f"Total bytes received on socket opened remotely -> {self.rcv_data}")

        assert self.rcv_data == int(
            bytes_sent), f"Data transfer failed. Expected {bytes_sent} bytes but received {self.rcv_data} bytes"


class WifiJoinThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None, sniffer_filter=None, wifi_sniffer=None,
                 sl_collections=None, test_name=None, remote_socket_factory=None, ap_mac_address=None,
                 remote_socket=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.dut_addr = None
        self.device_ip = None
        self.ap_mac_address = ap_mac_address
        self.sniffer_filter = sniffer_filter
        self.wifi_sniffer = wifi_sniffer
        self.enc = "ccmp"
        self.remote_socket_factory = remote_socket_factory
        self.remote_socket = remote_socket

    def run(self):
        try:
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, retry_count=3,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     ping_after_power_save=True, enc=self.enc)
            logger().info(
                f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e

    def tcp_server_single_socket(self, port=5001, keepalive_time=60, server_ip=None, data_length=1000):
        logger().info(f"\n Starting the Remote Socket Server \n")
        self.remote_socket.interfaces.socket.start_server(port=port)
        socket_id = self.wifi_dut.interfaces.wifi.socket()
        logger().info(f"Socket open successfully : {socket_id}")
        self.wifi_dut.interfaces.wifi.bind(
            socket_fd=socket_id, device_ip=self.dut_addr['device_ip'], server_port=port, timeout=5,
            asynch=0)
        logger().info(f"Setting the socket option SO_KEEPALIVE with {keepalive_time} seconds")
        self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
            socket_fd=socket_id, option_name="SO_KEEPALIVE", option_val=keepalive_time
        )
        logger().info("DUT is connecting to server socket")
        for count in range(3):
            connect_status = False
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                    socket_fd=socket_id, server_ip=server_ip, server_port=port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                assert connect_status, "Socket connection failed in DUT"
        logger().info("*********** Socket connection is successful ************")
        sent_data = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=data_length)
        )
        try:
            self.wifi_dut.interfaces.wifi.bsdSocketSend(
                socket_fd=socket_id, data=sent_data, higher_data_len=1
            )
            received_data = (
                self.remote_socket.interfaces.socket.recv_data_tcp(len(sent_data))
            )
            logger().info(f"\nReceived Data: {received_data}\n")
            assert (
                    sent_data == received_data
            ), f"Data mismatch in sent and received data"
        except Exception as e:
            logger().info(
                f"Socket Data Transfer Failed Within Duration"
            )
        time.sleep(keepalive_time * 1.3)
        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
        logger().info(f"Stopping the Remote Socket Server")
        self.remote_socket.interfaces.socket.stop()

    def tcp_multiple_socket_dut_client(self):
        no_of_pkts = 100
        pkt_length = 1460

        server_ip = self.wifi_client.interfaces.wifi.get_ip_address()

        client_sockets = []
        server_port_base = 5001
        server_socks = []
        for count in range(0, 10):
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
                try:
                    self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                        socket_fd=sock, server_ip=server_ip, server_port=local_port)
                    connect_status = True
                    break
                except:
                    logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                    time.sleep(10)
            assert connect_status, "Socket connection failed in DUT"
            logger().info("*********** Socket connection is successful ************")
            time.sleep(1)

        server_port = 5001
        time_interval = 5
        data_transfer_objs = []
        socket_threads = []
        for count in range(0, 10):
            logger().info(f"Iteration: {count}")
            local_port = server_port + count
            data_transfer_objs.append(DataTransfer())

            socket_threads.append(Thread(target=data_transfer_objs[count].send_and_receive_data_socket,
                                         args=(
                                             client_sockets[count], no_of_pkts, pkt_length, time_interval,
                                             self.wifi_dut,
                                             server_socks[count], local_port, server_ip, 0), daemon=True))

            socket_threads[count].start()
            time.sleep(2)

        for sock in server_socks:
            logger().info(f"Closing socket_id->{sock}")
            self.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)

    def udp_multiple_socket_dut_client(self):
        server_ip = self.wifi_client.interfaces.wifi.get_ip_address()

        no_of_pkts = 100
        pkt_length = 1460
        local_port_udp = 8001
        server_port = 8001

        time_interval = 5

        data_transfer_objs = []
        socket_threads = []
        server_socks = []
        client_sockets = []

        for count in range(0, 10):
            local_port = local_port_udp + count
            client_socket = self.remote_socket_factory.interfaces.socket.create_socket()
            client_sockets.append(client_socket)
            client_socket.start_server(port=local_port, socket_type=1)

            sock = self.wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
            logger().info(f"Successfully opened udp client socket and socket id received is {sock} which is expected")
            server_socks.append(sock)

            self.wifi_dut.interfaces.wifi.bind(
                socket_fd=sock, device_ip=self.dut_addr['device_ip'], server_port=local_port, asynch=1)

        for count in range(0, 10):
            logger().info(f"Iteration: {count}")
            local_port = server_port + count
            data_transfer_objs.append(DataTransfer())

            socket_threads.append(Thread(target=data_transfer_objs[count].send_and_receive_data_socket,
                                         args=(
                                             client_sockets[count], no_of_pkts, pkt_length, time_interval,
                                             self.wifi_dut,
                                             server_socks[count], local_port, server_ip, 1), daemon=True))

            socket_threads[count].start()
            time.sleep(2)

        for sock in server_socks:
            logger().info(f"Closing socket_id->{sock}")
            self.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)

    def udp_single_socket_dut_client(self):
        no_of_pkts = 100
        pkt_length = 1460
        server_port = 8001
        local_port_udp = 8001

        time_interval = 5

        data_transfer_objs = []
        socket_threads = []
        server_socks = []
        client_sockets = []

        # This function is responsible to create UDP socket, send data to the server
        server_ip = self.wifi_client.interfaces.wifi.get_ip_address()

        for count in range(0, 1):
            local_port = local_port_udp + count
            client_socket = self.remote_socket_factory.interfaces.socket.create_socket()
            client_sockets.append(client_socket)
            client_socket.start_server(port=local_port, socket_type=1)

            sock = self.wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
            logger().info(f"Successfully opened udp client socket and socket id received is {sock} which is expected")
            server_socks.append(sock)

            self.wifi_dut.interfaces.wifi.bind(
                socket_fd=sock, device_ip=self.dut_addr['device_ip'], server_port=local_port, asynch=1)

        for count in range(0, 1):
            logger().info(f"Iteration: {count}")
            local_port = server_port + count
            data_transfer_objs.append(DataTransfer())

            socket_threads.append(Thread(target=data_transfer_objs[count].send_and_receive_data_socket,
                                         args=(
                                             client_sockets[count], no_of_pkts, pkt_length, time_interval,
                                             self.wifi_dut,
                                             server_socks[count], local_port, server_ip, 1), daemon=True))

            socket_threads[count].start()
            time.sleep(2)

        for sock in server_socks:
            logger().info(f"Closing socket_id->{sock}")
            self.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)

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

    def tcp_udp_multiple_socket_dut_client(self):
        no_of_pkts = 100
        pkt_length = 1460
        client_sockets = []
        server_port_base = 8001
        server_socks = []

        server_ip = self.wifi_client.interfaces.wifi.get_ip_address()

        for count in range(0, 5):
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
                try:
                    self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                        socket_fd=sock, server_ip=server_ip, server_port=local_port)
                    connect_status = True
                    break
                except:
                    logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                    time.sleep(10)
            assert connect_status, "Socket connection failed in DUT"
            logger().info("*********** Socket connection is successful **************")
            time.sleep(1)

        local_port_udp = 8006
        for count in range(0, 5):
            local_port = local_port_udp + count
            client_socket = self.remote_socket_factory.interfaces.socket.create_socket()
            client_sockets.append(client_socket)
            client_socket.start_server(port=local_port, socket_type=1)

            sock = self.wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
            logger().info(f"Successfully opened udp client socket and socket id received is {sock} which is expected")
            server_socks.append(sock)

            self.wifi_dut.interfaces.wifi.bind(
                socket_fd=sock, device_ip=self.dut_addr['device_ip'], server_port=local_port, asynch=1)

        server_port = 8001
        time_interval = 5
        data_transfer_objs = []
        socket_threads = []
        for count in range(0, 10):
            prototype = 0
            if count >= 5:
                prototype = 1
            logger().info(f"Iteration: {count}")
            local_port = server_port + count
            data_transfer_objs.append(DataTransfer())

            socket_threads.append(Thread(target=data_transfer_objs[count].send_and_receive_data_socket,
                                         args=(
                                             client_sockets[count], no_of_pkts, pkt_length, time_interval,
                                             self.wifi_dut,
                                             server_socks[count], local_port, server_ip, prototype), daemon=True))

            socket_threads[count].start()
            time.sleep(2)

        for sock in server_socks:
            logger().info(f"Closing socket_id->{sock}")
            self.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)

    def tcp_remote_terminate(self):
        no_of_pkts = 100
        pkt_length = 1460
        local_port = 5001

        # This function is responsible to create a socket, send data to the server and checking for the
        # remote termination event

        server_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        self.remote_socket.interfaces.socket.start_server(port=local_port)
        self.wifi_dut.interfaces.wifi.set_remote_terminate_callback()
        socket_id = self.wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                              protocol="IPPROTO_TCP")
        logger().info(f"Socket open successfully : {socket_id}")

        self.wifi_dut.interfaces.wifi.bind(
            socket_fd=socket_id, device_ip=self.dut_addr['device_ip'], server_port=local_port, timeout=5, asynch=1)

        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                    socket_fd=socket_id, server_ip=server_ip, server_port=local_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")
        time.sleep(5)

        bytes_sent = self.wifi_dut.interfaces.wifi.send_data_pkts(
            socket_id=socket_id, pkt_length=pkt_length, no_of_pkts=no_of_pkts, time_interval=5,
            server_ip=server_ip, server_port=local_port)

        logger().info(f"Number of bytes sent by dut {bytes_sent}")
        self.remote_socket.interfaces.socket.stop()
        event_data_output = ""
        time.sleep(5)
        events = self.wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.REMOTE_TERMINATE:
                event_data_output = event.event_data

        logger().info(f" ***************** EVENT DATA IS : {event_data_output} ********************** ")

        assert "Remote Terminate" in event_data_output, "expected error code not found. Expected is Remote Terminate"
        logger().info("*********** Remote Termination is Successful *************")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_tcp_open_send_close_socket_c19347(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client):
    """This test case Verfies the tcp client socket is open, send data,close functionality"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0, scan_interval=4, beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     remote_socket_factory=remote_socket_factory, wifi_client=wifi_client)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        wifi_thread.tcp_single_socket_dut_client()

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point, test_case=19347,
                                                        dut_mac_address=dut_mac_address, ap_mac_address=ap_mac_address,
                                                        sl_collections=sl_collections)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_verification.verify_sniffer_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_udp_open_send_data_close_socket_c19348(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client):
    """This test case Verfies the udp client socket is open, send data,close functionality"""
    try:

        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     remote_socket_factory=remote_socket_factory, wifi_client=wifi_client)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        wifi_thread.udp_single_socket_dut_client()

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point, test_case=19348,
                                                        dut_mac_address=dut_mac_address, ap_mac_address=ap_mac_address,
                                                        sl_collections=sl_collections)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_verification.verify_sniffer_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_tcp_socket_dut_client_c19349(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client):
    """Verify 10 sockets functionality open 10 tcp client sockets and connect to server sockets and send data"""
    try:

        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     remote_socket_factory=remote_socket_factory, wifi_client=wifi_client)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        wifi_thread.tcp_multiple_socket_dut_client()

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point, test_case=19349,
                                                        dut_mac_address=dut_mac_address, ap_mac_address=ap_mac_address,
                                                        sl_collections=sl_collections)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_verification.verify_sniffer_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_udp_socket_dut_client_c19350(
        wifi_access_point, wifi_dut, wifi_sniffer, sl_collections, request, sniffer_filter,
        remote_socket_factory, wifi_client):
    """Verify 10 sockets functionality open 10 UDP client sockets and connect to server sockets"""
    try:

        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     remote_socket_factory=remote_socket_factory, wifi_client=wifi_client)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        wifi_thread.udp_multiple_socket_dut_client()

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point, test_case=19350,
                                                        dut_mac_address=dut_mac_address, ap_mac_address=ap_mac_address,
                                                        sl_collections=sl_collections)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_verification.verify_sniffer_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_5tcp_5udp_socket_c19352(
        wifi_access_point, wifi_dut, remote_socket_factory, wifi_sniffer, sl_collections, request, sniffer_filter,
        wifi_client):
    """Verify 10 sockets functionality open 5TCP & 5UDP client sockets"""
    try:

        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     remote_socket_factory=remote_socket_factory, wifi_client=wifi_client)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        wifi_thread.tcp_udp_multiple_socket_dut_client()

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point, test_case=19352,
                                                        dut_mac_address=dut_mac_address, ap_mac_address=ap_mac_address,
                                                        sl_collections=sl_collections)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_verification.verify_sniffer_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.config("net_perf_client",
                    net_perf={"host_role": IperfConstants.SERVER_MODE, "tcp_window_size": '1k'})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_socket_tcp_Data_Transfer_mss_c19356(wifi_access_point, wifi_dut, sl_collections, wifi_sniffer,
                                                      sniffer_filter, protocol, net_perf_client,
                                                      wifi_client):
    """
    Verify TCP data transfer when remote peer Window size is less than MSS
    """
    sock = 0
    try:
        capture_filename = "test_wifi_sdk_socket_tcp_Data_Transfer_mss_c19356"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        time.sleep(3)
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        device_ip, dut_mac_address = wifi_thread.dut_addr['device_ip'], wifi_thread.dut_addr['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                        mss_value=1460, time_out=500)
        net_perf_client.interfaces.net_perf.start()
        server_port = net_perf_client.interfaces.net_perf.server_port
        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port, timeout=20)
        wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(sock, option_name=Si91xCustomSyncSockOptParms.SL_SI91X_SO_MSS,
                                                      cert_index=1460)
        time.sleep(3)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=host_ip, server_port=server_port)

        for count in range(30):
            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))
            logger().info(f"*********** Sending packet_{count + 1} with size --> {len(tx_buffer)} bytes ***********")
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=tx_buffer, higher_data_len=1, timeout=60)
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        net_perf_client.interfaces.net_perf.close_files()
        net_perf_client.interfaces.net_perf.iperf_process.stop(10)
        logger().info(f"Successfully closed socket_id '{sock}' in the DUT")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
        logger().info("********** Validating MSS value in sniffer packets **********")
        packet_filter = f"(wlan.addr == {dut_mac_address}) && (tcp.options.mss_val == 1460)"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)[
            'packet_count'], "Unable to find configured MSS value in sniffer packets"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.config("net_perf_client",
                    net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_tcp_TX_with_message_size_greater_size_than_tcp_window_size_c19357(wifi_access_point, wifi_dut, sl_collections, wifi_sniffer,
                                                      sniffer_filter, protocol, net_perf_client,
                                                      wifi_client):
    """
        Verify TCP data transmission when the message size is greater than the TCP window size.

        This test case performs the following steps:
        1. Configures the WiFi sniffer to capture packets on the specified channel.
        2. Starts the WiFi sniffer to capture packets.
        3. Initializes and starts a WiFi join thread to connect the DUT to the access point.
        4. Retrieves the device IP and MAC address of the DUT and the BSSID of the access point.
        5. Initializes and starts a net performance client in server mode with a specified MSS value.
        6. Creates a TCP socket on the DUT and binds it to the device IP and server port.
        7. Sets the socket option for MSS on the DUT.
        8. Connects the DUT socket to the server.
        9. Sends multiple packets from the DUT to the server.
        10. Processes the output from the net performance client to verify throughput.
        11. Closes the socket on the DUT.
        12. Stops the WiFi sniffer and validates the captured packets for the configured MSS value.

        Args:
            wifi_access_point: The WiFi access point object.
            wifi_dut: The WiFi device under test (DUT) object.
            sl_collections: The SL collections object for handling exceptions.
            wifi_sniffer: The WiFi sniffer object for capturing packets.
            sniffer_filter: The filter to apply on the sniffer.
            protocol: The protocol to use for the net performance client (e.g., TCP).
            net_perf_client: The net performance client object.
            wifi_client: The WiFi client object.

        Raises:
            Exception: If any step in the test case fails.
        """
    try:
        tcp_window_size = 1000
        tcp_message_size = 1460
        capture_filename = "test_wifi_sdk_tcp_TX_with_message_size_greater_size_than_tcp_window_size_c19357"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        device_ip, dut_mac_address = wifi_thread.dut_addr['device_ip'], wifi_thread.dut_addr['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                        mss_value=tcp_window_size, time_out=500)
        net_perf_client.interfaces.net_perf.start()
        server_port = net_perf_client.interfaces.net_perf.server_port
        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port, timeout=20)
        wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(sock, option_name=Si91xCustomSyncSockOptParms.SL_SI91X_SO_MSS,
                                                      cert_index=tcp_message_size)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=host_ip, server_port=server_port)

        tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=tcp_message_size))
        logger().info(f"*********** Sending packet with size --> {len(tx_buffer)} bytes ***********")
        status, data = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=tx_buffer, higher_data_len=1, timeout=60, expected_status=BSDErrnoStatus.EMSGSIZE)
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        net_perf_client.interfaces.net_perf.close_files()
        net_perf_client.interfaces.net_perf.iperf_process.stop(10)
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger().info(f"Successfully closed socket_id '{sock}' in the DUT")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
        logger().info("********** Validating MSS value in sniffer packets **********")
        packet_filter = f"(wlan.addr == {dut_mac_address}) && (tcp.options.mss_val == {tcp_window_size})"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)[
            'packet_count'], "Unable to find configured MSS value in sniffer packets"
    except Exception as e:
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
def test_wifi_sdk_tcp_data_receive_check_c19360(wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections,
                                                sniffer_filter, remote_socket_factory, wifi_client):
    """Validation of data and length by giving length in read command over TCP server socket"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        socket_id = wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                         protocol="IPPROTO_TCP")
        logger().info(f"Socket open successfully : {socket_id}")
        logger().info(f"Successfully opened tcp client socket and socket id received is {socket_id} which is expected")
        local_port = 5001
        wifi_dut.interfaces.wifi.bind(socket_fd=socket_id, device_ip=wifi_thread.dut_addr['device_ip'],
                                      server_port=local_port, timeout=5, asynch=1)

        wifi_dut.interfaces.wifi.listen(socket_fd=socket_id, backlog=1, asynch=1)

        ThreadBase.call_functions_simultaneously(
            [
                (wifi_dut.interfaces.wifi.bsdSocketAccept, socket_id, 1),
                (
                    client_socket.connect_client_tcp,
                    wifi_thread.dut_addr['device_ip'],
                    local_port,
                ),
            ],
            timeout=10,
        )

        tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
        buffer_length = len(tx_buffer)
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            logger().info(f"Remote peer sending data over socket {socket_id} and data:{tx_buffer}")
            client_socket.send_data_tcp(tx_buffer, use_server_socket=False)
            time.sleep(1)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket_id + 1)
            logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
            logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                           f"{socket_id} opened in the DUT is not matched"
            logger().info("Data sent by remote peer and received on DUT is matching")

        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket_id)
        client_socket.socket_close_indication(1)
        logger().info("Successfully closed opened socket in the DUT")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name="ps_poll")
        logger().info(f"***** Validating PS POLL Packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find PS POLL Packets"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
def test_wifi_sdk_udp_receive_c19361(wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections,
                                     sniffer_filter, remote_socket, wifi_client):
    """Validation of data and length by giving length in read command over udp"""
    try:
        local_port = 5001
        test_name = request.node.name
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address(ip_version=4)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        remote_socket.interfaces.socket.start_server(socket_type=1)
        sock = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")

        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_thread.dut_addr['device_ip'],
                                      server_port=local_port, asynch=1)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, ip_len=4, server_port=local_port)

        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
            buffer_length = len(tx_buffer)
            remote_socket.interfaces.socket.send_data_udp(tx_buffer, wifi_thread.dut_addr['device_ip'], local_port)
            time.sleep(2)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)
            logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
            logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
            assert buffer_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name="ps_poll")
        logger().info(f"***** Validating PS POLL Packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find PS POLL Packets"

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

    finally:
        remote_socket.interfaces.socket.stop()
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA', "cipher": "TKIP", "passphrase": '123456789',
                                               "standard": '11bg'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
def test_wifi_sdk_tcp_udp_data_receive_WPA_TKIP_c71653(
        wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections, sniffer_filter, remote_socket_factory,
        remote_socket, wifi_client):
    """Verify TCP ,UDP data reception of STAUT in WPA-TKIP mode"""
    try:
        test_name = request.node.name
        local_port = 5001
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.enc = "tkip"
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        socket_id = wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                         protocol="IPPROTO_TCP")
        logger().info(f"Socket open successfully : {socket_id}")
        logger().info(f"Successfully opened tcp client socket and socket id received is {socket_id} which is expected")

        wifi_dut.interfaces.wifi.bind(socket_fd=socket_id, device_ip=wifi_thread.dut_addr['device_ip'],
                                      server_port=local_port, timeout=5, asynch=1)

        wifi_dut.interfaces.wifi.listen(socket_fd=socket_id, backlog=1, asynch=1)

        ThreadBase.call_functions_simultaneously(
            [
                (wifi_dut.interfaces.wifi.bsdSocketAccept, socket_id, 1),
                (client_socket.connect_client_tcp, wifi_thread.dut_addr['device_ip'], local_port),
            ],
            timeout=10,
        )

        tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
        buffer_length = len(tx_buffer)
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            logger().info(f"Remote peer sending data over socket {socket_id} and data:{tx_buffer}")
            client_socket.send_data_tcp(tx_buffer, use_server_socket=False)
            time.sleep(1)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket_id + 1)
            logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
            logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                           f"{socket_id} opened in the DUT is not matched"
            logger().info("Data sent by remote peer and received on DUT is matching")

        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket_id)
        remote_socket_factory.interfaces.socket.close_all()
        logger().info("Successfully closed opened socket in the DUT")
        time.sleep(20)

        """ ************************************** Creating UDP Socket *******************************************"""
        local_port_udp = 6001
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address(ip_version=4)
        remote_socket.interfaces.socket.start_server(socket_type=1)
        sock = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"Successfully opened udp client socket and socket id received is {sock} which is expected")

        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_thread.dut_addr['device_ip'],
                                      server_port=local_port_udp, asynch=1)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, ip_len=4,
                                                  server_port=local_port_udp)

        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
            buffer_length = len(tx_buffer)
            remote_socket.interfaces.socket.send_data_udp(tx_buffer, wifi_thread.dut_addr['device_ip'], local_port_udp)
            time.sleep(2)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)
            logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
            logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
            assert buffer_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name="ps_poll")
        logger().info(f"***** Validating PS POLL Packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find PS POLL Packets"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        remote_socket.interfaces.socket.stop()
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA', "cipher": "TKIP", "passphrase": '123456789',
                                               "standard": '11bg'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_tcp_udp_data_tx_WPA_TKIP_c19365(
        wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections, sniffer_filter, remote_socket_factory,
        wifi_client):
    """Verify TCP ,UDP data reception of STAUT in WPA-TKIP mode"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client, remote_socket_factory=remote_socket_factory)
        wifi_thread.enc = "tkip"
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        wifi_thread.tcp_single_socket_dut_client()

        time.sleep(5)

        """ ******************* Creating UDP Socket *******************"""

        wifi_thread.udp_single_socket_dut_client()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name="ps_poll")
        logger().info(f"***** Validating PS POLL Packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find PS POLL Packets"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
def test_wifi_sdk_multi_tcp_socket_dut_server_c19351(
        wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections, sniffer_filter, remote_socket_factory,
        wifi_client):
    """Verify 10 sockets functionality open 10 TCP server sockets and client sockets connect to it"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'***** AP MAC ADDRESS {ap_mac_address} ****')
        client_socket = []
        server_port_base = 5001
        tcp_socks = []
        for count in range(0, 10):
            local_port = server_port_base + count
            logger().info(f'Server port = {local_port}')
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            sock = wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                        protocol="IPPROTO_TCP")
            logger().info(f"Socket open successfully : {sock}")
            logger().info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_thread.dut_addr['device_ip'],
                                          server_port=local_port, timeout=5, asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)
            ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1, count),
                    (client_socket[count].connect_client_tcp, wifi_thread.dut_addr['device_ip'], local_port),
                ],
                timeout=10,
            )
        count = 0
        for sock_no in tcp_socks:
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
            buffer_length = len(tx_buffer)
            logger().info(f"Remote peer sending data over socket {sock_no} and data:{tx_buffer}")
            client_socket[count].send_data_tcp(tx_buffer, use_server_socket=False)
            time.sleep(1)
            count += 1
            wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=2, time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_no + 1)
            logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
            logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                           f"{sock_no} opened in the DUT is not matched"
            logger().info("Data sent by remote peer and received on DUT is matching")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        for sock_id in tcp_socks:
            logger().info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
def test_wifi_sdk_5tcp_5udp_dut_server_socket_c19353(
        wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections, sniffer_filter, remote_socket_factory,
        wifi_client, remote_multi_socket):
    """Verify 10 sockets functionality open 5TCP server +5UDP server sockets"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        client_socket = []
        server_port_base = 5001
        tcp_socks = []
        udp_socks = []
        for count in range(0, 5):
            local_port = server_port_base + count
            logger().info(f'Server port = {local_port}')
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            sock = wifi_dut.interfaces.wifi.Asyncsocket(
                domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP")
            logger().info(f"Socket open successfully : {sock}")
            logger().info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_thread.dut_addr['device_ip'],
                                          server_port=local_port, timeout=5, asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)
            ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1, count),
                    (client_socket[count].connect_client_tcp, wifi_thread.dut_addr['device_ip'], local_port),
                ],
                timeout=10,
            )
        count = 0
        for sock_no in tcp_socks:
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
            buffer_length = len(tx_buffer)
            logger().info(f"Remote peer sending data over socket {sock_no} and data:{tx_buffer}")
            client_socket[count].send_data_tcp(tx_buffer, use_server_socket=False)
            time.sleep(1)
            count += 1
            wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=2, time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_no + 1, timeout=60,
                                                                      async_timeout=60)
            logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
            logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                           f"{sock_no} opened in the DUT is not matched"
            logger().info("Data sent by remote peer and received on DUT is matching")
        start_port = 8001
        start_port_dut = 6001
        for sock_count in range(0, 5):
            port = start_port + sock_count
            port_dut = start_port_dut + sock_count
            sock_id = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
            remote_multi_socket.interfaces.socket.start_server(port=port, socket_type=1, sock_id=sock_id)
            udp_socks.append(sock_id)
            logger().info(
                f"Successfully opened UDP client socket and socket id received is {sock_id} which is expected")
            if sock_count == 10:
                assert sock_id == 10, f"socket id received is wrong, expected is 0"
            elif sock_count == 11:
                assert sock_id == 11, f"socket id received is wrong, expected is 1"
            elif sock_count == 12:
                assert sock_id == 12, f"socket id received is wrong, expected is 2"
            elif sock_count == 13:
                assert sock_id == 13, f"socket id received is wrong, expected is 3"
            elif sock_count == 14:
                assert sock_id == 14, f"socket id received is wrong, expected is 4"
            wifi_dut.interfaces.wifi.bind(socket_fd=sock_id, device_ip=wifi_thread.dut_addr['device_ip'],
                                          server_port=port_dut, asynch=1)
        i = 0
        for socket_no in range(10, 15):
            data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
            data_length = len(data_sent)
            if socket_no == 10:
                start_port_dut = 6001
            elif socket_no == 11:
                start_port_dut = 6002
            elif socket_no == 12:
                start_port_dut = 6003
            elif socket_no == 13:
                start_port_dut = 6004
            elif socket_no == 14:
                start_port_dut = 6005
            logger().info(f"###################### start_port from DUT : {start_port_dut}  ######################")
            remote_multi_socket.interfaces.socket.send_data_udp(tx_buffer=data_sent,port=start_port_dut,
                                                                server_ip=wifi_thread.dut_addr['device_ip'],
                                                                sock_id=udp_socks[i])
            i += 1

            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            time.sleep(3)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket_no, timeout=60,
                                                                      async_timeout=60)
            logger().info(f"###################### Buffer Data  {data_sent}  ######################")
            logger().info(f"###################### Buffer Data Length  {data_length}  ######################")
            logger().info(f"###################### Received Data: {buffer_rx} ######################")
            assert data_length == len(buffer_rx), (f"buffer length sent by remote peer and received on the socket id "
                                                   f"{socket_no} opened in the DUT is not matched ")
            time.sleep(2)
        for sock in tcp_socks:
            logger().info(f"Closing socket_id->{sock}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        for socket in udp_socks:
            logger().info(f"Closing socket_id->{socket}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_tcp_remote_terminate_c19362(
        wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections, sniffer_filter, remote_socket,
        wifi_client):
    """ TCP remote terminate after Tx from module. Check total bytes sent by module i.e. 100*1400 bytes  """
    try:
        test_name = request.node.name

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client, remote_socket=remote_socket)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        logger().info(f"\n\n *** Calling TCP remote termination ***\n\n")
        wifi_thread.tcp_remote_terminate()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        remote_socket.interfaces.socket.stop()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": 12345678})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_tcp_data_transfer_rejoin_c19354(wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections, sniffer_filter, remote_socket,
        wifi_client, switch):
    """ Verify TCP data transfer functionality while STA is in rejoin process. Send data packets 1000 with module size
    1460."""
    try:
        local_port = 5001
        no_of_pkts = 10000
        pkt_length = 1460
        time_interval = 5
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client, remote_socket=remote_socket)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        remote_socket.interfaces.socket.start_server(port=local_port)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"SERVER-IP: {server_ip}")
        socket_id = wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                         protocol="IPPROTO_TCP")
        logger().info(f"Socket open successfully : {socket_id}")
        wifi_dut.interfaces.wifi.bind(
            socket_fd=socket_id, device_ip=wifi_thread.dut_addr['device_ip'], server_port=local_port, timeout=5, asynch=1)
        logger().info("DUT is connecting to server socket")
        for count in range(3):
            connect_status = False
            try:
                wifi_dut.interfaces.wifi.bsdSocketConnect(
                    socket_fd=socket_id, server_ip=server_ip, server_port=local_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                assert connect_status, "Socket connection failed in DUT"
        logger().info("*********** Socket connection is successful ************")
        time.sleep(1)
        logger().info("Socket connection is successful")
        time.sleep(5)
        send_data_thread = Thread(target=wifi_dut.interfaces.wifi.send_data_pkts, args=(socket_id, pkt_length, no_of_pkts,
                                                                                  time_interval, server_ip, local_port),
                          daemon=True)
        send_data_thread.start()
        logger().info("Turning off the network")
        switch.interfaces.pdu_switch.turn_off()
        time.sleep(20)
        logger().info("Turning on the network")
        switch.interfaces.pdu_switch.turn_on()
        time.sleep(10)
        data = remote_socket.interfaces.socket.recv_data_tcp(data_size=1460)
        logger().info(f"Data received : {data}")
        logger().info(f"Closing the socket: {socket_id}")
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket_id)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, wifi_thread.dut_addr['dut_mac_address'],
                                               ap_bssid, sniffer_filter)
    except Exception as error:
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket_id)
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": 12345678})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_tcp_tx_rx_high_performance_socket_C19366(wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections,
                                                  sniffer_filter, remote_socket_factory, wifi_client):
    """ Verify TCP tx and Rx by opening 8 TCP high performance socket."""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'***** AP MAC ADDRESS {ap_mac_address} ****')
        client_socket = []
        server_port_base = 5001
        tcp_socks = []
        for count in range(0, 8):
            local_port = server_port_base + count
            logger().info(f'Server port: {local_port}')
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            sock = wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                        protocol="IPPROTO_TCP")
            logger().info(f"Socket open successfully : {sock}")
            logger().info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(socket_fd=sock,
                                                          option_name=Si91xCustomSyncSockOptParms.SL_SI91X_SO_HIGH_PERFORMANCE_SOCKET,
                                                          cert_index=128)
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_thread.dut_addr['device_ip'],
                                          server_port=local_port, timeout=5, asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)
            ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1, count),
                    (client_socket[count].connect_client_tcp, wifi_thread.dut_addr['device_ip'], local_port),
                ],
                timeout=10,
            )
        count = 0
        for sock_no in tcp_socks:
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
            buffer_length = len(tx_buffer)
            logger().info(f"Remote peer sending data over socket {sock_no} and data:{tx_buffer}")
            client_socket[count].send_data_tcp(tx_buffer, use_server_socket=False)
            time.sleep(1)
            count += 1
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_no + 1)
            logger().info(f" Buffer Data  {buffer_rx}")
            logger().info(f"Buffer Data Length  {buffer_length}")
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                           f"{sock_no} opened in the DUT is not matched"
            logger().info("Data sent by remote peer and received on DUT is matching")
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        for sock_id in tcp_socks:
            logger().info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": 12345678})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
def test_open_tcp_server_udp_client_C148603(wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections,
                                            sniffer_filter, remote_socket_factory, wifi_client):
    """ Verify 10 sockets functionality open 5TCP server +5UDP client sockets."""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'***** AP MAC ADDRESS {ap_mac_address} ****')
        client_socket = []
        server_port_base = 5001
        server_sock = []
        udp_sock = []
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        for count in range(0, 5):
            local_port = server_port_base + count
            logger().info(f'Server port = {local_port}')
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            sock = wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                        protocol="IPPROTO_TCP")
            logger().info(f"Socket open successfully : {sock}")
            logger().info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            server_sock.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_thread.dut_addr['device_ip'],
                                          server_port=local_port, timeout=5, asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)
            ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1, count),
                    (client_socket[count].connect_client_tcp, wifi_thread.dut_addr['device_ip'], local_port),
                ],
                timeout=10,
            )
        local_port_udp = 5006
        no_of_pkts = 100
        pkt_length = 1460
        udp_port = []
        udp_client_socket = []
        for count in range(0, 5):
            local_port = local_port_udp + count
            udp_port.append(local_port)
            logger().info(f"UDP port number{local_port}")
            client_socket_udp = remote_socket_factory.interfaces.socket.create_socket()
            udp_client_socket.append(client_socket_udp)
            client_socket_udp.start_server(port=local_port, socket_type=1)
            sock = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
            udp_sock.append(sock)
            logger().info(f"Successfully opened udp client socket and socket id received is {sock} which is expected")
            wifi_dut.interfaces.wifi.bind(
                socket_fd=sock, device_ip=wifi_thread.dut_addr['device_ip'], server_port=local_port, asynch=1)
        count = 0
        for sock in server_sock:
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
            buffer_length = len(tx_buffer)
            logger().info(f"Remote peer sending tcp data over socket {sock} and data:{tx_buffer}")
            client_socket[count].send_data_tcp(tx_buffer, use_server_socket=False)
            time.sleep(1)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock + 1)
            logger().info(f" Buffer Data  {buffer_rx}  ")
            logger().info(f"Buffer Data Length  {buffer_length} ")
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                           f"{server_sock[count]} opened in the DUT is not matched"
            logger().info("Data sent by remote peer and received on DUT is matching")
            count = count + 1

        for count in range(0, 5):
            wifi_dut.interfaces.wifi.send_data_pkts(socket_id=udp_sock[count], pkt_length=pkt_length,
                                                    no_of_pkts=no_of_pkts, server_ip=server_ip,
                                                    server_port=udp_port[count])
            time.sleep(20)
            data = udp_client_socket[count].recv_data_udp(data_size=1460)
            logger().info(f"Data received : {data}")
            time.sleep(2)
        for sock in server_sock:
            logger().info(f"Closing socket_id->{sock}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        for sock in udp_sock:
            logger().info(f"Closing socket_id->{sock}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT| Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_tcp_socket_window_size_C19367(wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections,
                                       sniffer_filter, remote_socket_factory, wifi_client):
    """ Open TCP socket with window size 7 in socket create command."""
    test_name = request.node.name
    local_port = 5001
    total_window_size = 1460 * 7
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
    wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                             beacon_missed_count=40, first_time_retry_enable=0)
    wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                 sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                 wifi_client=wifi_client)
    wifi_thread.start()
    wifi_thread.wait_for_exit()
    device_ip, dut_mac_address = wifi_thread.dut_addr['device_ip'], wifi_thread.dut_addr['dut_mac_address']
    logger().info(f"device_ip:{device_ip}")
    logger().info(f"dut_mac_address:{dut_mac_address}")
    wifi_dut.interfaces.wifi.set_socket_config(tcp_rx_window_size_cap=7, tcp_rx_window_div_factor=7)
    socket_id = wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                     protocol="IPPROTO_TCP")
    logger().info(f"Socket open successfully : {socket_id}")
    logger().info(f"Successfully opened tcp client socket and socket id received is {socket_id} which is expected")
    wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(
        socket_fd=socket_id, option_name=Si91xCustomSyncSockOptParms.SL_SI91X_SO_HIGH_PERFORMANCE_SOCKET,
        cert_index=128)
    wifi_dut.interfaces.wifi.bind(socket_fd=socket_id, device_ip=device_ip,
                                  server_port=local_port, timeout=5, asynch=1)
    wifi_dut.interfaces.wifi.listen(socket_fd=socket_id, backlog=1, asynch=1)
    time.sleep(3)
    client_socket = remote_socket_factory.interfaces.socket.create_socket()
    ThreadBase.call_functions_simultaneously(
        [(client_socket.connect_client_tcp, device_ip, local_port),
         (wifi_dut.interfaces.wifi.bsdSocketAccept, socket_id, 1)], timeout=10)
    tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
    buffer_length = len(tx_buffer)
    sw = Stopwatch()
    while sw.elapsed_sec < 60:
        logger().info(f"Remote peer sending data over socket {socket_id} and data:{tx_buffer}")
        client_socket.send_data_tcp(tx_buffer, use_server_socket=False)
        time.sleep(1)
        wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
        buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket_id + 1, timeout=60)
        logger().info(f"Buffer Data:  {buffer_rx}")
        logger().info(f"Buffer Data Length:  {buffer_length}")
        assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                       f"{socket_id} opened in the DUT is not matched"
        logger().info("Data sent by remote peer and received on DUT is matching")
    wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket_id)
    client_socket.socket_close_indication(1)
    logger().info("Successfully closed opened socket in the DUT")
    wifi_sniffer.interfaces.capture.stop_capture()
    packet_filter1 = (f'(wlan.addr == {dut_mac_address} && tcp.flags == 0x0012 && tcp.window_size_value == '
                      f'{total_window_size})')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
        'packet_count'], "Unable to find configured value in sniffer packets"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": 12345678})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_udp_async_server_open_receive_close_C584247(wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections,
                                                     sniffer_filter, remote_socket, wifi_client):
    """ Verify UDP async  server  socket is open, receive data, and close socket."""
    test_name = request.node.name
    local_port = 5001
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
    wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                             beacon_missed_count=40, first_time_retry_enable=0)
    wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                 sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                 wifi_client=wifi_client)
    wifi_thread.start()
    wifi_thread.wait_for_exit()
    dut_ip = wifi_thread.dut_addr['device_ip']
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'***** AP MAC ADDRESS {ap_mac_address} ****')
    server_ip = wifi_client.interfaces.wifi.get_ip_address()
    remote_socket.interfaces.socket.start_server(server_ip=server_ip, port=local_port, socket_type=1)
    socket_id = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM",
                                                     protocol="IPPROTO_UDP")
    logger().info(f"Socket open successfully : {socket_id}")
    wifi_dut.interfaces.wifi.bind(
        socket_fd=socket_id, device_ip=wifi_thread.dut_addr['device_ip'], server_port=local_port, timeout=30, asynch=1)
    time.sleep(5)
    tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
    buffer_length = len(tx_buffer)
    logger().info(f"Remote peer sending data over socket {socket_id} and data:{tx_buffer}")
    logger().info(f"SERVER-IP: {server_ip}")
    remote_socket.interfaces.socket.send_data_udp(tx_buffer=tx_buffer, server_ip=dut_ip, port=local_port)
    time.sleep(5)
    buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket_id, timeout=60)
    logger().info(f"Buffer Data:  {buffer_rx}")
    logger().info(f"Buffer Data Length:  {buffer_length}")
    assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                   f"{socket_id} opened in the DUT is not matched"
    logger().info("Data sent by remote peer and received on DUT is matching")
    logger().info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(2)
    logger().info(f"Closing socket_id->{socket_id}")
    wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket_id)
    remote_socket.interfaces.socket.stop()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features":Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": 12345678})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_tcp_server_open_more_than_max_limit_C19364(wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections,
                                                    sniffer_filter, remote_socket_factory, wifi_client):
    """ Open TCP severs socket more than maximum  and connect TCP clients."""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'***** AP MAC ADDRESS {ap_mac_address} ****')
        client_socket = []
        server_port_base = 5001
        tcp_socks = []
        socket_list = []
        max_socket_count = 10
        for count in range(0, max_socket_count + 1):
            local_port = server_port_base + count
            socket_list.append(local_port)
            logger().info(f'Server port = {local_port}')
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            sock = wifi_dut.interfaces.wifi.socket()
            logger().info(f"Socket open successfully : {sock}")
            logger().info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_thread.dut_addr['device_ip'],
                                          server_port=local_port, timeout=5, asynch=0)
            try:
                wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=0)
            except Exception as e:
                if count == max_socket_count:
                    wifi_dut.interfaces.wifi.get_saved_firmware_status(expected_status=
                                                                       SLStatus.SL_STATUS_SI91X_MAX_SOCKETS_EXCEEDED)
                    logger().info(f"\n **** Status Received: {SLStatus.SL_STATUS_SI91X_MAX_SOCKETS_EXCEEDED}")
                    tcp_socks.remove(sock)
                    wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                    break
        for count in range(0, 10):
            ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.bsdSocketAccept, tcp_socks[count], 0),
                    (client_socket[count].connect_client_tcp, wifi_thread.dut_addr['device_ip'], socket_list[count]),
                ],
                timeout=10,
            )
        server_count = 9
        for count in range(0, 10):
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
            buffer_length = len(tx_buffer)
            logger().info(f"Remote peer sending data over socket {tcp_socks[count]} and data:{tx_buffer}")
            client_socket[tcp_socks[count]].send_data_tcp(tx_buffer, use_server_socket=False)
            time.sleep(1)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceive(socket_fd=server_count + 1, timeout=60)
            logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
            logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
            server_count = server_count + 1
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                           f"{tcp_socks[count]} opened in the DUT is not matched"
            logger().info("Data sent by remote peer and received on DUT is matching")
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        for sock_id in range(0, 10):
            logger().info(f"Closing socket_id->{tcp_socks[sock_id]}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=tcp_socks[sock_id])
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_TOTAL_SOCKETS_1,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.check
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": 12345678})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_socket_limit_C19359(wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections, sniffer_filter, remote_socket,
        wifi_client):
    """ Open more than one socket when only one socket is selected in opermode command."""

    try:
        local_port = 5001
        device_port = 5002
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client, remote_socket=remote_socket)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        remote_socket.interfaces.socket.start_server(port=local_port)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"SERVER-IP: {server_ip}")
        socket_id = wifi_dut.interfaces.wifi.socket()
        logger().info(f"Socket open successfully : {socket_id}")
        wifi_dut.interfaces.wifi.bind(
            socket_fd=socket_id, device_ip=wifi_thread.dut_addr['device_ip'], server_port=local_port, timeout=5,
            asynch=0)
        logger().info("DUT is connecting to server socket")
        for count in range(3):
            connect_status = False
            try:
                wifi_dut.interfaces.wifi.bsdSocketConnect(
                    socket_fd=socket_id, server_ip=server_ip, server_port=local_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                assert connect_status, "Socket connection failed in DUT"
        logger().info("*********** Socket connection is successful ************")
        time.sleep(1)
        logger().info("Socket connection is successful")
        bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(
            socket_id=socket_id, pkt_length=10, no_of_pkts=10, time_interval=5,
            server_ip=server_ip, server_port=local_port)
        logger().info(f"Number_of_bytes_sent: {bytes_sent}")
        data = remote_socket.interfaces.socket.recv_data_tcp(data_size=1460)
        logger().info(f"Data received : {data}")
        remote_socket.interfaces.socket.start_server(port=device_port)
        sock = wifi_dut.interfaces.wifi.socket()
        logger().info(f"Socket open successfully : {sock}")
        wifi_dut.interfaces.wifi.bind(
            socket_fd=sock, device_ip=wifi_thread.dut_addr['device_ip'], server_port=device_port, timeout=5, asynch=0)
        logger().info("DUT is connecting to server socket")
        for count in range(3):
            try:
                wifi_dut.interfaces.wifi.bsdSocketConnect(
                    socket_fd=sock, server_ip=server_ip, server_port=device_port)
            except:
                wifi_dut.interfaces.wifi.get_saved_firmware_status(expected_status=
                                                                   SLStatus.SL_STATUS_SI91X_MAX_SOCKETS_EXCEEDED)
                logger().info("Error matches with the expected error")
                break
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        remote_socket.interfaces.socket.stop()
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_TOTAL_SOCKETS_1,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'open', "passphrase": 12345678})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_verify_keep_alive_functionality_with_LI_500_900_1000ms_c586158(wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections, sniffer_filter, remote_socket,
        wifi_client):
    """
        Verify the keep-alive functionality of the WiFi SDK with different listen intervals (500ms, 700ms, 1000ms).

        This test performs the following steps:
        1. Configure the WiFi DUT (Device Under Test) with different listen intervals.
        2. Start a remote socket server.
        3. Connect the WiFi DUT to the access point.
        4. Verify the keep-alive functionality by sending and receiving data.
        5. Capture and validate the network traffic using a WiFi sniffer.

        Args:
            wifi_sniffer: The WiFi sniffer interface for capturing network traffic.
            wifi_dut: The WiFi Device Under Test (DUT) interface.
            wifi_access_point: The WiFi access point interface.
            request: The pytest request object.
            sl_collections: The collection of SL (Silicon Labs) interfaces.
            sniffer_filter: The sniffer filter interface for filtering captured packets.
            remote_socket: The remote socket interface for server-client communication.
            wifi_client: The WiFi client interface.

        Raises:
            Exception: If any step in the test fails.
        """
    try:
        port = 5001
        keepalive_time = 60
        listen_intervals = [500, 700, 1000]
        test_name = request.node.name
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"SERVER-IP: {server_ip}")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        for listen_interval in listen_intervals:
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            logger().info(f"\n Starting the Remote Socket Server \n")
            remote_socket.interfaces.socket.start_server(port=port)
            wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
            wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=listen_interval)
            wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                         sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                         wifi_client=wifi_client, remote_socket=remote_socket)
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            wifi_thread.tcp_server_single_socket(port=port, server_ip=server_ip, keepalive_time=keepalive_time, data_length=1000)
            wifi_sniffer.interfaces.capture.stop_capture()
            wifi_dut.interfaces.wifi.leave()
            sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, wifi_thread.dut_addr['dut_mac_address'], ap_bssid,
                                              sniffer_filter)
            logger().info(f"Starting the Keep Alive Validation with duration {keepalive_time} seconds")

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                ta_addr=wifi_thread.dut_addr['dut_mac_address'],
                ra_addr=ap_bssid, filter_name="keep_alive")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count'], f"Keep alive packets not found in sniffer packets"

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'open', "passphrase": 12345678})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_verify_keep_alive_functionality_with_different_dtim_c586159(wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections, sniffer_filter, remote_socket,
        wifi_client):
    """
        Verify the keep-alive functionality of the WiFi SDK with different DTIM intervals.

        This test case configures the WiFi DUT (Device Under Test) to operate as a WiFi client with specific features and
        TCP/IP configurations. It then verifies the keep-alive functionality by setting different DTIM (Delivery Traffic
        Indication Message) intervals and checking the behavior of the DUT.

        Steps:
        1. Configure the WiFi DUT with the specified features and TCP/IP configurations.
        2. Initialize the WiFi DUT and connect it to the access point with the specified security settings.
        3. Start the WiFi sniffer to capture network traffic.
        4. Set different DTIM intervals and verify the keep-alive functionality for each interval.
        5. Capture and validate the network traffic to ensure the keep-alive functionality is working as expected.

        Args:
            wifi_sniffer: The WiFi sniffer interface to capture network traffic.
            wifi_dut: The WiFi DUT (Device Under Test) interface.
            wifi_access_point: The WiFi access point interface.
            request: The pytest request object.
            sl_collections: The SL collections interface for handling exceptions.
            sniffer_filter: The sniffer filter interface for filtering captured packets.
            remote_socket: The remote socket interface for communication.
            wifi_client: The WiFi client interface.

        Raises:
            Exception: If any step in the test case fails.
        """
    try:
        port = 5001
        keepalive_time = 60
        dtim_intervals = [1, 3, 5]
        test_name = request.node.name
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"SERVER-IP: {server_ip}")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        for dtim_interval in dtim_intervals:
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            logger().info(f"\n Setting the DTIM value as {dtim_interval} \n")
            wifi_access_point.interfaces.wifi.start_ap(dtim=dtim_interval)
            wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                         sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                         wifi_client=wifi_client, remote_socket=remote_socket)
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            wifi_thread.tcp_server_single_socket(port=port, server_ip=server_ip, keepalive_time=keepalive_time,
                                                 data_length=1000)
            wifi_sniffer.interfaces.capture.stop_capture()
            wifi_dut.interfaces.wifi.leave()
            sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, wifi_thread.dut_addr['dut_mac_address'], ap_bssid,
                                               sniffer_filter)
            dtim_packet_filter = f'wlan.tim.dtim_period == {dtim_interval} && wlan.addr == {ap_bssid}'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=dtim_packet_filter), f"Configured DTIM value: {dtim_interval} not found in sniffer packets"
            logger().info(f"Starting the Keep Alive Validation with duration {keepalive_time} seconds")

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                ta_addr=wifi_thread.dut_addr['dut_mac_address'],
                ra_addr=ap_bssid, filter_name="keep_alive")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count'], f"Keep alive packets not found in sniffer packets"

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.skip()
@pytest.mark.firmware_app("test_lwip_stack")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
                               | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}}
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.start_state("wifi_dut", wifi=["init", "net_init_client"])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_verify_tcp_server_functionality_with_tcp_ip_bypass_mode_c585534(firmware_loader, wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections,
                                                net_perf_client, wifi_client, protocol):
    """
        Verify the TCP server functionality with TCP/IP bypass mode.

        This test case performs the following steps:
        1. Configure the WiFi DUT (Device Under Test) to operate in TCP/IP bypass mode.
        2. Connect the WiFi DUT to the access point.
        3. Start the WiFi sniffer to capture network traffic.
        4. Initialize and start the iperf server on the remote client.
        5. Start the iperf client on the WiFi DUT to send data to the iperf server.
        6. Capture and validate the network traffic to ensure the TCP server functionality is working as expected.

        Args:
            wifi_sniffer: The WiFi sniffer interface to capture network traffic.
            wifi_dut: The WiFi DUT interface to configure and control the DUT.
            wifi_access_point: The WiFi access point interface to configure and control the access point.
            request: The pytest request object to get test metadata.
            sl_collections: The SL collections interface for exception handling and validation.
            sniffer_filter: The sniffer filter interface to configure packet filters.
            net_perf_client: The net_perf client interface to initialize and start the iperf server.
            wifi_client: The WiFi client interface to get the IP address of the remote client.
            protocol: The protocol to be used for the iperf test (TCP in this case).

        Raises:
            Exception: If any step in the test case fails.
        """
    try:
        transfer_type = 1
        throughput_type = 3
        size = 1460
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_dut.interfaces.wifi.join(enable_lwip=1, security=wifi_access_point.interfaces.wifi.security, ssid=wifi_access_point.interfaces.wifi.ssid, passphrase=wifi_access_point.interfaces.wifi.passphrase)
        time.sleep(2)
        wifi_dut.interfaces.wifi.start_ip_lwip()
        time.sleep(2)
        wifi_dut.interfaces.wifi.sl_net_up(mode='client')

        result = wifi_dut.interfaces.wifi.display_device_ip_lwip()
        time.sleep(2)
        dut_ip = wifi_dut.interfaces.wifi.get_device_ip(device_ip=result)
        timeout = 60

        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=dut_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("\n Start Receiving Data from Iperf Client \n")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=6,
                                           local_port=5201, local_ip=dut_ip,
                                           remote_ip=host_ip,
                                           remote_port=5201,
                                           size=size, ttl=timeout, throughput_type=throughput_type, timeout=timeout + 2,
                                           qos=0, host_tcp_ip_stack_enable=1)

        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        time.sleep(5)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

