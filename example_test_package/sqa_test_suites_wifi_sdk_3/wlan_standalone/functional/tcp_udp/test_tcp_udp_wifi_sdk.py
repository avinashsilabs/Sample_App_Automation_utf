import time
import pytest
import re
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

from utf.interfaces.wifi import SecurityMode, Standard
from utf.utf_config import UtfConfig

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
            self, thread_no, remote_socket, no_of_pkts, data_size, time_interval, wifi_dut, server_sock, local_port, server_ip,
            proto_type=0):

        proto_name = "TCP" if proto_type == 0 else "UDP"
        logger().info(f"[Thread {thread_no}] ========================================")
        logger().info(f"[Thread {thread_no}] Starting {proto_name} data transfer")
        logger().info(f"[Thread {thread_no}] Socket: {server_sock}, Packets: {no_of_pkts}, Size: {data_size} bytes")
        logger().info(f"[Thread {thread_no}] Server: {server_ip}:{local_port}, Interval: {time_interval}s")
        logger().info(f"[Thread {thread_no}] ========================================")

        bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(
            socket_id=server_sock, pkt_length=data_size, no_of_pkts=no_of_pkts, time_interval=time_interval,
            server_ip=server_ip, server_port=local_port)

        logger().info(f"[Thread {thread_no}] **** Sent {bytes_sent} bytes from DUT ****")
        
        timeout = 2
        if proto_type == 0:
            remote_socket.set_recv_timeout(socket_type=0, timeout=timeout)
        else:
            remote_socket.set_recv_timeout(socket_type=1, use_client_socket=True, timeout=timeout)
        
        for i in range(0, no_of_pkts):
            if proto_type == 0:
                data = remote_socket.recv_data_tcp(data_size, timeout=timeout)
                if i % 10 == 0 or i == 0:  # Log every 10th packet
                    logger().info(f'[Thread {thread_no}] TCP RX packet {i+1}/{no_of_pkts}, size: {len(data) if isinstance(data, str) else 0} bytes')
            else:
                data, address = remote_socket.recv_data_udp(data_size, timeout=timeout)
                if i % 10 == 0 or i == 0:  # Log every 10th packet
                    logger().info(f'[Thread {thread_no}] UDP RX packet {i+1}/{no_of_pkts}, size: {len(data) if isinstance(data, str) else 0} bytes')
            
            if not isinstance(data, str):
                logger().warning(f"[Thread {thread_no}] **** Unable to Receive on Socket: {server_sock} at packet {i+1} ****")
                break
            self.rcv_data = self.rcv_data + len(data)
            if self.rcv_data == len(bytes_sent):
                break

        remote_socket.socket_close_indication(1)
        
        logger().info(f"[Thread {thread_no}] ========================================")
        logger().info(f"[Thread {thread_no}] {proto_name} DATA TRANSFER COMPLETE")
        logger().info(f"[Thread {thread_no}] Total bytes received: {self.rcv_data} / {bytes_sent}")
        
        if proto_type == 0:
            logger().info(f"[Thread {thread_no}] ========================================")
            assert self.rcv_data == int(
                bytes_sent), f"Data transfer failed. Expected {bytes_sent} bytes but received {self.rcv_data} bytes"
        else:
            packet_loss = 100 - (int(self.rcv_data) * 100 / int(bytes_sent)) if int(bytes_sent) > 0 else 0
            logger().info(f"[Thread {thread_no}] UDP packet loss: {packet_loss:.2f}%")
            logger().info(f"[Thread {thread_no}] ========================================")


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
        
        logger().info("=" * 80)
        logger().info(f"STARTING DATA TRANSFER ON {len(server_socks)} TCP SOCKETS")
        logger().info("=" * 80)
        
        for count in range(0, 10):
            logger().info(f"Creating data transfer thread {count} for socket {server_socks[count]}")
            local_port = server_port + count
            data_transfer_objs.append(DataTransfer())

            socket_threads.append(Thread(target=data_transfer_objs[count].send_and_receive_data_socket,
                                         args=(
                                             count, client_sockets[count], no_of_pkts, pkt_length, time_interval,
                                             self.wifi_dut,
                                             server_socks[count], local_port, server_ip, 0), 
                                         daemon=True,
                                         name=f"DataTransfer-Socket{count}"))

        # Start all threads
        logger().info("Starting all data transfer threads...")
        for idx, thread in enumerate(socket_threads):
            thread.start()
            logger().info(f"Started thread {idx}: {thread.name}")
            time.sleep(2)

        # Wait for all threads to complete with timeout
        logger().info("Waiting for all threads to complete...")
        all_completed = True
        for idx, thread in enumerate(socket_threads):
            thread.join(timeout=60)  # 60 second timeout per thread
            if thread.is_alive():
                logger().error(f"Thread {idx} ({thread.name}) did not complete within timeout!")
                all_completed = False
            else:
                logger().info(f"Thread {idx} ({thread.name}) completed successfully")
        
        if all_completed:
            logger().info("=" * 80)
            logger().info("ALL DATA TRANSFER THREADS COMPLETED SUCCESSFULLY")
            logger().info("=" * 80)
        else:
            logger().error("=" * 80)
            logger().error("SOME DATA TRANSFER THREADS DID NOT COMPLETE!")
            logger().error("=" * 80)

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
                                             count+1, client_sockets[count], no_of_pkts, pkt_length, time_interval,
                                             self.wifi_dut,
                                             server_socks[count], local_port, server_ip, 1), daemon=True))

            socket_threads[count].start()
            socket_threads[count].join()

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
            socket_threads[count].join()

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

def per_socket_close_dut_marker(*, tls=False, ap=False, ap_ssid="WLAN_BLE_AP_C1726587", ap_passphrase="12345678", ap_channel=11, ap_security="Open"):
    """Build pytest.mark.config for C172657x WLAN+BLE per-socket-close tests (websocket wifi_dut_marker pattern)."""
    tcpip_features = (
        Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid
    )
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": tcpip_features,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
                               | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE
                               | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
    if tls:
        config["tcpip_features"] = tcpip_features | Si91xTCPIPFeatureBitMap.SSL
        config["ca_cert"] = [
            (
                "ca-chain.cert.pem",
                "SL_NET_SIGNING_CERTIFICATE",
                "SL_NET_TLS_SERVER_CREDENTIAL_START",
            )
        ]
    if ap:
        config["oper_mode"] = Si91xOperatingMode.AccessPoint
        config["tcpip_features"] = (
            Si91xTCPIPFeatureBitMap.DHCPv4Server
            | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
            | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid
        )
        config["security"] = ap_security
        config["ssid"] = ap_ssid
        config["passphrase"] = ap_passphrase
        config["channel"] = ap_channel
    return pytest.mark.config("wifi_dut", wifi=config)


class PerSocketCloseRemoteTerminateFlow:
    """Reusable WLAN+BLE per-socket-close test flow (C172657x series).

    Automates DUT socket setup, data transfer, remote termination handling, and host
    close for WiseConnect per-socket-close (WaitForSocketClose) validation. Pair with
    ``per_socket_close_dut_marker()`` for DUT pytest config (WLAN+BLE coex, global
    WaitForSocketClose ext_tcpip feature).

    **Full flow (typical pytest usage)**::

        @per_socket_close_dut_marker()
        def test_my_case(..., remote_socket, wifi_client):
            PerSocketCloseRemoteTerminateFlow(
                test_map_id="C1726572", dut_role="client",
            ).run(
                sniffer_filter, wifi_access_point, wifi_dut, sl_collections,
                wifi_sniffer, request, remote_socket, wifi_client,
            )

    **Partial reuse** — call public phase methods directly after constructing the flow
    (same pattern as ``WifiJoinThread`` scenario methods)::

        flow = PerSocketCloseRemoteTerminateFlow(test_map_id="C1726574", dut_role="multi_server")
        dut_addr = flow.join_dut_to_ap(wifi_dut, wifi_access_point, sl_collections)
        flow.device_ip = dut_addr["device_ip"]
        flow.setup_dut_multi_server_path(wifi_dut, remote_socket_factory, flow.device_ip)
        flow.verify_remote_terminate(wifi_dut)
        flow.close_dut_sockets(wifi_dut)
        flow.cleanup(wifi_dut, None, remote_socket_factory=remote_socket_factory)

    **Import from another test file**::

        from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.tcp_udp.test_tcp_udp_wifi_sdk import (
            per_socket_close_dut_marker,
            PerSocketCloseRemoteTerminateFlow,
        )

    ``dut_role`` selects the end-to-end scenario executed by ``run()``:

    ==============================  ==========  =======================================
    dut_role                        Test ID     Summary
    ==============================  ==========  =======================================
    ``client``                      C1726572    DUT TCP client TX; remote server stop → 0x62 → 0x43
    ``multi_server``                C1726574    10 DUT TCP servers; remote close during RX → 0x62 → 0x43
    ``tls_client``                  C1726576    DUT TLS client TX; remote SSL stop → 0x62 → 0x43
    ``client_graceful``             C1726579    DUT host graceful close (FIN, no 0x62)
    ``tls_client_tx``               C1726581    DUT TLS client send only (no close verify)
    ``client_graceful_loop``        C1726584    Repeat graceful connect/send/close for 24 h
    ``client_lan_unplug``           C1726585    Remote LAN down during TX → 0x62 → 0x43
    ``ap_client_remote_terminate``  C1726587    DUT AP + STA; TCP client remote close → 0x62 → 0x43
    ==============================  ==========  =======================================

    **Fixtures required by ``run()``** (depends on ``dut_role``):

    - All roles: ``sniffer_filter``, ``wifi_access_point``, ``wifi_dut``, ``sl_collections``,
      ``wifi_sniffer``, ``request``, ``wifi_client``
    - ``remote_socket``: client / graceful / LAN-unplug / AP-client roles
    - ``remote_socket_factory``: ``multi_server`` (pass ``remote_socket=None``)
    - ``ssl_server``: ``tls_client``, ``tls_client_tx`` (pass ``remote_socket=None``)

    **TA async events:** remote terminate = cmd **0x62**; host socket close =
    ``bsdAsyncSockClose`` cmd **0x43**.

    Per-socket ``bsdSetPerSocketWaitForSocketClose`` setsockopt (spec step 5) is deferred
    until firmware support; global WaitForSocketClose from the marker is still applied.

    All methods on this class are public for reuse. Key phases: ``join_dut_to_ap``,
    ``enable_power_save``, ``setup_dut_client_path``, ``setup_dut_multi_server_path``,
    ``setup_dut_tls_client_path``, ``receive_data_on_all_server_sockets``,
    ``trigger_remote_terminate_during_server_receive``, ``verify_remote_terminate``,
    ``close_dut_sockets``, ``client_graceful_flow``, ``client_graceful_loop_flow``,
    ``client_lan_unplug_flow``, ``tls_client_tx_flow``, ``ap_client_remote_terminate_flow``,
    ``cleanup``.
    """

    DEFAULT_LOOP_DURATION_SEC = 24 * 3600

    def __init__(
            self,
            test_map_id,
            dut_role="client",
            no_of_pkts=100,
            pkt_length=1460,
            local_port=5001,
            connect_retries=3,
            connect_retry_delay=10,
            num_client_sockets=10,
            num_server_sockets=10,
            loop_duration_sec=None,
    ):
        """Configure a per-socket-close flow instance.

        Args:
            test_map_id: TestRail / source map ID (e.g. ``'C1726572'``) used in log prefixes.
            dut_role: Scenario selector for ``run()`` — see class docstring for values.
            no_of_pkts: Number of TX/RX packet iterations per socket path.
            pkt_length: TCP/TLS payload size in bytes.
            local_port: Base DUT bind port; multi-server uses ``local_port + socket_index``.
            connect_retries: DUT connect attempts before assert failure.
            connect_retry_delay: Seconds between connect retries.
            num_client_sockets: Reserved for multi-client scenarios (default 10).
            num_server_sockets: DUT TCP server count for ``multi_server`` role (default 10).
            loop_duration_sec: Duration in seconds for ``client_graceful_loop`` (default 24 h).
        """
        self.test_map_id = test_map_id
        self.dut_role = dut_role
        self.no_of_pkts = no_of_pkts
        self.pkt_length = pkt_length
        self.local_port = local_port
        self.connect_retries = connect_retries
        self.connect_retry_delay = connect_retry_delay
        self.num_client_sockets = num_client_sockets
        self.num_server_sockets = num_server_sockets
        self.loop_duration_sec = loop_duration_sec or self.DEFAULT_LOOP_DURATION_SEC
        self.server_socket_id = None
        self.client_socket_id = None
        self.dut_socket_ids = []
        self.server_socket_ids = []
        self.client_socket_ids = []
        self.remote_servers = []
        self.remote_clients = []
        self.socket_ids_to_close = []
        self.device_ip = None
        self.ssl_server = None
        self.ssl_server_port = None
        self._remote_lan_iface = None
        self._remote_lan_unplugged = False

    def ensure_multi_socket_state(self):
        """Back-fill multi-socket fields when an older class body is partially deployed."""
        if not hasattr(self, 'num_client_sockets'):
            self.num_client_sockets = 10
        if not hasattr(self, 'num_server_sockets'):
            self.num_server_sockets = 10
        if not hasattr(self, 'loop_duration_sec'):
            self.loop_duration_sec = self.DEFAULT_LOOP_DURATION_SEC
        if not hasattr(self, 'dut_socket_ids'):
            self.dut_socket_ids = []
        if not hasattr(self, 'server_socket_ids'):
            self.server_socket_ids = []
        if not hasattr(self, 'client_socket_ids'):
            self.client_socket_ids = []
        if not hasattr(self, 'remote_servers'):
            self.remote_servers = []
        if not hasattr(self, 'remote_clients'):
            self.remote_clients = []
        if not hasattr(self, 'socket_ids_to_close'):
            self.socket_ids_to_close = []

    def log_phase(self, phase, message):
        logger().info(f"[{self.test_map_id} {phase}] {message}")

    def enable_power_save(self, wifi_dut, power_save):
        self.log_phase(
            "power_save",
            "Enable Wi-Fi and BT power save on DUT "
            "(set_performance_profile + rsi_bt_power_save_profile mode=2, type=0)",
        )
        if power_save:
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            wifi_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
            )
            self.log_phase("power_save", "Wi-Fi and BT power save enabled successfully")
        else:
            self.log_phase("power_save", "Skipped — harness power_save flag is not set")

    @staticmethod
    def parse_accepted_client_socket_id(accept_data):
        """Parse accepted client socket fd from bsdSocketAccept TA output ('Socket ID: N')."""
        if accept_data is None:
            raise ValueError("bsdSocketAccept returned no data")
        text = accept_data.decode('utf-8', errors='ignore') if isinstance(accept_data, bytes) else str(accept_data)
        match = re.search(r'Socket ID:\s*(\d+)', text)
        if match:
            return int(match.group(1))
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.isdigit():
                return int(stripped)
        raise ValueError(f"Could not parse accepted client socket ID from accept response: {text!r}")

    def connect_remote_tcp_client(self, remote_client, device_ip, dut_port):
        if remote_client.sock is not None:
            try:
                remote_client.sock.close()
            except Exception:
                pass
            remote_client.sock = None
        remote_client.connect_client_tcp(device_ip, dut_port, client_port=0)

    def close_remote_tcp_peer(self, remote_client):
        """Close remote TCP peer — prefer stop() (C1726572 / socket-select pattern)."""
        if hasattr(remote_client, 'stop'):
            try:
                remote_client.stop()
                return
            except Exception:
                pass
        if remote_client.sock is not None:
            try:
                remote_client.sock.close()
            except Exception:
                pass
            remote_client.sock = None

    def setup_dut_multi_server_path(self, wifi_dut, remote_socket_factory, device_ip):
        """Multi DUT TCP server sockets — create, setsockopt, bind, listen, accept."""
        num = self.num_server_sockets
        self.log_phase("socket_create", f"Create {num} TCP server sockets (sl_si91x_config_socket + Asyncsocket)")
        wifi_dut.interfaces.wifi.set_socket_config(
            total_sockets=num,
            total_tcp_sockets=num,
            tcp_rx_only_sockets=num,
            tcp_rx_high_performance_sockets=0,
        )
        self.server_socket_ids = []
        self.client_socket_ids = []
        self.remote_clients = []
        self.socket_ids_to_close = []

        for socket_index in range(num):
            server_socket_id = wifi_dut.interfaces.wifi.Asyncsocket(
                domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP")
            self.server_socket_ids.append(server_socket_id)
            self.log_phase(
                "socket_create", f"Created server socket index {socket_index}: socket_id={server_socket_id}")

        # Step 5 (per-socket close setsockopt) deferred — see comment above per_socket_close_dut_marker.

        self.log_phase("connect", f"Bind all {num} DUT TCP server sockets")
        for socket_index, server_socket_id in enumerate(self.server_socket_ids):
            dut_port = self.local_port + socket_index
            wifi_dut.interfaces.wifi.bind(
                socket_fd=server_socket_id, device_ip=device_ip,
                server_port=dut_port, timeout=5, asynch=1)
            self.log_phase("connect", f"Bound socket index {socket_index} on port {dut_port}")

        self.log_phase("connect", f"Listen on all {num} DUT TCP server sockets")
        for socket_index, server_socket_id in enumerate(self.server_socket_ids):
            wifi_dut.interfaces.wifi.listen(socket_fd=server_socket_id, backlog=1, asynch=1)
            self.log_phase("connect", f"Listening socket index {socket_index}: socket_id={server_socket_id}")

        self.log_phase("connect", f"Accept remote TCP clients on all {num} DUT server sockets")
        for socket_index, server_socket_id in enumerate(self.server_socket_ids):
            dut_port = self.local_port + socket_index
            remote_client = remote_socket_factory.interfaces.socket.create_socket()
            accept_results = ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.bsdSocketAccept, server_socket_id, 1),
                    (self.connect_remote_tcp_client, remote_client, device_ip, dut_port),
                ],
                timeout=40,
            )
            client_socket_id = self.parse_accepted_client_socket_id(accept_results[0])
            self.client_socket_ids.append(client_socket_id)
            self.remote_clients.append(remote_client)
            self.socket_ids_to_close.insert(0, client_socket_id)
            self.socket_ids_to_close.append(server_socket_id)
            self.log_phase(
                "connect", f"Accepted socket index {socket_index}: client_socket_id={client_socket_id}")
            time.sleep(1)

        self.server_socket_id = self.server_socket_ids[0]
        self.client_socket_id = self.client_socket_ids[0]

    def receive_data_on_all_server_sockets(self, wifi_dut):
        """Round-robin RX on all accepted client sockets (C19351/C780281 async pattern)."""
        self.log_phase("send", f"Receive TCP data on all {self.num_server_sockets} accepted sockets")
        tx_buffer = "X" * self.pkt_length
        for _ in range(self.no_of_pkts):
            for socket_index, client_socket_id in enumerate(self.client_socket_ids):
                dut_port = self.local_port + socket_index
                remote_client = self.remote_clients[socket_index]
                assert remote_client.sock is not None, (
                    f"Remote client index {socket_index} (port={dut_port}) not connected")
                remote_client.send_data_tcp(tx_buffer, use_server_socket=False)
                time.sleep(1)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(
                    socket_fd=client_socket_id, async_timeout=60)

    def trigger_remote_terminate_during_server_receive(self, wifi_dut, socket_index=0):
        """Close remote client while DUT is blocked in RX (TA cmd 0x62)."""
        remote_client = self.remote_clients[socket_index]
        client_socket_id = self.client_socket_ids[socket_index]
        recv_expected = [
            SLStatus.SL_STATUS_OK,
            SLStatus.SL_STATUS_SI91X_SOCKET_TX_OR_RX_FAIL,
            SLStatus.SL_STATUS_SI91X_TCP_SERVER_SOCKET_CLOSE_FAIL,
            SLStatus.SL_STATUS_SI91X_SOCKET_NOT_CONNECTED,
        ]
        self.log_phase(
            "remote_terminate",
            f"Block DUT recv on socket index {socket_index} while closing remote client",
        )
        try:
            ThreadBase.call_functions_simultaneously(
                [
                    (
                        wifi_dut.interfaces.wifi.bsdSocketReceiveFrom,
                        client_socket_id,
                        recv_expected,
                        10,
                        120,
                    ),
                    (self.close_remote_tcp_peer, remote_client),
                ],
                timeout=150,
            )
        except Exception as exc:
            self.log_phase(
                "remote_terminate",
                f"Simultaneous recv/remote-close finished: {exc}",
            )
        time.sleep(3)
        for _ in range(3):
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            time.sleep(1)

    def setup_dut_client_path(self, wifi_dut, remote_socket, wifi_client):
        self.log_phase("socket_create", "Create DUT TCP client socket")
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        remote_socket.interfaces.socket.start_server(port=self.local_port)
        self.server_socket_id = wifi_dut.interfaces.wifi.Asyncsocket(
            domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP")
        self.log_phase("socket_create", f"DUT TCP client socket created, socket_id={self.server_socket_id}")
        # Step 5 (per-socket close setsockopt) deferred — see comment above per_socket_close_dut_marker.
        self.log_phase("connect", "DUT TCP client bind and connect to remote server")
        wifi_dut.interfaces.wifi.bind(
            socket_fd=self.server_socket_id, device_ip=self.device_ip,
            server_port=self.local_port, timeout=5, asynch=1)
        connect_status = False
        for count in range(self.connect_retries):
            try:
                wifi_dut.interfaces.wifi.bsdSocketConnect(
                    socket_fd=self.server_socket_id, server_ip=server_ip, server_port=self.local_port)
                connect_status = True
                break
            except Exception:
                logger().info(f"Socket connect retry {count + 1}/{self.connect_retries}")
                time.sleep(self.connect_retry_delay)
        assert connect_status, "Socket connection failed in DUT"
        self.log_phase("connect", f"DUT connected to remote server {server_ip}:{self.local_port}")
        time.sleep(2)
        self.socket_ids_to_close = [self.server_socket_id]
        return server_ip

    def prepare_tcp_client(
            self, wifi_dut, remote_socket, wifi_client, power_save, *, remote_terminate_callback=False):
        self.enable_power_save(wifi_dut, power_save)
        if remote_terminate_callback:
            wifi_dut.interfaces.wifi.set_remote_terminate_callback()
        return self.setup_dut_client_path(wifi_dut, remote_socket, wifi_client)

    def client_send_during(self, wifi_dut, server_ip, action, *, action_phase="trigger"):
        self.log_phase("send", "Start DUT TCP client TX (send_data_pkts in background)")
        tx_thread = Thread(
            target=wifi_dut.interfaces.wifi.send_data_pkts,
            args=(self.server_socket_id, self.pkt_length, self.no_of_pkts, 1, server_ip, self.local_port),
            daemon=True,
        )
        tx_thread.start()
        time.sleep(2)
        self.log_phase(action_phase, f"Executing {action_phase} while DUT is sending")
        action()
        tx_thread.join(timeout=120)
        time.sleep(2)

    def client_graceful_send_and_host_close(self, wifi_dut, server_ip, remote_socket):
        """DUT TCP TX then graceful host close via bsdAsyncSockClose (FIN, not RST)."""
        self.log_phase("send", "Send TCP data from DUT client (send_data_pkts)")
        bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(
            socket_id=self.server_socket_id, pkt_length=self.pkt_length, no_of_pkts=self.no_of_pkts,
            time_interval=1, server_ip=server_ip, server_port=self.local_port)
        self.log_phase("send", f"DUT sent {bytes_sent} bytes")
        assert bytes_sent, "DUT failed to send TCP data in step 7"
        self.log_phase(
            "host_close",
            "Host close DUT socket via bsdAsyncSockClose — expect graceful FIN shutdown (not RST)",
        )
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=self.server_socket_id)
        remote_socket.interfaces.socket.socket_close_indication(1)
        time.sleep(2)
        wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
        self.log_phase("host_close", "Host close completed — DUT should have sent FIN for graceful shutdown")
        self.socket_ids_to_close = []

    def client_graceful_flow(self, wifi_dut, remote_socket, wifi_client, power_save):
        """C1726579: power save, socket, setsockopt, connect, send, host close."""
        server_ip = self.prepare_tcp_client(wifi_dut, remote_socket, wifi_client, power_save)
        self.client_graceful_send_and_host_close(wifi_dut, server_ip, remote_socket)
        remote_socket.interfaces.socket.stop()

    def client_graceful_loop_flow(self, wifi_dut, remote_socket, wifi_client, power_save):
        """C1726584: power save once, then repeat socket/connect/send/host-close for 24 hours."""
        self.enable_power_save(wifi_dut, power_save)
        loop_hours = self.loop_duration_sec // 3600
        self.log_phase(
            "loop",
            f"Repeat socket setup and graceful close in loop for {loop_hours} hours "
            f"({self.loop_duration_sec} seconds)",
        )
        loop_sw = Stopwatch()
        iteration = 0
        while loop_sw.elapsed_sec < self.loop_duration_sec:
            iteration += 1
            logger().info(
                f"[{self.test_map_id} loop] iteration {iteration}: "
                f"elapsed {loop_sw.elapsed_sec:.0f}s / {self.loop_duration_sec}s")
            try:
                remote_socket.interfaces.socket.stop()
            except Exception:
                pass
            server_ip = self.setup_dut_client_path(wifi_dut, remote_socket, wifi_client)
            self.client_graceful_send_and_host_close(wifi_dut, server_ip, remote_socket)
            try:
                remote_socket.interfaces.socket.stop()
            except Exception:
                pass
            time.sleep(1)
        self.log_phase(
            "loop",
            f"Loop completed: {iteration} iterations over {loop_sw.elapsed_sec:.0f}s "
            f"without failure",
        )

    def unplug_remote_lan_cable(self, wifi_client):
        """Simulate unplugging remote LAN cable by bringing its interface down."""
        iface = wifi_client.interfaces.wifi.config.get("interface", "eth0")
        self.log_phase(
            "lan_unplug",
            f"Plug out LAN cable on remote TCP server machine — "
            f"sudo ifconfig {iface} down",
        )
        wifi_client.interfaces.wifi.shell(f"sudo ifconfig {iface} down")
        self._remote_lan_iface = iface
        self._remote_lan_unplugged = True
        time.sleep(2)

    def restore_remote_lan_cable(self, wifi_client):
        """Restore remote interface after simulated LAN cable unplug."""
        if not self._remote_lan_unplugged or not self._remote_lan_iface:
            return
        try:
            logger().info(
                f"[{self.test_map_id}] Restoring remote interface "
                f"{self._remote_lan_iface} — sudo ifconfig up")
            wifi_client.interfaces.wifi.shell(f"sudo ifconfig {self._remote_lan_iface} up")
            time.sleep(5)
        except Exception as exc:
            logger().warning(f"Failed to restore remote LAN interface: {exc}")
        finally:
            self._remote_lan_unplugged = False

    def trigger_lan_unplug_during_client_send(self, wifi_dut, server_ip, wifi_client):
        """Unplug remote LAN while DUT is actively sending TCP data."""
        self.client_send_during(
            wifi_dut, server_ip,
            lambda: self.unplug_remote_lan_cable(wifi_client),
            action_phase="lan_unplug",
        )

    def client_lan_unplug_flow(self, wifi_dut, remote_socket, wifi_client, power_save):
        """C1726585: TCP client TX, remote LAN unplug during send, retries, socket close."""
        server_ip = self.prepare_tcp_client(
            wifi_dut, remote_socket, wifi_client, power_save, remote_terminate_callback=True)
        self.trigger_lan_unplug_during_client_send(wifi_dut, server_ip, wifi_client)
        self.verify_remote_terminate(wifi_dut)
        self.close_dut_sockets(wifi_dut)
        self.log_phase(
            "lan_unplug", "DUT completed TCP retries and proper socket closing after remote LAN unplug")
        try:
            remote_socket.interfaces.socket.stop()
        except Exception:
            pass
        self.restore_remote_lan_cable(wifi_client)

    def setup_dut_ap_and_sta_join(self, wifi_dut, wifi_client, sl_collections, power_save):
        """C1726587: WLAN+BLE AP mode, power save, 3rd party STA join + DHCP IP."""
        channel = wifi_client.interfaces.wifi.config.get("channel", 11)
        ssid = wifi_client.interfaces.wifi.config.get("ssid", "WLAN_BLE_AP_C1726587")
        passphrase = wifi_client.interfaces.wifi.config.get("passphrase", "12345678")
        security = wifi_client.interfaces.wifi.config.get("security", "Open")
        self.log_phase("connect", "Bring up DUT in AP mode (start_ap)")
        sl_collections.configure_dut_in_static_ip(
            wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
            static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(
            ssid=ssid, security=security, psk=passphrase, channel=channel,
            dtim_beacon_count=1, beacon_interval=100)
        self.device_ip = "192.168.100.76"
        self.log_phase("connect", f"DUT AP started — SSID {ssid}, channel {channel}")
        self.enable_power_save(wifi_dut, power_save)
        self.log_phase("connect", "3rd party STA joins DUT AP and obtains IP via DHCP")
        wifi_client.interfaces.wifi.join()
        time.sleep(10)
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        assert client_ip, "3rd party STA failed to get IP from DUT AP"
        self.log_phase("connect", f"3rd party STA connected with IP {client_ip}")

    def trigger_remote_server_close_during_client_send(self, wifi_dut, server_ip, remote_socket):
        """DUT TX while remote TCP server socket is closed."""
        def close_remote_server():
            self.log_phase("remote_close", "Close remote TCP server socket while DUT is sending")
            remote_socket.interfaces.socket.stop()

        self.client_send_during(
            wifi_dut, server_ip, close_remote_server, action_phase="remote_close")

    def ap_client_remote_terminate_flow(
            self, wifi_dut, remote_socket, wifi_client, sl_collections, power_save):
        """C1726587: DUT AP + STA, TCP client remote terminate (0x62) + host close (0x43)."""
        self.setup_dut_ap_and_sta_join(wifi_dut, wifi_client, sl_collections, power_save)
        server_ip = self.prepare_tcp_client(
            wifi_dut, remote_socket, wifi_client, power_save, remote_terminate_callback=True)
        self.trigger_remote_server_close_during_client_send(wifi_dut, server_ip, remote_socket)
        self.verify_remote_terminate(wifi_dut)
        self.close_dut_sockets(wifi_dut)
        self.log_phase(
            "host_close", "Host close completed — Cmd 0x43 after remote terminate event (0x62)")

    def tls_client_send_data_only(self, wifi_dut):
        """DUT TLS client TX (send_data_pkts)."""
        self.log_phase("send", "Send TLS data from DUT client (send_data_pkts)")
        bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(
            socket_id=self.server_socket_id, pkt_length=self.pkt_length,
            no_of_pkts=self.no_of_pkts, time_interval=1)
        self.log_phase("send", f"DUT sent {bytes_sent} bytes over TLS socket")
        assert bytes_sent, "DUT failed to send TLS data in step 7"

    def tls_client_tx_flow(self, wifi_dut, ssl_server, power_save):
        """C1726581: power save, socket, TLS setsockopt, connect, send."""
        self.enable_power_save(wifi_dut, power_save)
        self.setup_dut_tls_client_path(wifi_dut, ssl_server)
        self.tls_client_send_data_only(wifi_dut)

    def setup_dut_tls_client_path(self, wifi_dut, ssl_server):
        """Create TLS client socket, TCP_ULP setsockopt, TLS connect."""
        self.ssl_server = ssl_server
        self.ssl_server_port = ssl_server.interfaces.ssl.config["device_port1"]
        ssl_server.interfaces.ssl.start_server(port=self.ssl_server_port)
        server_ip = ssl_server.interfaces.ssl.server_ip

        self.log_phase("socket_create", "Create DUT TCP/TLS client socket (Asyncsocket SOCK_STREAM)")
        self.server_socket_id = wifi_dut.interfaces.wifi.Asyncsocket(
            domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP")

        self.log_phase("connect", "Setsockopt: TCP_ULP TLS (sl_si91x_setsockopt)")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(
            socket_fd=self.server_socket_id, option_name="TCP_ULP", option_val="tls_1_2")
        # Step 5 (per-socket close setsockopt) deferred — see comment above per_socket_close_dut_marker.

        self.log_phase("connect", f"Bind and TLS connect to remote server {server_ip}:{self.ssl_server_port}")
        wifi_dut.interfaces.wifi.bind(
            socket_fd=self.server_socket_id, device_ip=self.device_ip,
            server_port=self.local_port, timeout=5, asynch=1, ip_len=4)
        wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(
            socket_fd=self.server_socket_id, cert_index=0)
        connect_status = False
        for count in range(self.connect_retries):
            try:
                wifi_dut.interfaces.wifi.bsdSocketConnect(
                    socket_fd=self.server_socket_id, server_ip=server_ip,
                    server_port=self.ssl_server_port)
                connect_status = True
                break
            except Exception:
                logger().info(f"TLS socket connect retry {count + 1}/{self.connect_retries}")
                time.sleep(self.connect_retry_delay)
        assert connect_status, "TLS socket connection failed in DUT"
        time.sleep(2)
        self.socket_ids_to_close = [self.server_socket_id]
        return server_ip

    def tls_client_send_and_remote_terminate(self, wifi_dut):
        """DUT TLS TX while remote SSL server is closed (TA cmd 0x62)."""
        self.log_phase("send", "DUT TLS client TX (send_data_pkts)")
        tx_thread = Thread(
            target=wifi_dut.interfaces.wifi.send_data_pkts,
            args=(self.server_socket_id, self.pkt_length, self.no_of_pkts, 1),
            daemon=True,
        )
        tx_thread.start()
        time.sleep(2)
        self.log_phase("remote_close", "Close remote SSL server during DUT TLS TX")
        self.ssl_server.interfaces.ssl.stop_server()
        tx_thread.join(timeout=120)
        time.sleep(2)

    def start_client_data_transfer(self, wifi_dut, server_ip):
        self.log_phase("send", "DUT TCP client TX")
        tx_thread = Thread(
            target=wifi_dut.interfaces.wifi.send_data_pkts,
            args=(self.server_socket_id, self.pkt_length, self.no_of_pkts, 1, server_ip, self.local_port),
            daemon=True,
        )
        tx_thread.start()
        time.sleep(2)
        return tx_thread

    def verify_remote_terminate(self, wifi_dut, since_time=None):
        event_data_output = ""
        sw = Stopwatch()
        while sw.elapsed_sec < 60 and not event_data_output:
            time.sleep(2)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            if since_time is not None:
                events = wifi_dut.interfaces.wifi.get_async_events(
                    since_time=since_time, update_last_retrieved_timestamp=False)
            else:
                events = wifi_dut.interfaces.wifi.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.REMOTE_TERMINATE:
                    event_data_output = event.event_data
                    break
                if "Remote Terminate" in event.event_data:
                    event_data_output = event.event_data
                    break
        self.log_phase("remote_terminate", f"Async event data: {event_data_output}")
        assert event_data_output, "Remote terminate event (0x62) not received from TA"
        assert "Remote Terminate" in event_data_output, "Expected Remote Terminate in event data"
        self.log_phase("remote_terminate", "Remote terminate (0x62) received from TA successfully")

    def close_dut_sockets(self, wifi_dut):
        self.log_phase("host_close", "Host close DUT sockets (bsdAsyncSockClose / cmd 0x43)")
        for socket_id in self.socket_ids_to_close:
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket_id)
            self.log_phase("host_close", f"DUT socket close completed for socket_id={socket_id}")

    def cleanup(self, wifi_dut, remote_socket, remote_socket_factory=None, ssl_server=None):
        if ssl_server is not None:
            try:
                ssl_server.interfaces.ssl.stop_server()
            except Exception:
                pass
        elif remote_socket_factory is not None:
            try:
                remote_socket_factory.interfaces.socket.close_all()
            except Exception:
                pass
        elif remote_socket is not None:
            try:
                remote_socket.interfaces.socket.stop()
            except Exception:
                pass
        for socket_id in self.socket_ids_to_close:
            try:
                wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket_id)
            except Exception:
                pass

    def join_dut_to_ap(self, wifi_dut, wifi_access_point, sl_collections):
        """Join DUT to external AP (standalone — no dependency on WifiJoinThread)."""
        dut_addr = sl_collections.join_to_wifi_network(
            wifi_dut=wifi_dut,
            retry_count=3,
            wifi_access_point=wifi_access_point,
            associated=wifi_dut.interfaces.wifi.associated,
            ping_after_power_save=True,
            enc="ccmp",
        )
        logger().info(
            f"device_ip, device_mac : {dut_addr['device_ip']}, {dut_addr['dut_mac_address']}")
        return dut_addr

    def run(
            self,
            sniffer_filter,
            wifi_access_point,
            wifi_dut,
            sl_collections,
            wifi_sniffer,
            request,
            remote_socket,
            wifi_client,
            remote_socket_factory=None,
            ssl_server=None,
    ):
        """Execute the full per-socket-close flow for ``self.dut_role``.

        Orchestrates sniffer capture, Wi-Fi join (or AP+STA for AP role), power save,
        socket setup, data transfer, remote terminate / graceful close as applicable,
        0x62 verification, 0x43 host close, and cleanup. Exceptions are routed through
        ``sl_collections.exception_handling``; LAN-unplug role restores remote interface
        in ``finally``.

        Args:
            sniffer_filter: Sniffer filter fixture.
            wifi_access_point: External AP fixture (join path) or channel reference.
            wifi_dut: DUT Wi-Fi fixture.
            sl_collections: UTF sl_collections helper fixture.
            wifi_sniffer: Sniffer capture fixture.
            request: Pytest ``request`` fixture (test name for capture file).
            remote_socket: Remote TCP server/client fixture; ``None`` for multi-server/TLS.
            wifi_client: Remote STA / server IP fixture.
            remote_socket_factory: Required when ``dut_role`` is ``multi_server``.
            ssl_server: Required when ``dut_role`` is ``tls_client`` or ``tls_client_tx``.
        """
        self.ensure_multi_socket_state()
        try:
            test_name = request.node.name
            power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)

            sniffer_channel = wifi_access_point.interfaces.wifi.channel
            if self.dut_role == "ap_client_remote_terminate":
                sniffer_channel = wifi_client.interfaces.wifi.config.get("channel", sniffer_channel)
            wifi_sniffer.interfaces.capture.configure_interface(channel=sniffer_channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

            if self.dut_role == "ap_client_remote_terminate":
                self.ap_client_remote_terminate_flow(
                    wifi_dut, remote_socket, wifi_client, sl_collections, power_save)
            else:
                dut_addr = self.join_dut_to_ap(wifi_dut, wifi_access_point, sl_collections)
                self.device_ip = dut_addr['device_ip']

                if self.dut_role == "client_graceful":
                    self.client_graceful_flow(
                        wifi_dut, remote_socket, wifi_client, power_save)
                elif self.dut_role == "client_graceful_loop":
                    self.client_graceful_loop_flow(
                        wifi_dut, remote_socket, wifi_client, power_save)
                elif self.dut_role == "client_lan_unplug":
                    self.client_lan_unplug_flow(
                        wifi_dut, remote_socket, wifi_client, power_save)
                elif self.dut_role == "tls_client_tx":
                    if ssl_server is None:
                        raise ValueError("ssl_server fixture is required for tls_client_tx role")
                    self.tls_client_tx_flow(wifi_dut, ssl_server, power_save)
                else:
                    self.enable_power_save(wifi_dut, power_save)
                    remote_terminate_since_time = None
                    if self.dut_role != "multi_server":
                        wifi_dut.interfaces.wifi.set_remote_terminate_callback()

                    logger().info(
                        f"[{self.test_map_id}] Running per-socket close flow with "
                        f"dut_role={self.dut_role}, num_client_sockets={self.num_client_sockets}, "
                        f"num_server_sockets={self.num_server_sockets}")

                    if self.dut_role == "client":
                        server_ip = self.setup_dut_client_path(wifi_dut, remote_socket, wifi_client)
                        data_thread = self.start_client_data_transfer(wifi_dut, server_ip)
                        remote_socket.interfaces.socket.stop()
                        data_thread.join(timeout=120)
                    elif self.dut_role == "multi_server":
                        if remote_socket_factory is None:
                            raise ValueError(
                                "remote_socket_factory is required for multi_server role")
                        self.setup_dut_multi_server_path(wifi_dut, remote_socket_factory, self.device_ip)
                        self.receive_data_on_all_server_sockets(wifi_dut)
                        assert self.remote_clients, "No remote TCP clients available for step 10"
                        remote_terminate_since_time = time.perf_counter_ns()
                        wifi_dut.interfaces.wifi.set_remote_terminate_callback()
                        self.trigger_remote_terminate_during_server_receive(wifi_dut, socket_index=0)
                    elif self.dut_role == "tls_client":
                        if ssl_server is None:
                            raise ValueError("ssl_server fixture is required for tls_client role")
                        self.setup_dut_tls_client_path(wifi_dut, ssl_server)
                        self.tls_client_send_and_remote_terminate(wifi_dut)
                    else:
                        raise ValueError(f"Unsupported dut_role={self.dut_role!r}")

                    self.verify_remote_terminate(
                        wifi_dut, since_time=remote_terminate_since_time)
                    self.close_dut_sockets(wifi_dut)

            wifi_sniffer.interfaces.capture.stop_capture()

        except Exception as e:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

        finally:
            if self.dut_role == "client_lan_unplug":
                self.restore_remote_lan_cable(wifi_client)
            self.cleanup(
                wifi_dut, remote_socket, remote_socket_factory=remote_socket_factory,
                ssl_server=ssl_server)

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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19347')
def test_wifi_sdk_tcp_open_send_close_socket_c19347(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client):
    """This test case Verifies the tcp client socket is open, send data,close functionality"""
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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19347')
def test_wifi_sdk_tcp_open_send_close_socket_c19347(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client):
    """This test case Verifies the tcp client socket is open, send data,close functionality"""
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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19348')
def test_wifi_sdk_udp_open_send_data_close_socket_c19348(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client):
    """This test case Verifies the udp client socket is open, send data,close functionality"""
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
@pytest.mark.test_src_map_id('C19349')
def test_wifi_sdk_tcp_socket_dut_client_c19349(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client):
    """Verify 10 sockets functionality open 10 tcp client sockets and connect to server sockets and send data"""
    
    wifi_thread = None
    sockets_created = []
    
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     remote_socket_factory=remote_socket_factory, wifi_client=wifi_client)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        # ========================================================================
        # PERFORM DATA TRANSFER ON ALL SOCKETS
        # ========================================================================
        logger().info("=" * 80)
        logger().info("STARTING TCP DATA TRANSFER TEST")
        logger().info("=" * 80)
        
        wifi_thread.tcp_multiple_socket_dut_client()
        
        logger().info("=" * 80)
        logger().info("TCP DATA TRANSFER TEST COMPLETED SUCCESSFULLY")
        logger().info("=" * 80)

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
        logger().error(f"Test failed with exception: {e}")
        logger().error(f"Exception type: {type(e).__name__}")
        import traceback
        logger().error(f"Traceback:\n{traceback.format_exc()}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    
    finally:
        # Ensure sockets are closed in cleanup
        logger().info("=" * 80)
        logger().info("TEST CLEANUP - Ensuring all sockets are closed")
        logger().info("=" * 80)


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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19350')
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

        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []

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
@pytest.mark.test_src_map_id('C19352')
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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19356')
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
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
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
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        net_perf_client.interfaces.net_perf.close_files()
        net_perf_client.interfaces.net_perf.iperf_process.stop(10)

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
@pytest.mark.test_src_map_id('C19357')
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
    sock = 0
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
                                                      cert_index=tcp_window_size)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=host_ip, server_port=server_port)

        tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=tcp_message_size))
        logger().info(f"*********** Sending packet with size --> {len(tx_buffer)} bytes ***********")
        status, data = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=tx_buffer, higher_data_len=1, timeout=60, expected_status=SLStatus.SL_STATUS_FAIL)
        error_code_pattern = r"errno:\s+(\d+)"
        match = re.search(error_code_pattern, data)
        error_code = 0
        if match:
            error_code = match.group(1)
            logger().info(f"\n Encountered Error Code: {error_code}\n")
        assert int(error_code) == 40, f"\n The Expected Error Code is 40, got {int(error_code)} \n"
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
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
        if sock in wifi_dut.interfaces.wifi.sockets_info["sync_sockets"]:
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        net_perf_client.interfaces.net_perf.close_files()
        net_perf_client.interfaces.net_perf.iperf_process.stop(10)



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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19360')
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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19361')
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
        remote_socket.interfaces.socket.stop()
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)

    except Exception as error:
        remote_socket.interfaces.socket.stop()
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)



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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C71653')
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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19365')
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(2),
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
@pytest.mark.test_src_map_id('C19351')
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
            sock = wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_STREAM",
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

        logger().info(f"Processing {len(tcp_socks)} sockets with individual select() calls")
        
        for count, sock_no in enumerate(tcp_socks):
            try:
                tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
                buffer_length = len(tx_buffer)

                logger().info("=" * 80)
                logger().info(f"PROCESSING SOCKET {sock_no} (Index: {count})")
                logger().info("=" * 80)
                logger().info(f"Remote peer sending data over socket {sock_no} and data: {tx_buffer}")

                # Send data from client
                client_socket[count].send_data_tcp(tx_buffer, use_server_socket=False)
                time.sleep(1)

                # Calculate DUT socket ID (sock_no + 1)
                dut_socket_id = sock_no + 1

                # This avoids the errno:22 issue with numberOfFds exceeding firmware limits
                logger().info(f"Receiving directly from DUT socket ID: {dut_socket_id} (matching C code behavior)")
                
                # Directly receive data without select() call
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=dut_socket_id)

                # Validate received data
                if buffer_rx is None or (isinstance(buffer_rx, bytes) and len(buffer_rx) == 0):
                    logger().error(f"Received NULL or empty data from socket {dut_socket_id}")
                    raise AssertionError(
                        f"No data received on DUT socket {dut_socket_id} "
                        f"(expected {buffer_length} bytes)"
                    )

                # Convert buffer_rx to string if it's bytes
                if isinstance(buffer_rx, bytes):
                    buffer_rx = buffer_rx.decode('utf-8', errors='ignore')

                logger().info(f"###################### Buffer Data: {buffer_rx} ######################")
                logger().info(f"###################### Buffer Data Length: {buffer_length} ######################")
                logger().info(f"###################### Received Data Length: {len(buffer_rx)} ######################")

                # Validate data integrity
                assert tx_buffer == buffer_rx, (
                    f"Data mismatch on socket {sock_no} (DUT socket {dut_socket_id}): "
                    f"\nExpected ({buffer_length} bytes): {tx_buffer}"
                    f"\nReceived ({len(buffer_rx)} bytes): {buffer_rx}"
                )

                logger().info(f"✓ Data verification PASSED for socket {sock_no}")
                logger().info("Data sent by remote peer and received on DUT is matching")
                logger().info("=" * 80)

            except AssertionError as ae:
                logger().error(f"Assertion Error on socket {sock_no}: {ae}")
                raise

            except Exception as e:
                logger().error(f"Unexpected error processing socket {sock_no}: {e}")
                logger().error(f"Exception type: {type(e).__name__}")
                logger().error(f"Exception details: {str(e)}")
                import traceback
                logger().error(f"Traceback:\n{traceback.format_exc()}")
                raise AssertionError(
                    f"Failed to process socket {sock_no} (index {count}): {e}"
                ) from e

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        
        # Close server sockets only - accepted client sockets are automatically closed
        for sock_id in tcp_socks:
            logger().info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)

    except Exception as e:
        # Close server sockets on error
        for sock_id in tcp_socks:
            logger().info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(2),
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
@pytest.mark.test_src_map_id('C19353')
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
        for socket in udp_socks:
            logger().info(f"Closing socket_id->{socket}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket)
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
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19362')
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
@pytest.mark.test_src_map_id('C19354')
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
@pytest.mark.test_src_map_id('C19366')
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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148603')
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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19367')
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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C584247')
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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19364')
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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19359')
def test_wifi_socket_limit_C19359(wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections, sniffer_filter, remote_socket,
        wifi_client):
    """ Open more than one socket when only one socket is selected in opermode command."""

    try:
        local_port = 8001
        device_port = 8002
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
@pytest.mark.test_src_map_id('C586158')
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
        keepalive_time = 300
        listen_intervals = [500, 700, 1000]
        test_name = request.node.name
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"SERVER-IP: {server_ip}")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        for listen_interval in listen_intervals:
            logger().info(f"\n\n ***** Starting the Keep Alive Validation with listen interval {listen_interval} ms "
                          f"***** \n\n")
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
@pytest.mark.test_src_map_id('C586159')
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
        keepalive_time = 300
        dtim_intervals = [1, 3, 5]
        test_name = request.node.name
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"SERVER-IP: {server_ip}")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        for dtim_interval in dtim_intervals:
            logger().info(f"\n\n ***** Starting the Keep Alive Validation with dtim interval {dtim_interval} ms "
                          f"***** \n\n")
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
@pytest.mark.test_src_map_id('C585534')
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
@pytest.mark.config(
    "wifi_client", wifi={"interface": "wlan0", "ip_address": "192.168.0.1"}
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
@pytest.mark.test_src_map_id('C780281')
def test_wifi_sdk_raspi_ap_and_dut_tcp_data_receive_check_c780281(wifi_sniffer, wifi_dut, wifi_client, request, sl_collections,
                                                sniffer_filter, remote_socket_factory):
    """Bring up Raspi in AP mode and DUT in station mode, Validation TCP data receive on DUT from Raspi AP."""
    try:
        test_name = request.node.name
        logger().info(f"***********************request.node.name************************** : {test_name}")
        ssid = "WPA2_SECURITY_TEST"
        channel = 8
        passphrase = "mypassword123"
        power_save = True
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

        wifi_client.interfaces.wifi.start_ap(
            ssid=ssid,
            security=SecurityMode.WPA2,
            passphrase=passphrase,
            channel=channel,
            standard=Standard.n,
            region = 'US'
        )
        logger().info(f"\n **** Access Point started with SSID: {ssid}, Channel: {channel} ****\n")
        ap_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")
        wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
        wifi_dut.interfaces.wifi.join(ssid=ssid,
                                      channel=channel,
                                      passphrase=passphrase,
                                      security="wpa2")
        logger().info(f"\n **** DUT joined the Access Point with SSID: {ssid}, Channel: {channel} ****\n")
        ip_obj = wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_obj)
        logger().info(f"\n **** Device IP Address: {device_ip} ****\n")

        if power_save:
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        wireless_info = wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()
        ip_address = str(wifi_dut.interfaces.wifi.get_ip_address())

        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        socket_id = wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                         protocol="IPPROTO_TCP")
        logger().info(f"Socket open successfully : {socket_id}")
        logger().info(f"Successfully opened tcp client socket and socket id received is {socket_id} which is expected")
        local_port = 5001
        wifi_dut.interfaces.wifi.bind(socket_fd=socket_id, device_ip=device_ip,
                                      server_port=local_port, timeout=5, asynch=1)

        wifi_dut.interfaces.wifi.listen(socket_fd=socket_id, backlog=1, asynch=1)

        ThreadBase.call_functions_simultaneously(
            [
                (wifi_dut.interfaces.wifi.bsdSocketAccept, socket_id, 1),
                (
                    client_socket.connect_client_tcp,
                    device_ip,
                    local_port,
                ),
            ],
            timeout=40,
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
            sa_addr=dut_mac_address, filter_name="ps_poll")
        logger().info(f"***** Validating PS POLL Packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find PS POLL Packets"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@per_socket_close_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C1726572')
def test_wifi_sdk_tcp_client_tx_per_socket_close_remote_terminate_c1726572(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket, wifi_client):
    """C1726572: WLAN+BLE TCP client TX, per-socket close setsockopt, remote terminate (0x62), host close (0x43)."""
    PerSocketCloseRemoteTerminateFlow(
        test_map_id='C1726572',
        dut_role="client",
    ).run(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket, wifi_client)


# C1726579 — WLAN+BLE TCP client graceful host close (FIN not RST):
# 1 WLAN+BLE init | 2 Wi-Fi join | 3 power save | 4 socket create |
# 5 per-socket close setsockopt (deferred) | 6 connect | 7 send | 8 host close
@per_socket_close_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C1726579')
def test_wifi_sdk_tcp_client_per_socket_close_graceful_host_close_c1726579(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket, wifi_client):
    """C1726579: WLAN+BLE TCP client — per-socket close setsockopt, TX, graceful host close (FIN not RST)."""
    PerSocketCloseRemoteTerminateFlow(
        test_map_id='C1726579',
        dut_role="client_graceful",
    ).run(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket, wifi_client)


# C1726584 — WLAN+BLE TCP client graceful close loop for 24 hours:
# 1 WLAN+BLE init | 2 Wi-Fi join | 3 power save |
# 4-8 socket/connect/send/graceful host close (FIN not RST) | 9 repeat 4-8 for 24h
# (step 5 per-socket close setsockopt deferred)
@per_socket_close_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C1726584')
def test_wifi_sdk_tcp_client_per_socket_close_graceful_host_close_24h_loop_c1726584(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket, wifi_client):
    """C1726584: WLAN+BLE TCP client — repeat steps 4-8 (graceful FIN close) in loop for 24 hours."""
    PerSocketCloseRemoteTerminateFlow(
        test_map_id='C1726584',
        dut_role="client_graceful_loop",
        no_of_pkts=20,
        pkt_length=50,
        loop_duration_sec=24 * 3600,
    ).run(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket, wifi_client)


@per_socket_close_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C1726574')
def test_wifi_sdk_multi_tcp_server_per_socket_close_remote_terminate_c1726574(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client):
    """C1726574: WLAN+BLE 10 DUT TCP server sockets, bind/listen/accept/RX, remote terminate (0x62), host close (0x43)."""
    PerSocketCloseRemoteTerminateFlow(
        test_map_id='C1726574',
        dut_role="multi_server",
        num_server_sockets=10,
        no_of_pkts=20,
        pkt_length=50,
    ).run(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket=None, wifi_client=wifi_client, remote_socket_factory=remote_socket_factory)


@per_socket_close_dut_marker(tls=True)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C1726576')
def test_wifi_sdk_tls_client_per_socket_close_remote_terminate_c1726576(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        ssl_server, wifi_client):
    """C1726576: WLAN+BLE TLS client TX, TCP_ULP + per-socket close setsockopt, remote terminate (0x62), host close (0x43)."""
    PerSocketCloseRemoteTerminateFlow(
        test_map_id='C1726576',
        dut_role="tls_client",
        no_of_pkts=100,
        pkt_length=1460,
    ).run(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket=None, wifi_client=wifi_client, ssl_server=ssl_server)


# C1726581 — 7-step WLAN+BLE TLS client TX with TCP_ULP + per-socket close setsockopt:
# 1 WLAN+BLE init | 2 Wi-Fi join | 3 power save | 4 socket create |
# 5 TCP_ULP TLS + per-socket close setsockopt | 6 TLS connect | 7 send TLS data
@per_socket_close_dut_marker(tls=True)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C1726581')
def test_wifi_sdk_tls_client_per_socket_close_send_data_c1726581(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        ssl_server, wifi_client):
    """C1726581: WLAN+BLE TLS client — TCP_ULP setsockopt, per-socket close, TLS connect, send data."""
    PerSocketCloseRemoteTerminateFlow(
        test_map_id='C1726581',
        dut_role="tls_client_tx",
        no_of_pkts=100,
        pkt_length=1460,
    ).run(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket=None, wifi_client=wifi_client, ssl_server=ssl_server)


# C1726585 — WLAN+BLE TCP client remote LAN unplug during TX:
# 1 WLAN+BLE init | 2 Wi-Fi join | 3 power save | 4 socket create |
# 5 per-socket close setsockopt (deferred) | 6 connect | 7 send | 8 unplug remote LAN
@per_socket_close_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C1726585')
def test_wifi_sdk_tcp_client_per_socket_close_remote_lan_unplug_c1726585(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket, wifi_client):
    """C1726585: WLAN+BLE TCP client — per-socket close, TX, remote LAN unplug, TCP retries, socket close."""
    PerSocketCloseRemoteTerminateFlow(
        test_map_id='C1726585',
        dut_role="client_lan_unplug",
        no_of_pkts=100,
        pkt_length=1460,
    ).run(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket, wifi_client)


# C1726587 — 9-step WLAN+BLE DUT AP + STA remote terminate flow:
# 1 WLAN+BLE init | 2 DUT AP | 3 power save + STA join | 4-6 socket/setsockopt/connect |
# 7 send | 8 close remote server (0x62) | 9 host close (0x43)
@pytest.mark.wifi_client("raspi_wifi")
@per_socket_close_dut_marker(ap=True)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_client",
    wifi={
        "ssid": "WLAN_BLE_AP_C1726587",
        "passphrase": "12345678",
        "security": "Open",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '12345678', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C1726587')
def test_wifi_sdk_ap_tcp_client_per_socket_close_remote_terminate_c1726587(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket, wifi_client):
    """C1726587: WLAN+BLE DUT AP — STA join, TCP client TX, remote server close (0x62), host close (0x43)."""
    PerSocketCloseRemoteTerminateFlow(
        test_map_id='C1726587',
        dut_role="ap_client_remote_terminate",
        no_of_pkts=100,
        pkt_length=1460,
    ).run(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket, wifi_client)

