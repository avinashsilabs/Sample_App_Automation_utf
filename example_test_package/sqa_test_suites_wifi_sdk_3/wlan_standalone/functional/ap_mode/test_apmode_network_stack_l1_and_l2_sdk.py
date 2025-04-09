import re
import time
import pytest
from retry import retry
import test_apmode_sdk as ap
import string
import threading
import random
from utf.interfaces.socket import SOCKET_TYPE_TCP, SOCKET_TYPE_UDP
from threading import Thread
from random import randint
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
import concurrent.futures
import pytest as pytest
from utf.utils import get_random_data
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf import UtfDatabaseProperties
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
import threading
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtCustomFeatureBitMap
from utf_wiseconnect_3.tests.sl_status import SLStatus



def logger():
    return get_logger(__name__)

"""Test Author = Jyothi Nagireddy & Vasavi Kalla

        1. Start the sniffer before connection
        2. Required A7 EVK(DUT) board 
        3. Stop the sniffer
        4. Initiate ping from the dut
        5. Analysing all sniffer capture packets and find the arp announcement packet

setup requirement:
        1. DUT
        2. Raspberry PI4 - 2 and more
        3. Access Point(Third Party AP's)
"""

socket_list = {
    "async_socket": [],
    "sync_socket": [],
}

class TCPThread(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        remote_socket_factory=None,
        remote_ip_address=None,
        dut_addr=None,
        client_socket=None,
        transfer_type=None,
        port_number=None,
    ):
        super().__init__()
        self.thread_lock = threading.Lock()
        self.wifi_dut = wifi_dut
        self.remote_socket_factory = remote_socket_factory
        self.remote_ip_address = remote_ip_address
        self.dut_addr = dut_addr
        self.client_socket = client_socket
        self.transfer_type = transfer_type
        self.port_number = port_number

    def run(self):
        if True:
            global socket_list
            keepalive_time = 60
            self.socket_fd = (
                self.wifi_dut.interfaces.wifi.socket(
                    domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP"
                )
                if self.transfer_type == "TX"
                else self.wifi_dut.interfaces.wifi.Asyncsocket(
                    domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP"
                )
            )
            # Append the sync and async sockets to the list to close the sockets at the end of the testcase
            if (
                self.transfer_type == "TX"
                and self.socket_fd not in socket_list["sync_socket"]
            ):
                socket_list["sync_socket"].append(self.socket_fd)
            if (
                self.transfer_type == "RX"
                and self.socket_fd not in socket_list["async_socket"]
            ):
                socket_list["async_socket"].append(self.socket_fd)

            self.client_socket = (
                self.remote_socket_factory.interfaces.socket.create_socket()
            )
            if self.transfer_type == "TX":
                self.client_socket.start_server(port=self.port_number)
            self.wifi_dut.interfaces.wifi.bind(
                socket_fd=self.socket_fd,
                device_ip=self.dut_addr['dut_ip'],
                server_port=self.port_number,
                timeout=5,
                asynch=0 if self.transfer_type == "TX" else 1,
            )
            logger().info(f"bind API is invoked")
            if self.transfer_type != "TX":
                self.wifi_dut.interfaces.wifi.listen(
                    socket_fd=self.socket_fd, backlog=1, asynch=1
                )
                logger().info(f"listen API is invoked")
                ThreadBase.call_functions_simultaneously(
                    [
                        (
                            self.wifi_dut.interfaces.wifi.bsdSocketAccept,
                            self.socket_fd,
                            1,
                        ),
                        (
                            self.client_socket.connect_client_tcp,
                            self.dut_addr['dut_ip'],
                            self.port_number,
                        ),
                    ],
                    timeout=10,
                )
                return
            logger().info(
                f"Setting the socket option SO_KEEPALIVE with {keepalive_time} seconds"
            )
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
                socket_fd=self.socket_fd,
                option_name="SO_KEEPALIVE",
                option_val=keepalive_time,
            )
            for count in range(3):
                connect_status = False
                if True:
                    self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                        socket_fd=self.socket_fd,
                        server_ip=self.remote_ip_address,
                        server_port=self.port_number,
                    )
                    connect_status = True
                    # break
                # except:
                #     logger().info(
                #         f"Socket connection failed in DUT...retry_count:{count + 1}"
                #     )
                # assert connect_status, "Socket connection failed in DUT"
        # except Exception as e:
        #     logger().info(
        #         f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n"
        #     )

    def transmit_tcp_data(self):
        duration = 60
        sw = Stopwatch()
        logger().info(f"\n Starting the TCP TX data Transfer \n")
        while sw.elapsed_sec < duration:
            sent_data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=20)
            )
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketSend(
                    socket_fd=self.socket_fd, data=sent_data, higher_data_len=0
                )
                self.client_socket.set_recv_timeout(socket_type=0)
                received_data = self.client_socket.recv_data_tcp(len(sent_data))
                logger().info(
                    f"\n###################### Received TCP Data: {received_data} ######################\n"
                )
                assert (
                    sent_data == received_data
                ), f"Data mismatch in sent and received data"
            except Exception as e:
                logger().info(
                    f"\n Socket Data Transfer Failed Within Duration: {sw.elapsed_sec} \n"
                )
                break

    def recv_tcp_data(self, recv_sock_id=None):
        duration = 60
        sw = Stopwatch()
        logger().info(f"\n Starting the TCP RX Data Transfer \n")
        while sw.elapsed_sec < duration:
            sent_data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=20)
            )
            self.client_socket.send_data_tcp(sent_data)
            time.sleep(1)
            received_data = self.wifi_dut.interfaces.wifi.bsdSocketReceive(
                recv_sock_id + 1
            )
            logger().info(
                f"###################### Buffer TCP Data  {received_data}  ######################"
            )
            logger().info(
                f"###################### Buffer TCP Data Length  {len(received_data)}  ######################"
            )
            assert sent_data == received_data, (
                f"buffer length sent by remote peer and received on the socket id "
                f"{self.socket_fd} opened in the DUT didn't matched"
            )
            logger().info("Data received successfully")
        self.client_socket.socket_close_indication(1)


class UDPThread(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        remote_socket_factory=None,
        remote_ip_address=None,
        dut_addr=None,
        client_socket=None,
        transfer_type=None,
        port_number=None,
    ):
        super().__init__()
        self.thread_lock = threading.Lock()
        self.wifi_dut = wifi_dut
        self.remote_socket_factory = remote_socket_factory
        self.remote_ip_address = remote_ip_address
        self.dut_addr = dut_addr
        self.client_socket = client_socket
        self.transfer_type = transfer_type
        self.port_number = port_number

    def run(self):
        if True:
            global socket_list
            keepalive_time = 60
            self.socket_fd = (
                self.wifi_dut.interfaces.wifi.socket(
                    domain="AF_INET", stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP"
                )
                if self.transfer_type == "TX"
                else self.wifi_dut.interfaces.wifi.Asyncsocket(
                    domain="AF_INET", stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP"
                )
            )
            # Append the sync and async sockets to the list to close the sockets at the end of the test
            if (
                self.transfer_type == "TX"
                and self.socket_fd not in socket_list["sync_socket"]
            ):
                socket_list["sync_socket"].append(self.socket_fd)
            if (
                self.transfer_type == "RX"
                and self.socket_fd not in socket_list["async_socket"]
            ):
                socket_list["async_socket"].append(self.socket_fd)
            self.client_socket = (
                self.remote_socket_factory.interfaces.socket.create_socket()
            )
            logger().info(f"Starting the Remote Server Socket")
            self.client_socket.start_server(port=self.port_number, socket_type=1)
            self.wifi_dut.interfaces.wifi.bind(
                socket_fd=self.socket_fd,
                device_ip=self.dut_addr["dut_ip"],
                server_port=self.port_number,
                timeout=5,
                asynch=0 if self.transfer_type == "TX" else 1,
            )
            if self.transfer_type == "TX":
                logger().info(
                    f"Setting the socket option SO_KEEPALIVE with {keepalive_time} seconds"
                )
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
                    socket_fd=self.socket_fd,
                    option_name="SO_KEEPALIVE",
                    option_val=keepalive_time,
                )
            for count in range(3):
                connect_status = False
                if True:
                    self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                        socket_fd=self.socket_fd,
                        server_ip=self.remote_ip_address,
                        server_port=self.port_number,
                    )
                    connect_status = True
                #     break
                # except:
                #     logger().info(
                #         f"Socket connection failed in DUT...retry_count:{count + 1}"
                #     )
                assert connect_status, "Socket connection failed in DUT"
        # except Exception as e:
        #     logger().info(
        #         f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n"
        #     )

    def transmit_udp_data(self):
        duration = 60
        sw = Stopwatch()
        logger().info(f"\n Starting the UDP TX data Transfer \n")
        while sw.elapsed_sec < duration:
            sent_data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=20)
            )
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketSend(
                    socket_fd=self.socket_fd, data=sent_data, higher_data_len=0
                )
                self.client_socket.set_recv_timeout(
                    socket_type=1, use_client_socket=True
                )
                received_data = self.client_socket.recv_data_udp(len(sent_data))[0]
                logger().info(
                    f"\n###################### Received UDP Data: {received_data} ######################\n"
                )
                assert (
                    sent_data == received_data
                ), f"Data mismatch in sent and received data"
            except Exception as e:
                logger().info(
                    f"Socket Data Transfer Failed Within Duration: {sw.elapsed_sec}"
                )
                break

    def rev_udp_data(self, recv_sock_id=None):
        duration = 60
        sw = Stopwatch()
        logger().info(f"\n Starting the UDP RX data Transfer \n")
        while sw.elapsed_sec < duration:
            sent_data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=20)
            )
            self.client_socket.send_data_udp(
                sent_data, self.dut_addr["dut_ip"], port=self.port_number
            )
            time.sleep(1)
            self.wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            received_data = self.wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(
                socket_fd=recv_sock_id
            )
            logger().info(
                f"###################### Buffer UDP Data  {received_data}  ######################"
            )
            logger().info(
                f"###################### Buffer UDP Data Length  {received_data}  ######################"
            )
            assert len(sent_data) == len(
                received_data
            ), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "
            assert (
                sent_data == received_data
            ), f"Data mismatch in sent and received data"

class IperfThread(ThreadBase):

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None, wifi_client=None,
        test_id=None, traffic_type=None, protocol=None, net_perf_client=None, timeout=60,
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
        logger().info(f"initiating traffic in {self.protocol} with type {self.traffic_type}")
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

class data_transfer:
    def __init__(self):
        self.thread_lock = threading.Lock()
        self.sent_data = 0
        self.rcv_data = 0

    def send_and_receive_data_socket(self, remote_socket, no_of_pkts, data_size, time_interval,
                                     wifi_dut, server_sock, local_port, server_ip,
                                     proto_type=0):

        bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(
            socket_id=server_sock, pkt_length=data_size, no_of_pkts=no_of_pkts, time_interval=time_interval,
            server_ip=server_ip, server_port=local_port)

        logger().info(f"Number of bytes sent by dut {bytes_sent}")

        fail_count = 0
        if proto_type == 0:
            remote_socket.set_recv_timeout(socket_type=0)
        else:
            remote_socket.set_recv_timeout(socket_type=1)

        for i in range(0, no_of_pkts):
            if proto_type == 0:
                data = remote_socket.recv_data_tcp(data_size)
                logger().info(f"data : {data}")
            else:
                data, address = remote_socket.recv_data_udp(data_size)
                logger().info(f"data : {data}")
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

class DataTransfer(ThreadBase):
    def __init__(self, wifi_dut, remote_socket, utf_constants, dut_ip=None, data=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.remote_socket = remote_socket
        self.utf_constants = utf_constants
        self.dut_ip = dut_ip
        self.data = data

    def run(self):
        logger().info("Starting TCP server socket remotely")
        local_port = randint(6000, 6100)
        self.remote_socket.interfaces.socket.interface = "wlan0"
        logger().info("Starting TCP Server socket at remote device")
        self.remote_socket.interfaces.socket.start_server(port=local_port)
        server_ip = self.remote_socket.interfaces.socket.hostname_or_ip_address()
        time.sleep(5)
        server_port = self.remote_socket.interfaces.socket.server_port

        logger().info(f"DUT opens tcp client socket")
        tcp_socket_id = self.wifi_dut.interfaces.wifi.socket()
        logger().info(f"Socket open successfully : {tcp_socket_id}")
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {tcp_socket_id} which is expected")
        logger().info(f"Socket binds at (device_ip, 5001) in DUT")
        bind_response = self.wifi_dut.interfaces.wifi.bind(socket_fd=tcp_socket_id, device_ip=self.dut_ip,
                                                      server_port=server_port,
                                                      timeout=5)
        logger().info(f"Bind socket successfully: {bind_response}")

        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=tcp_socket_id, server_ip=server_ip,
                                                          server_port=server_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")
        for packets in range(10):
            logger().info("DUT Sending Data packets")
            bytes_sent = self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=tcp_socket_id, data=self.data, timeout=60)
            logger().info(f"Number of bytes sent by dut {bytes_sent}")



class Disconnection(ThreadBase):
    def __init__(self, wifi_clients):
        super().__init__()
        self.wifi_clients = wifi_clients

    def run(self):
        self.wifi_clients[0].interfaces.wifi.leave()

class MultiSocketsConnectionTx(ThreadBase):
    def __init__(self, wifi_dut, wifi_client, remote_socket_factory, utf_constants, host_ip=None, dut_ip=None, socket_count=None, dut_socket_close=False, remote_close=False):
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.remote_socket_factory = remote_socket_factory
        self.utf_constants = utf_constants
        self.host_ip = host_ip
        self.dut_ip = dut_ip
        self.socket_count = socket_count
        self.dut_socket_close = dut_socket_close
        self.remote_close = remote_close


    def multi_sockets_tx(self, socket_count=None):
        self.socket_count = socket_count
        client_ips = []
        client_sockets = []
        for _ in range(1, self.socket_count + 1):
            client_ips.append(self.host_ip)
            client_socket = self.remote_socket_factory.interfaces.socket.create_socket()
            client_sockets.append(client_socket)
        server_base_port = 5001
        dut_sockets = []
        for index, client_socket in enumerate(client_sockets):
            client_ip = client_ips[index]
            server_port = server_base_port + index
            client_socket.start_server(server_ip=client_ip, port=server_port)
            time.sleep(2)
            logger().info(f"opening socket_id_{index}")
            tcp_socket_id = self.wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP",
                                                   timeout=15)
            logger().info(f"socket id received is {tcp_socket_id} which is expected")
            if isinstance(tcp_socket_id, int):
                logger().info(f"Socket open successfully : {tcp_socket_id}")
            else:
                logger().error(f"Unable to open socket id: {tcp_socket_id}")
                raise RuntimeError(tcp_socket_id)
            dut_sockets.append(tcp_socket_id)
            time.sleep(5)
            bind_response = self.wifi_dut.interfaces.wifi.bind(tcp_socket_id, self.dut_ip, server_port)
            if bind_response.decode().split(">")[1].replace("'", '').strip() == 'success':
                logger().info(f"Bind socket successfully: {bind_response}")
            else:
                logger().error(f"Unable to bind socket: {bind_response}")
                raise RuntimeError(bind_response)
            time.sleep(3)
            retry_limit: int = 2
            connect_status = False
            for retry in range(1, retry_limit):
                logger().info(f"connecting to the server")
                connect_response = self.wifi_dut.interfaces.wifi.bsdSocketConnect(tcp_socket_id, self.host_ip, server_port=server_port)
                logger().info(f"Connect response : {connect_response}")
                if connect_response.decode() == '':
                    logger().info(f"Unable to connect socket: {connect_response} in {retry} try")
                    if retry < retry_limit:
                        pass
                elif connect_response.decode().split(">")[1].strip() == 'success':
                    logger().info(f"Socket connected successfully in {retry} try")
                    connect_status = True
                    break
                logger().info(f"Socket connected with server in: {retry + 1} time")
            if connect_status is False:
                logger().info("Unable to connect with Server")
                assert connect_status
        data_sent = []
        for _ in client_sockets:
            data_sent.append(get_random_data(20))
        sw = Stopwatch()
        while sw.elapsed_sec < 300:
              results = ThreadBase.call_functions_simultaneously(
                 [(self.wifi_dut.interfaces.wifi.send_data, dut_sockets[index], len(data), data) for index, data in
                   enumerate(data_sent)]
               )
              for index, client_socket in enumerate(client_sockets):
                 data = data_sent[index]
                 logger().info(f"Data sent to client {index} - {data}")
                 data_recv = client_socket.recv_data_tcp(len(data))
                 logger().info(f"Data received in client {index} - {data_recv}")
                 assert data_recv == data
        if self.remote_close:
            logger().info(f"closing the sockets on remote side")
            self.remote_socket_factory.interfaces.socket.close_all()
            time.sleep(15)
            events = self.wifi_dut.interfaces.wifi.get_async_events()
            for event in events:
                # if event.event_type == RS9116AsyncEventType.TCP_REMOTE_TERMINATE:
                    remote_terminate = event.event_data
                    assert remote_terminate, f"unable to find remote terminate event"
                    logger().info("Remote terminate event is received by DUT when tcp socket connected is closed")
                    break
        if self.dut_socket_close:
            for index, client_socket in enumerate(client_sockets):
                result = self.wifi_dut.interfaces.wifi.bsdSockClose(dut_sockets[index])
                assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id -> {dut_sockets[index]}"
                logger().info(f"Successfully close socket_id -> {dut_sockets[index]}")
        logger().info("******* Initiating disconnection on STA(Raspberry pi)*******")
        self.wifi_client.interfaces.wifi.leave()

    def multi_sockets_tx_udp(self, socket_count=None):
        self.socket_count = socket_count  # sockets to open on each wifi client
        client_sockets = []
        client_ips = []
        for _ in range(0, socket_count):
            client_ips.append(self.host_ip)  # four hosts totally
            client_socket = self.remote_socket_factory.interfaces.socket.create_socket(
                interface="wlan0"
            )
            client_sockets.append(client_socket)
        server_base_port = 5001
        dut_sockets = []
        for index, client_socket in enumerate(client_sockets):
            server_port = server_base_port + index
            logger().info(f"Client socket: {client_socket}")
            client_socket.start_server(
                # server_ip=client_ips[index], port=server_port, socket_type=SOCKET_TYPE_UDP
            )
            sock = self.wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP",
                                                   timeout=15)
            if isinstance(sock, int):

                logger().info(f"Socket open successfully : {sock}")
            else:
                logger().error(f"Unable to open socket id: {sock}")
                raise RuntimeError(sock)
            time.sleep(5)
            self.wifi_dut.interfaces.wifi.bind(sock, self.dut_ip, server_port)
            dut_sockets.append(sock)
            if isinstance(sock, int):
                logger().info(f"Socket open successfully : {sock}")
            else:
                logger().error(f"Unable to open socket id: {sock}")
                raise RuntimeError(sock)
            time.sleep(5)
            retry_limit: int = 2
            connect_status = False
            for retry in range(1, retry_limit):
                logger().info(f"connecting to the server")
                connect_response = self.wifi_dut.interfaces.wifi.bsdSocketConnect(sock, self.host_ip, server_port=server_port)
                logger().info(f"Connect response : {connect_response}")
                if connect_response.decode() == '':
                    logger().info(f"Unable to connect socket: {connect_response} in {retry} try")
                    if retry < retry_limit:
                        pass
                elif connect_response.decode().split(">")[1].strip() == 'success':
                    logger().info(f"Socket connected successfully in {retry} try")
                    connect_status = True
                    break
                logger().info(f"Socket connected with server in: {retry + 1} time")
            if connect_status is False:
                logger().info("Unable to connect with Server")
                assert connect_status

        data_sent = []
        for _ in client_sockets:
            data_sent.append(get_random_data(20))
        sw = Stopwatch()
        while sw.elapsed_sec < 300:
            results = ThreadBase.call_functions_simultaneously(
                [
                    (
                        client_socket.send_data_udp,
                        data_sent[index],
                        self.dut_ip,
                        server_base_port + index,
                    )
                    for index, client_socket in enumerate(client_sockets)
                ]
            )

            time.sleep(2)

            for index, client_socket in enumerate(client_sockets):
                logger().info(f"Data sent from client to dut: {data_sent[index]}")
                recv_data_length, recv_data = self.wifi_dut.interfaces.wifi.receive_from(
                    socket_id=dut_sockets[index], data_len=len(data_sent[index]), timeout=50
                )
                logger().info(f"Data recv from client to dut: {recv_data}")
                assert len(data_sent[index]) == recv_data_length
                assert data_sent[index] == recv_data.decode()

        for index, client_socket in enumerate(client_sockets):
            result = self.wifi_dut.interfaces.wifi.bsdSockClose(dut_sockets[index])
            logger().info("Closed socket in DUT")
            assert b"success" in result
        logger().info(f"closing the sockets on remote side")
        self.remote_socket_factory.interfaces.socket.close_all()
        self.wifi_client.interfaces.wifi.leave()


class SocketDataTransfer(ThreadBase):
    def __init__(self, wifi_dut, remote_socket, utf_constants, dut_ip=None, data=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.remote_socket = remote_socket
        self.utf_constants = utf_constants
        self.dut_ip = dut_ip
        self.data = data

    def run_tcp_traffic(self):
        logger().info("Starting TCP server socket remotely")
        local_port = randint(6000, 6100)
        self.remote_socket.interfaces.socket.interface = "wlan0"
        logger().info("Starting TCP Server socket at remote device")
        self.remote_socket.interfaces.socket.start_server(port=local_port)
        server_ip = self.remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = self.remote_socket.interfaces.socket.server_port

        logger().info(f"DUT opens tcp client socket")
        tcp_socket_id = self.wifi_dut.interfaces.wifi.socket()
        logger().info(f"Socket open successfully : {tcp_socket_id}")
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {tcp_socket_id} which is expected")
        logger().info(f"Socket binds at (device_ip, 5001) in DUT")
        bind_response = self.wifi_dut.interfaces.wifi.bind(socket_fd=tcp_socket_id, device_ip=self.dut_ip,
                                                      server_port=server_port,
                                                      timeout=5)
        logger().info(f"Bind socket successfully: {bind_response}")

        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=tcp_socket_id, server_ip=server_ip,
                                                          server_port=server_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")
        for packets in range(20):
            logger().info("DUT Sending Data packets")
            bytes_sent = self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=tcp_socket_id, data=self.data, timeout=30)
            logger().info(f"Number of bytes sent by dut {bytes_sent}")
            logger().info("Setting TCP socket receive timeout in remote server")
            self.remote_socket.interfaces.socket.set_recv_timeout(socket_type=0)
            recv_data = self.remote_socket.interfaces.socket.recv_data_tcp(data_size=len(self.data))
            logger().info(f"data received : {recv_data}")
            packets = packets + 1
            logger().info(f"total packets received at the remote socket: {packets}")

        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=tcp_socket_id)
        self.remote_socket.interfaces.socket.stop()

    def run_udp_traffic(self):
        local_port = randint(5001, 6000)
        logger().info("Starting UDP server socket at remote device")
        self.remote_socket.interfaces.socket.interface = "wlan0"
        self.remote_socket.interfaces.socket.start_server(socket_type=1)  # 0-TCP, 1-UDP
        server_ip = self.remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = self.remote_socket.interfaces.socket.server_port
        logger().info(f"DUT opens tcp client socket")
        udp_socket_id = self.wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_DGRAM",
                                                             protocol="IPPROTO_UDP")
        logger().info(f"Socket open successfully : {udp_socket_id}")
        logger().info("Initiating socket bind from DUT")
        self.wifi_dut.interfaces.wifi.bind(udp_socket_id, device_ip=self.dut_ip, server_port=local_port)
        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(udp_socket_id, server_ip=server_ip, server_port=server_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")
        time.sleep(3)
        for packets in range(20):
            logger().info("DUT Sending Data packets")
            bytes_sent = self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=udp_socket_id, data=self.data, timeout=30)
            logger().info(f"Number of bytes sent by dut {bytes_sent}")
            logger().info("Setting UDP socket receive timeout in remote server")
            self.remote_socket.interfaces.socket.set_recv_timeout(use_client_socket=True, socket_type=1)
            recv_data, address = self.remote_socket.interfaces.socket.recv_data_udp(data_size=len(self.data))
            logger().info(f"data received : {recv_data}")
            packets = packets + 1
            logger().info(f"total packets received at the remote socket: {packets}")
        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=udp_socket_id)
        self.remote_socket.interfaces.socket.stop()




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_sdk_DUTAP_Validate_UDP_Rx_data_C19465(wifi_sniffer, net_perf_client, wifi_dut, wifi_clients, protocol,
                                           utf_constants, sl_collections, sniffer_filter):
    '''Validate UDP Tx data on Remote peer in ap mode connection'''
    try:
        ap_dut_obj = ap.ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                                utf_constants, net_perf_client=net_perf_client, protocol=protocol,
                                                capture_filename="test_C19465",
                                                testcase_no=19465, traffic_type="Rx", leave=False,  sniffer_stop=True)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.ap_sniffer_validation(wifi_sniffer, sniffer_filter, dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],  rasp_mac_address=ap_dut_obj.dut_addr_dict['rasp_mac_address'])

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_DUTAP_Validate_TCP_Rx_data_C19464(wifi_sniffer, net_perf_client, wifi_dut, protocol,
                                                    utf_constants, sl_collections, wifi_clients, wifi_access_point, sniffer_filter):
    '''Validate TCP Rx data on Remote peer in ap mode connection'''
    try:
        ap_dut_obj = ap.ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                                utf_constants, net_perf_client=net_perf_client, protocol=protocol,
                                                capture_filename="test_C19464",
                                                testcase_no=19465, leave=False, sniffer_stop=True)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        timeout = 30
        sl_collections.run_traffic(wifi_dut, net_perf_client, protocol, ap_dut_obj.dut_addr_dict['dut_ip'],
                                   ap_dut_obj.dut_addr_dict['client_ip'], timeout,
                                   traffic_type="RX")
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.ap_sniffer_validation(wifi_sniffer, sniffer_filter, dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'], rasp_mac_address=ap_dut_obj.dut_addr_dict['rasp_mac_address'])

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_DUTAP_Validate_TCP_Tx_data_C19462(wifi_sniffer, net_perf_client, wifi_dut, protocol,
                                                    utf_constants, sniffer_filter, sl_collections, wifi_clients):
    """Validate TCP Tx data on Remote peer in ap mode connection"""
    try:
        ap_dut_obj = ap.ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                                utf_constants, net_perf_client=net_perf_client, protocol=protocol, capture_filename="test_C19462",
                                                testcase_no=19465, traffic_type="Tx", leave=False, sniffer_stop=True)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                             dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                             rasp_mac_address=ap_dut_obj.dut_addr_dict['rasp_mac_address'])
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100, "channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_sdk_DUTAP_Validate_UDP_Tx_data_C19463(wifi_sniffer, net_perf_client, wifi_dut, protocol,
                                           utf_constants, sl_collections, sniffer_filter, wifi_clients):
    """Validate UDP Tx data on Remote peer in ap mode connection"""
    try:
        ap_dut_obj = ap.ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                                utf_constants, net_perf_client=net_perf_client, protocol=protocol, capture_filename="test_C19463",
                                                testcase_no=19465, leave=False, sniffer_stop=True)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client,
                                        protocol=protocol, device_ip=ap_dut_obj.dut_addr_dict['dut_ip'],
                                        host_ip=ap_dut_obj.dut_addr_dict['client_ip'], timeout=40, traffic_type="TX")

        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                             dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                             rasp_mac_address=ap_dut_obj.dut_addr_dict['rasp_mac_address'])
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "client_socket_limit": 10,
        "server_socket_limit": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.parametrize("channel", [11])
def test_wifi_sdk_dutap_tcp_socket_create_transfer_terminate_30min_c19480(wifi_sniffer, sniffer_filter, remote_socket, wifi_dut,
                                                                          utf_constants, sl_collections, wifi_clients, channel):
    '''By creating socket need to test tcp data transfer functionality in ap mode for 30mins'''
    try:
        test_run_time = utf_constants.get('time_duration')
        ap_dut_obj = ap.ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                                utf_constants, capture_filename="test_C19480_connection",
                                                testcase_no=19465, leave=False, sniffer_stop=True)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        sw = Stopwatch()
        while sw.elapsed_sec <= test_run_time:
            time_left = round(((test_run_time - sw.elapsed_sec) / 60), 2)
            logger().info(f"Remaining time to complete test is '{time_left}' minutes")
            logger().info("***** Initiating TCP TX traffic from DUT *****")
            socket_obj = SocketDataTransfer(wifi_dut, remote_socket, utf_constants, dut_ip=ap_dut_obj.dut_addr_dict['dut_ip'], data= "Thisisfromtcpclient")
            socket_obj.run_tcp_traffic()
            time.sleep(30)
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'],
            filter_name='beacon')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  beacon in Sniffer'


    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "client_socket_limit": 10,
        "server_socket_limit": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.parametrize("channel", [11])
def test_wifi_sdk_dutap_udp_socket_create_transfer_terminate_30min_C19481(wifi_sniffer, remote_socket, wifi_dut,
                                                                           utf_constants, sniffer_filter, sl_collections, wifi_clients, channel):
    '''By creating socket need to test udp data transfer functionality in ap mode for 30mins'''
    try:
        test_run_time = utf_constants.get('time_duration')
        ap_dut_obj = ap.ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                                utf_constants,
                                                capture_filename="test_C19481_connection",
                                                testcase_no=19465, leave=False, sniffer_stop=True)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        sw = Stopwatch()
        while sw.elapsed_sec <= test_run_time:
            time_left = round(((test_run_time - sw.elapsed_sec) / 60), 2)
            logger().info(f"Remaining time to complete test is '{time_left}' minutes")
            logger().info("***** Initiating TCP TX traffic from DUT *****")
            socket_obj = SocketDataTransfer(wifi_dut, remote_socket, utf_constants,
                                            dut_ip=ap_dut_obj.dut_addr_dict['dut_ip'], data="Thisisfromudpclient")
            socket_obj.run_udp_traffic()
            time.sleep(30)
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'],
            filter_name='beacon')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  beacon in Sniffer'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
def test_wifi_sdk_DUTAP_tcp_remote_termiate_C19466(wifi_sniffer, sniffer_filter, remote_socket, wifi_dut, utf_constants, sl_collections, wifi_clients):
    '''Run tcp iperf data transfer , check for remote terminate in the dut'''
    try:
        local_port = randint(5001, 6000)
        ap_dut_obj = ap.ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                                utf_constants,
                                                capture_filename="test_C19466",
                                                testcase_no=19465, leave=False,
                                                sniffer_stop=False)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        remote_socket.interfaces.socket.start_server(port=local_port)
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = remote_socket.interfaces.socket.server_port
        tcp_socket_id = wifi_dut.interfaces.wifi.socket()
        logger().info(f"Socket open successfully : {tcp_socket_id}")
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {tcp_socket_id} which is expected")
        bind_response =  wifi_dut.interfaces.wifi.bind(tcp_socket_id, ap_dut_obj.dut_addr_dict['dut_ip'], 4,
                                                          server_port=server_port, timeout=5)
        logger().info(f"Bind socket successfully: {bind_response}")
        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=tcp_socket_id, server_ip=server_ip,
                                                          server_port=server_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        send_bytes = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=tcp_socket_id, data="Thisisfromclient",
                                                            timeout=120)
        logger().info(f'SEND-Bytes = {send_bytes}')
        wifi_dut.interfaces.wifi.set_remote_terminate_callback()
        remote_socket.interfaces.socket.socket_close_indication(1)
        time.sleep(8)
        events = wifi_dut.interfaces.wifi.get_async_events()
        remote_terminate = ""
        for event in events:
            if event.event_type == AsyncEventIdentifiers.REMOTE_TERMINATE:
                remote_terminate = event.event_data
        logger().info(f"*********{remote_terminate}*************")
        assert remote_terminate, f"unable to find remote terminate event"
        logger().info("Remote terminate event is received by DUT when tcp socket connected is closed")
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                             dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                             rasp_mac_address=ap_dut_obj.dut_addr_dict['rasp_mac_address'])

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "client_socket_limit": 4,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
def test_wifi_sdk_DUTAP_remote_terminate_while_sending_tcp_data_on_4sockets_C19482(utf_constants, sniffer_filter, wifi_sniffer, wifi_dut, wifi_client, remote_socket_factory, sl_collections, wifi_clients):
    '''create 4 sockets ,do the data transfer check for remote terminate event in the dut'''
    try:
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_tcp_4_clients_C19482')
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )
        client_ips = []
        client_sockets = []
        for _ in range(0, 4):
            client_ips.append(dut_addr_dict['client_ip'])
            client_socket = remote_socket_factory.interfaces.socket.create_socket()
            client_sockets.append(client_socket)
        server_base_port = 5001
        dut_sockets = []
        for index, client_socket in enumerate(client_sockets):
            client_ip = client_ips[index]
            server_port = server_base_port + index
            client_socket.start_server(server_ip=client_ip, port=server_port)
            time.sleep(10)
            logger().info(f"opening socket_id_{index}")
            tcp_socket_id = wifi_dut.interfaces.wifi.socket()
            if isinstance(tcp_socket_id, int):
                logger().info(f"Socket open successfully : {tcp_socket_id}")
            else:
                logger().error(f"Unable to open socket id: {tcp_socket_id}")
                raise RuntimeError(tcp_socket_id)
            dut_sockets.append(tcp_socket_id)
            time.sleep(5)
            wifi_dut.interfaces.wifi.bind(tcp_socket_id, dut_addr_dict['dut_ip'], 4,
                                                          server_port=server_port, timeout=5)
            time.sleep(3)
            logger().info(f"connecting to the server")
            connect_response = wifi_dut.interfaces.wifi.bsdSocketConnect(tcp_socket_id, dut_addr_dict['client_ip'],
                                                                         server_port=server_port)
            logger().info(f"Connect response : {connect_response}")
            send_bytes = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=tcp_socket_id, data="Thisisfromclient",
                                                                     timeout=120)
            logger().info(f'SEND-Bytes = {send_bytes}')
        wifi_dut.interfaces.wifi.set_remote_terminate_callback()
        remote_socket_factory.interfaces.socket.close_all()
        time.sleep(10)
        event_data_output = ""
        events = wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.REMOTE_TERMINATE:
                event_data_output = event.event_data
                logger().info(f"*****{event_data_output}*******")
        assert "Remote Terminate" in event_data_output, "expected error code not found. Expected is Remote Terminate"
        logger().info(f" ***************** EVENT DATA IS : {event_data_output} ********************** ")
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server  | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "client_socket_limit": 10,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123"
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config(
    "remote_socket_factory",
    socket={
        "interface": "wlan0"
    }
)
def test_wifisdk_DUTAP_open_10_TCP_client_sockets_send_tx_C19473( wifi_dut, wifi_sniffer, remote_socket_factory, sl_collections, wifi_clients):
    '''Open 10 TCP client sockets and Data TX in ap mode'''
    socket_threads = []
    try:
        no_of_pkts = 100
        pkt_length = 1460
        no_of_socket = 10
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_tcp_10clients')
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )
        client_sockets = []
        server_port_base = 5001
        server_socks = []
        client_ips = []
        for count in range(0, no_of_socket):
            client_ips.append(dut_addr_dict['client_ip'])

            local_port = server_port_base + count
            logger().info(f'Server port = {local_port}')

            client_socket = remote_socket_factory.interfaces.socket.create_socket()
            client_sockets.append(client_socket)
            client_socket.start_server(port=local_port)
            sock = wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                        protocol="IPPROTO_TCP")
            logger().info(f"Socket open successfully : {sock}")
            server_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_addr_dict['dut_ip'], server_port=local_port, timeout=5, asynch=1)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, ip_len=4, server_ip=client_ips[count],
                                                      server_port=local_port)
            time.sleep(1)

        server_port = 5001
        time_interval = 5
        data_transfer_objs = []
        socket_threads = []
        for count in range(0, no_of_socket):
            local_port = server_port + count
            data_transfer_objs.append(data_transfer())
            socket_threads.append(Thread(target=data_transfer_objs[count].send_and_receive_data_socket,
                                         args=(client_sockets[count], no_of_pkts, pkt_length, time_interval, wifi_dut,
                                               server_socks[count], local_port, client_ips[0], 0), daemon=True))

            socket_threads[count].start()
            time.sleep(2)

        for sock in server_socks:
            logger().info(f"Closing socket_id->{sock}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)

        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()

    except Exception as e:
        logger().exception(f"Exception...")
        raise e

    finally:
        for th in socket_threads:
            th.join()
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANBLE,
        "features": Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": 0,
        "custom_features": 0,
        "bt_features": 0,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ble_features": 0,
        "band": 0,
        "boot_option": 49,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)

def test_DUTAP_LTCP_socket_connection_when_max_sockets_limit_to_11_C19472(wifi_access_point, wifi_clients, wifi_sniffer, sl_collections, wifi_dut, utf_constants, remote_socket_factory):
    '''Checking maximum socket limit(11) on the Dut in ap mode connection'''
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{19472}.pcap")
        time.sleep(3)
        socket_limit = 11
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.set_socket_config(total_sockets=10, total_tcp_sockets=10, tcp_rx_only_sockets=10)
        dut_add_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )
        client_socket = []
        server_port_base = 5001
        tcp_socks = []
        socket_list = []
        for count in range(0, 11):
            local_port = server_port_base + count
            socket_list.append(local_port)
            logger().info(f'Server port = {local_port}')
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            sock = wifi_dut.interfaces.wifi.socket()
            logger().info(f"Socket open successfully : {sock}")
            logger().info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            tcp_socks.append(sock)
        for count in range(0, socket_limit):
            wifi_dut.interfaces.wifi.bind(socket_fd=tcp_socks[count], device_ip= dut_add_dict['client_ip'],
                                          server_port=socket_list[count], timeout=5, asynch=0)
        for count in range(0, socket_limit):
            try:
                wifi_dut.interfaces.wifi.listen(socket_fd=tcp_socks[count], backlog=1, asynch=0)
            except Exception as error:
                if count == len(tcp_socks) - 1:
                    wifi_dut.interfaces.wifi.get_saved_firmware_status(expected_status=
                                                                       SLStatus.SL_STATUS_SI91X_MAX_SOCKETS_EXCEEDED)
                    logger().info("Received error matches with expected error successfully")
                else:
                    logger().info(error)
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=tcp_socks[len(tcp_socks) - 1])

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
    finally:
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_sdk_Verify_Multicast_data_TX_and_RX_C19469(wifi_sniffer, net_perf_client, wifi_dut, protocol,
                                                    utf_constants, sniffer_filter, sl_collections, wifi_clients, multicast_client):
    try:
        ap_dut_obj = ap.ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                                utf_constants, net_perf_client=net_perf_client, protocol=protocol,
                                                capture_filename="test_C19464",
                                                testcase_no=19465, leave=False, sniffer_stop=False)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.sl_net_join_multicast_address()
        logger().info("starting the server from Remote device")
        logger().info(f"starting iperf")
        net_perf_client.interfaces.net_perf.init_server(host_ip=ap_dut_obj.dut_addr_dict['client_ip'],
                                                        device_ip=ap_dut_obj.dut_addr_dict['dut_ip'],
                                                        protocol=protocol, time_out=30, bind_address=multicast_ip)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=ap_dut_obj.dut_addr_dict['dut_ip'],
                                       remote_ip=multicast_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1470,
                                       ttl=30,
                                       throughput_type=2, qos=0, async_socket=1)

        net_perf_client.interfaces.net_perf.init_client(host_ip=ap_dut_obj.dut_addr_dict['client_ip'], device_ip=multicast_ip,
                                                        time_out=30,
                                                        protocol=protocol, time_to_leave="32",
                                                        bandwidth="60M",
                                                        host_role="C", bind_address=ap_dut_obj.dut_addr_dict['client_ip'])
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** start listening  ******")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                       local_port=net_perf_client.interfaces.net_perf.client_port,
                                       local_ip=multicast_ip, remote_ip=ap_dut_obj.dut_addr_dict['client_ip'],
                                       remote_port=net_perf_client.interfaces.net_perf.client_port,
                                       size=1470, ttl=30, throughput_type=4, qos=0, async_socket=1)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               },
            1: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
            }
         }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_sdk_Verify_Multicast_RX_C19484(wifi_sniffer, net_perf_client, wifi_dut, protocol,
                                                    utf_constants, sniffer_filter, sl_collections, wifi_clients, multicast_client, net_perf_clients):
    try:
        assert len(wifi_clients) >= 2, f"Minimum 2 raspi devices needed for this test"
        ip_dict = {}
        timeout = 60
        ap_dut_obj = ap.ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                                utf_constants, net_perf_client=net_perf_client, protocol=protocol,
                                                capture_filename="test_C19484",
                                                testcase_no=19484, leave=False, sniffer_stop=True)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        for i in range(0, 2):
            ip_dict[f'client_ip_{i}'] = wifi_clients[i].interfaces.wifi.get_ip_address()
            logger().info(f"*****************client_ip{i}: {ip_dict[f'client_ip_{i}']}")
        client_ip_1 = ip_dict['client_ip_0']
        client_ip_2 = ip_dict['client_ip_1']
        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.sl_net_join_multicast_address(interface=18)
        for i in range(0, 2):
            if net_perf_clients[i].name == "raspi_iperf":
                host_ip = client_ip_1
                logger().info(f"***********{host_ip}**********")
                logger().info(f"************1st raspi: {net_perf_clients[i].name}*********")
                logger().info("***** Initiating UDP RX traffic from DUT *****")
                net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=multicast_ip,
                                                                time_out=timeout,
                                                                protocol=protocol, time_to_leave="32",
                                                                bandwidth="60M",
                                                                host_role="C", bind_address=host_ip)
                logger().info(f"***** starting iperf ******")
                net_perf_client.interfaces.net_perf.start()
                logger().info(f"***** start listening  ******")
                wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                               local_port=net_perf_client.interfaces.net_perf.client_port,
                                               local_ip=multicast_ip, remote_ip=host_ip,
                                               remote_port=net_perf_client.interfaces.net_perf.client_port,
                                               size=1470, ttl=30, throughput_type=4, qos=0, async_socket=1)
                time.sleep(20)
            else:
                host_ip = client_ip_2
                logger().info(f"***********{host_ip}**********")
                logger().info(f"************2nd raspi: {net_perf_clients[i].name}*********")
                logger().info("***** Initiating UDP RX traffic from DUT *****")
                net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=multicast_ip,
                                                                time_out=timeout,
                                                                protocol=protocol, time_to_leave="32",
                                                                bandwidth="60M",
                                                                host_role="C", bind_address=host_ip)
                logger().info(f"***** starting iperf ******")
                net_perf_client.interfaces.net_perf.start()
                logger().info(f"***** start listening  ******")
                wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                               local_port=net_perf_client.interfaces.net_perf.client_port,
                                               local_ip=multicast_ip, remote_ip=host_ip,
                                               remote_port=net_perf_client.interfaces.net_perf.client_port,
                                               size=1470, ttl=30, throughput_type=4, qos=0, async_socket=1)
                time.sleep(20)

        wifi_dut.interfaces.wifi.sl_net_leave_multicast_address(interface=18)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        for i in range(0, 2):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features": 0,
        "ext_tcpip_features": 0,
        "custom_features": 0,
        "band": 0,
        "boot_option": 49,
        "thread_config": {"wifi": {"count": 2, "stack_len": 4096}},
        "client_socket_limit": 10,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123"
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
def test_wifisdk_DUTAP_open_10_UDP_client_sockets_send_tx_C19474(wifi_sniffer, wifi_dut,  remote_socket_factory, sl_collections, wifi_clients):
    try:
        no_of_pkts = 100
        pkt_length = 1460
        no_of_socket = 10
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C19474.pcap")
        time.sleep(3)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )
        client_sockets = []
        server_port_base = 5001
        server_socks = []
        client_ips = []
        for count in range(0, no_of_socket):
            client_ips.append(dut_addr_dict['client_ip'])
            local_port = server_port_base + count
            logger().info(f'Server port = {local_port}')
            client_socket = remote_socket_factory.interfaces.socket.create_socket()
            client_sockets.append(client_socket)
            client_socket.start_server(port=local_port)
            udp_socket_id = wifi_dut.interfaces.wifi.socket(stream_type="SOCK_DGRAM",
                                                            protocol="IPPROTO_UDP")
            server_socks.append(udp_socket_id)
            bind_response = wifi_dut.interfaces.wifi.bind(socket_fd=udp_socket_id,
                                                          device_ip=dut_addr_dict['dut_ip'], ip_len=4,
                                                          server_port=local_port, timeout=5)
            logger().info(f"Bind socket successfully: {bind_response}")
            logger().info("DUT is connecting to server socket")
        server_port = 5001
        time_interval = 5
        data_transfer_objs = []
        socket_threads = []
        for count in range(0, no_of_socket):
            local_port = server_port + count
            data_transfer_objs.append(data_transfer())
            socket_threads.append(Thread(target=data_transfer_objs[count].send_and_receive_data_socket,
                                         args=(client_sockets[count], no_of_pkts, pkt_length, time_interval, wifi_dut,
                                               server_socks[count], local_port, client_ips[0], 1), daemon=True))
            logger().info(f"***** UDP_TX is running now in {count} ******")
            socket_threads[count].start()
            time.sleep(2)

        for index in server_socks:
           wifi_dut.interfaces.wifi.bsdSockClose(server_socks[index])

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:

        for th in socket_threads:
            th.join()
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               },
            1: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
            }
         }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_DUTAP_Bidirectional_TCP_traffic_data_C19467(wifi_sniffer, net_perf_client, wifi_dut, protocol,
                                                    utf_constants, net_perf_clients, sniffer_filter, sl_collections, wifi_clients, multicast_client, net_perf_server,):
    """Validate bidirectional tcp traffic on Remote peer in ap mode connection"""
    try:
        ip_dict = {}
        assert len(wifi_clients) >= 2, f"Minimum 2 raspi devices needed for this test"
        ap_dut_obj = ap.ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                                utf_constants, net_perf_client=net_perf_client, protocol=protocol,
                                                capture_filename="test_C19467",
                                                testcase_no=19484, leave=False, sniffer_stop=True)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        for i in range(0, len(wifi_clients)):
            ip_dict[f'client_ip_{i}'] = wifi_clients[i].interfaces.wifi.get_ip_address()
            ip_dict[f'rasp_mac_address_{i + 1}'] = wifi_clients[i].interfaces.wifi.get_mac_address()

        client_ip_1 = ip_dict['client_ip_0']
        client_ip_2 = ip_dict['client_ip_1']
        rasp_mac_address_1 = ip_dict['rasp_mac_address_1']
        rasp_mac_address_2 = ip_dict['rasp_mac_address_2']
        timeout = 30
        logger().info("***** Initiating TCP RX traffic *****")
        for retry_count in range(5):
            try:
                for i in range(0, 2):
                    if net_perf_clients[i].name == "raspi_iperf":
                        logger().info(f"************1st raspi: {net_perf_clients[i].name}*********")
                        sl_collections.run_traffic(wifi_dut, net_perf_client, protocol, ap_dut_obj.dut_addr_dict['dut_ip'], client_ip_2, timeout,
                                              traffic_type="RX")
                        time.sleep(15)
                    # else:
                    #     logger().info(f"************2nd raspi: {net_perf_clients[i].name}*********")
                    #     sl_collections.run_traffic(wifi_dut, net_perf_client, protocol, ap_dut_obj.dut_addr_dict['dut_ip'], client_ip_1, timeout,
                    #                                traffic_type="RX")
                    #     time.sleep(15)
                break
            except Exception as e:
                try:
                    net_perf_client.interfaces.net_perf.close_files()
                    net_perf_client.interfaces.net_perf.iperf_process.stop(5)
                except:
                    pass
                logger().info(f"Iperf process Failed...retry_count{retry_count + 1}")
                if retry_count == 4:
                    raise e
                time.sleep(25)
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                             dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                             rasp_mac_address=rasp_mac_address_1)
        sl_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                             dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                             rasp_mac_address=rasp_mac_address_2)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               },
            1: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
            }
         }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_sdk_DUTAP_Bidirectional_UDP_traffic_data_C19468(wifi_sniffer, net_perf_client, wifi_dut, protocol,
                                                    utf_constants, net_perf_clients, sniffer_filter, sl_collections, wifi_clients, multicast_client, net_perf_server,):
    """Validate bidirectional udp traffic on Remote peer in ap mode connection"""
    try:
        ip_dict = {}
        assert len(wifi_clients) >= 2, f"Minimum 2 raspi devices needed for this test"
        logger().info("********** configuring the sniffer with access point channel **********")
        ap_dut_obj = ap.ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                                utf_constants, net_perf_client=net_perf_client, protocol=protocol,
                                                capture_filename="test_C19468",
                                                testcase_no=19484, leave=False, sniffer_stop=True)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        for i in range(0, len(wifi_clients)):
            ip_dict[f'client_ip_{i}'] = wifi_clients[i].interfaces.wifi.get_ip_address()
            ip_dict[f'rasp_mac_address_{i + 1}'] = wifi_clients[i].interfaces.wifi.get_mac_address()

        client_ip_1 = ip_dict['client_ip_0']
        client_ip_2 = ip_dict['client_ip_1']
        rasp_mac_address_1 = ip_dict['rasp_mac_address_1']
        rasp_mac_address_2 = ip_dict['rasp_mac_address_2']
        timeout = 30
        logger().info("***** Initiating UDP TX traffic from DUT *****")
        for retry_count in range(5):
            try:
                for i in range(0, 2):
                    if net_perf_clients[i].name == "raspi_iperf":
                        logger().info(f"************1st raspi: {net_perf_clients[i].name}*********")
                        sl_collections.run_traffic(wifi_dut, net_perf_client, protocol, ap_dut_obj.dut_addr_dict['dut_ip'], client_ip_2, timeout,
                                              traffic_type="RX")
                    else:
                        logger().info(f"************2nd raspi: {net_perf_clients[i].name}*********")
                        sl_collections.run_traffic(wifi_dut, net_perf_client, protocol, ap_dut_obj.dut_addr_dict['dut_ip'], client_ip_1, timeout,
                                                   traffic_type="RX")
                break
            except Exception as e:
                try:
                    net_perf_client.interfaces.net_perf.close_files()
                    net_perf_client.interfaces.net_perf.iperf_process.stop(5)
                except:
                    pass
                logger().info(f"Iperf process Failed...retry_count{retry_count + 1}")
                if retry_count == 4:
                    raise e
                time.sleep(10)
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                             dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                             rasp_mac_address=rasp_mac_address_1)
        sl_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                             dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                             rasp_mac_address=rasp_mac_address_2)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "server_socket_limit": 10,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123"
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
def test_wifisdk_DUTAP_open_10_tcp_server_sockets_rx_C19475(wifi_dut, wifi_sniffer, utf_constants,
                                                            remote_socket_factory, sl_collections, wifi_clients):
    """Open 10 TCP server sockets and Data RX"""
    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_C19475")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )
        server_port_base = 5001
        tcp_socks = []
        client_socket = []
        for count in range(0, 10):
            server_port = server_port_base + count
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket(interface="wlan0"))
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_addr_dict['dut_ip'], server_port=server_port, timeout=15,
                                          asynch=1)
            wifi_dut.interfaces.wifi.listen(sock, backlog=1, asynch=1)
            time.sleep(3)
            ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1),
                    (
                        client_socket[count].connect_client_tcp,
                        dut_addr_dict['dut_ip'],
                        server_port,
                    ),
                ],
                timeout=10,
            )

            time.sleep(3)
        count = 0
        for sock_no in tcp_socks:
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=1460))
            buffer_length = len(tx_buffer)
            sw = Stopwatch()
            while sw.elapsed_sec <= 60:
                logger().info(f"Remote peer sending data over socket {sock_no} and data:{tx_buffer}")
                client_socket[count].send_data_tcp(tx_buffer)
                time.sleep(1)
                buffer_rx = ""
                for retry in range(3):
                    try:
                        buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_no + 1)
                        break
                    except:
                        if retry == 2:
                            raise Exception(f"failed to receive data from the socket id {sock} opened in the DUT")
                logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
                logger().info(f"###################### Buffer Data  {len(buffer_rx)}  ######################")
                logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock_no} opened in the DUT is not matched"
                logger().info("Data sent by remote peer and received on DUT is matching")
            count += 1

        for sock in tcp_socks:
            logger().info(f"Closing socket_id->{sock}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)

        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        remote_socket_factory.interfaces.socket.close_all()
        wifi_dut.interfaces.wifi.stop_ap()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "client_socket_limit": 10,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123"
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.end_state("wifi_dut", ["close_sockets"])
def test_wifisdk_DUTAP_open_10_udp_server_sockets_rx_C19476(wifi_dut, remote_socket, wifi_sniffer, utf_constants,
                                                            remote_socket_factory, sl_collections, wifi_clients,
                                                            remote_multi_socket):
    """Open 10 UDP server sockets and Data RX"""
    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_C19476")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )
        dut = 6001
        udp_socks = []
        local_port = randint(6001, 60000)
        for sock_count in range(0, 10):
            port = local_port + sock_count
            port_dut = 6001 + sock_count
            sock_id = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
            remote_multi_socket.interfaces.socket.start_server(port=port, socket_type=1, sock_id=sock_id)
            udp_socks.append(sock_id)
            logger().info(
                f"Successfully opened UDP client socket and socket id received is {sock_id} which is expected")
            wifi_dut.interfaces.wifi.bind(socket_fd=sock_id, device_ip=dut_addr_dict['dut_ip'],
                                          server_port=port_dut, asynch=1)
        i = 0
        for socket_no in range(0, 10):
            data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))
            data_length = len(data_sent)
            if socket_no == 0:
                start_port_dut = 6001
            elif socket_no == 1:
                start_port_dut = 6002
            elif socket_no == 2:
                start_port_dut = 6003
            elif socket_no == 3:
                start_port_dut = 6004
            elif socket_no == 4:
                start_port_dut = 6005
            elif socket_no == 5:
                start_port_dut = 6006
            elif socket_no == 6:
                start_port_dut = 6007
            elif socket_no == 7:
                start_port_dut = 6008
            elif socket_no == 8:
                start_port_dut = 6009
            elif socket_no == 9:
                start_port_dut = 6010
            sw = Stopwatch()
            while sw.elapsed_sec <= 60:
                logger().info(f"###################### start_port from DUT : {start_port_dut}  ######################")
                remote_multi_socket.interfaces.socket.send_data_udp(
                    tx_buffer=data_sent, server_ip=dut_addr_dict['dut_ip'], port=start_port_dut, sock_id=udp_socks[i])
                logger().info(f"********data on socket {data_sent}")
                time.sleep(2)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket_no)
                logger().info(f"###################### Buffer Data  {data_sent}  ######################")
                logger().info(f"###################### Buffer Data Length  {data_length}  ######################")
                logger().info(f"###################### Received Data: {buffer_rx} ######################")
                assert data_length == len(
                    buffer_rx), f"buffer length sent by remote peer and received on the socket id {socket_no} opened in the DUT is not matched "
                time.sleep(2)
            i += 1
        for socket in udp_socks:
            logger().info(f"Closing socket_id->{socket}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket)
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": 0,
        "ext_custom_features": 0,
        "ext_tcpip_features": 0,
        "band": 0,
        "boot_option": 49,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "client_socket_limit": 5,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123"
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
def test_wifisdk_DUTAP_open_5_UDP_client_sockets_tx_5_TCP_server_socket_send_rx_C19478( wifi_dut, wifi_sniffer, remote_multi_socket, utf_constants, remote_socket_factory, sl_collections, wifi_clients):
    """ Test DUT as AP by opening 5 UDP client sockets & tx, 5 TCP server by rx """
    socket_threads = []
    try:
        no_of_pkts = 100
        pkt_length = 1460
        no_of_socket = 5
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_udp_client_tcp_server_sockets_C19478")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )
        server_port_base = 5001
        udp_sockets= []
        client_ips = []
        udp_socks = []
        for count in range(0, no_of_socket):
            client_ips.append(dut_addr_dict['client_ip'])
            local_port = server_port_base + count
            logger().info(f'Server port = {local_port}')
            client_socket = remote_socket_factory.interfaces.socket.create_socket()
            udp_sockets.append(client_socket)
            client_socket.start_server(port=local_port)
            udp_socket_id = wifi_dut.interfaces.wifi.socket(stream_type="SOCK_DGRAM",
                                                            protocol="IPPROTO_UDP")
            udp_socks.append(udp_socket_id)
            bind_response = wifi_dut.interfaces.wifi.bind(socket_fd=udp_socket_id,
                                                          device_ip=dut_addr_dict['dut_ip'], ip_len=4,
                                                          server_port=local_port, timeout=5)
            logger().info(f"Bind socket successfully: {bind_response}")
            logger().info("DUT is connecting to server socket")

        start_port = 5006
        server_socks = []
        tcp_socks = []
        for count in range(0, no_of_socket):
            server_port = start_port + count
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_addr_dict['dut_ip'], server_port=server_port, timeout=15,
                                          asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)
            time.sleep(3)
            server_socks.append(remote_socket_factory.interfaces.socket.create_socket())
            ThreadBase.call_functions_simultaneously(
                [(server_socks[count].connect_client_tcp, dut_addr_dict['dut_ip'], server_port),
                 (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1)], timeout=10)

        logger().info(f"****** Initiating UDP_TX **********")
        socket_threads = []
        data_transfer_objs = []
        time_interval = 5
        for count in range(0, no_of_socket):
            local_port = server_port_base + count
            data_transfer_objs.append(data_transfer())
            socket_threads.append(Thread(target=data_transfer_objs[count].send_and_receive_data_socket,
                                         args=(udp_sockets[count], no_of_pkts, pkt_length, time_interval, wifi_dut,
                                               server_socks[count], local_port, client_ips[0], 1), daemon=True))
            logger().info(f"***** UDP_TX is running now in {count} ******")
            socket_threads[count].start()
            time.sleep(2)
        logger().info(f"************ Initiating TCP_RX **********")

        count = 0
        for sock_no in tcp_socks:
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=1460))
            buffer_length = len(tx_buffer)
            sw = Stopwatch()
            while sw.elapsed_sec <= 60:
                logger().info(f"Remote peer sending data over socket {sock_no} and data:{tx_buffer}")
                server_socks[count].send_data_tcp(tx_buffer)
                time.sleep(1)
                buffer_rx = ""
                for retry in range(3):
                    try:
                        buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_no + 1)
                        break
                    except:
                        if retry == 2:
                            raise Exception(f"failed to receive data from the socket id {sock} opened in the DUT")
                logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
                logger().info(f"###################### Buffer Data  {len(buffer_rx)}  ######################")
                logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock_no} opened in the DUT is not matched"
                logger().info("Data sent by remote peer and received on DUT is matching")
            count += 1

        for sock in tcp_socks:
            logger().info(f"Closing socket_id->{sock}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)

        for socket in udp_socks:
            logger().info(f"Closing socket_id->{socket}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket)

        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().exception(f"Exception...")
        raise e

    finally:
        for th in socket_threads:
            th.join()
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "client_socket_limit": 5,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123"
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config(
    "remote_socket_factory",
    socket={
        "interface": "wlan0"
    }
)
def test_wifisdk_DUTAP_open_5_TCP_client_sockets_tx_5_udp_server_socket_send_rx_C19477( wifi_dut, wifi_sniffer, remote_multi_socket, utf_constants, remote_socket_factory, sl_collections, wifi_clients):
    socket_threads = []
    try:
        no_of_pkts = 100
        pkt_length = 1460
        no_of_socket = 5
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_tcp_client_udp_server_sockets_C19477")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )
        client_sockets = []
        server_port_base = 5001
        server_socks = []
        client_ips = []
        for count in range(0, no_of_socket):
            client_ips.append(dut_addr_dict['client_ip'])

            local_port = server_port_base + count
            logger().info(f'Server port = {local_port}')

            client_socket = remote_socket_factory.interfaces.socket.create_socket()
            client_sockets.append(client_socket)
            client_socket.start_server(port=local_port)
            sock = wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                        protocol="IPPROTO_TCP")
            logger().info(f"Socket open successfully : {sock}")
            server_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_addr_dict['dut_ip'], server_port=local_port, timeout=5, asynch=1)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, ip_len=4, server_ip=client_ips[count],
                                                      server_port=local_port)
            time.sleep(1)

        start_port_dut = 5006
        udp_socks = []
        local_port = randint(5001, 60000)
        for sock_count in range(0, 5):
            port = local_port + sock_count
            port_dut = start_port_dut + sock_count
            sock_id = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
            remote_multi_socket.interfaces.socket.start_server(port=port, socket_type=1, sock_id=sock_id)
            udp_socks.append(sock_id)
            logger().info(
                f"Successfully opened UDP client socket and socket id received is {sock_id} which is expected")
            wifi_dut.interfaces.wifi.bind(socket_fd=sock_id, device_ip=dut_addr_dict['dut_ip'],
                                          server_port=port_dut, asynch=1)

        server_port = 5001
        time_interval = 5
        data_transfer_objs = []
        socket_threads = []
        for count in range(0, no_of_socket):
            logger().info(f"Iteration: {count}")
            local_port = server_port + count
            data_transfer_objs.append(data_transfer())
            socket_threads.append(Thread(target=data_transfer_objs[count].send_and_receive_data_socket,
                                         args=(client_sockets[count], no_of_pkts, pkt_length, time_interval, wifi_dut,
                                               server_socks[count], local_port, client_ips[0], 0), daemon=True))

            socket_threads[count].start()
            time.sleep(2)
        i = 0
        for socket_no in range(5, 10):
            data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))
            data_length = len(data_sent)
            if socket_no == 5:
                start_port_dut = 5006
            elif socket_no == 6:
                start_port_dut = 5007
            elif socket_no == 7:
                start_port_dut = 5008
            elif socket_no == 8:
                start_port_dut = 5009
            elif socket_no == 9:
                start_port_dut = 5010
            sw = Stopwatch()
            while sw.elapsed_sec <= 60:
                logger().info(f"###################### start_port from DUT : {start_port_dut}  ######################")
                remote_multi_socket.interfaces.socket.send_data_udp(
                    tx_buffer=data_sent, server_ip=dut_addr_dict['dut_ip'], port=start_port_dut, sock_id=udp_socks[i])
                logger().info(f"********data on socket {data_sent}")
                time.sleep(2)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket_no)
                logger().info(f"###################### Buffer Data  {data_sent}  ######################")
                logger().info(f"###################### Buffer Data Length  {data_length}  ######################")
                logger().info(f"###################### Received Data: {buffer_rx} ######################")
                assert data_length == len(
                    buffer_rx), f"buffer length sent by remote peer and received on the socket id {socket_no} opened in the DUT is not matched "
                time.sleep(2)
            i += 1


        for sock in server_socks:
            logger().info(f"Closing socket_id->{sock}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)

        for socket in udp_socks:
            logger().info(f"Closing socket_id->{socket}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket)

        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().exception(f"Exception...")
        raise e

    finally:
        for th in socket_threads:
            th.join()
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_DUTAP_Validate_TCP_Tx_data_for_multiple_iterations_C551123(wifi_sniffer, net_perf_client, wifi_dut, protocol,
                                                    utf_constants, sniffer_filter, sl_collections, wifi_clients):
    """TCP-socket create, Receive data, socket close and Repeat"""
    try:
        iter_count = utf_constants.get("iter_count")
        ap_dut_obj = ap.ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                                utf_constants, capture_filename="test_C551123",
                                                testcase_no=19465, leave=False, sniffer_stop=False)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        timeout = 30
        for i in range(0, iter_count):
            sl_collections.run_traffic(wifi_dut, net_perf_client, protocol, ap_dut_obj.dut_addr_dict['dut_ip'],
                                       ap_dut_obj.dut_addr_dict['client_ip'], timeout,
                                       traffic_type="TX")

        wifi_clients[0].interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                             dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                             rasp_mac_address=ap_dut_obj.dut_addr_dict['rasp_mac_address'])
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.start_state("wifi_dut", wifi=['net_init'])
def test_wifi_sdk_DUTAP_wlan_disconnect_while_sending_data_C551124(wifi_sniffer, wifi_dut,
                                                    utf_constants, sl_collections, wifi_clients, remote_socket):
    """trigger WLAN disconnect callback while sending TCP data"""
    try:
        ap_dut_obj = ap.ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                                utf_constants, capture_filename="test_C551124",
                                                testcase_no=19465, leave=False, sniffer_stop=False)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        socket_obj = DataTransfer(wifi_dut, remote_socket, utf_constants, dut_ip=ap_dut_obj.dut_addr_dict['dut_ip'],
                                    data="Thisisfromtcpclient")
        disc_obj = Disconnection(wifi_clients)
        socket_obj.start()
        time.sleep(8)
        disc_obj.start()
        socket_obj.wait_for_exit()
        disc_obj.wait_for_exit()
        sw = Stopwatch()
        client_disconnect = 0
        while sw.elapsed_sec < 120:
            events = wifi_dut.interfaces.wifi.get_async_events()
            for event in events:
                logger().info(f"*********{event.event_data}******")
                if "Client disconnected:" in event.event_data:
                    client_disconnect = 1
            if client_disconnect:
                break
        assert client_disconnect, f"unable to find client disconnect event"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()
        time.sleep(10)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048, "priority": 8}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_verify_one_TCP_TX_and_UDP_TX_using_multithread_C689592(wifi_dut, wifi_clients, request, wifi_sniffer, net_perf_clients, wifi_access_point, sl_collections,utf_constants,  channel):
    """ Verify  one TCP TX and UDP TX simultaneously using multi thread sockets.
         steps:
              1:set_socket_config as per testrail
              2:DUT as AP should bring up and connect to client
              3:start 2 threads parallel for TCP & UDP
              4:run traffic using iperf in both threads parallel
              5:close all sockets and terminate threads.
            """
    test_name = request.node.name
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{689592}.pcap")
        time.sleep(3)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.set_socket_config(total_sockets=2, total_tcp_sockets=2, tcp_tx_only_sockets=1,
                                                   tcp_rx_only_sockets=1)
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )

        tcp_tx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 test_name=test_name, wifi_client=wifi_clients[0],
                                 traffic_type="TX", protocol="TCP", net_perf_client=net_perf_clients[0], timeout=60,
                                 device_ip=dut_addr_dict['dut_ip'], remote_ip=dut_addr_dict['client_ip'],
                                 ip_version=4, async_socket=0,
                                 )
        udp_tx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 test_name=test_name, wifi_client=wifi_clients[0],
                                 traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=60,
                                 device_ip=dut_addr_dict['dut_ip'], remote_ip=dut_addr_dict['client_ip'],
                                 ip_version=4, async_socket=0,
                                 )
        tcp_tx_obj.start()
        udp_tx_obj.start()
        time.sleep(5)

        tcp_tx_obj.wait_for_exit()
        udp_tx_obj.wait_for_exit()
        time.sleep(5)
        logger().info(f"TCP_TX & UDP_TX ran successfully")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        time.sleep(10)
    finally:
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048, "priority": 8}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_verify_one_TCP_TX_and_UDP_RX_using_multithread_C689593(wifi_dut, wifi_clients, request, wifi_sniffer, net_perf_clients, wifi_access_point, sl_collections,utf_constants,  channel):
    """ Verify  one TCP TX and UDP RX simultaneously using multi thread sockets
        steps:
          1:set_socket_config as per testrail
          2:DUT as AP should bring up and connect to client
          3:start 2 threads parallel
          4:run traffic using iperf in both threads parallel
          5:close all sockets and terminate threads.
        """
    test_name = request.node.name
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{689593}.pcap")
        time.sleep(3)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.set_socket_config(total_sockets=2, total_tcp_sockets=1, tcp_rx_only_sockets=0, total_udp_sockets=1, tcp_tx_only_sockets=1,
                                                   tcp_rx_high_performance_sockets=0, udp_rx_only_sockets=1)
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )

        tcp_tx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 test_name=test_name, wifi_client=wifi_clients[0],
                                 traffic_type="TX", protocol="TCP", net_perf_client=net_perf_clients[0], timeout=60,
                                 device_ip=dut_addr_dict['dut_ip'], remote_ip=dut_addr_dict['client_ip'],
                                 ip_version=4, async_socket=1,
                                 )
        udp_rx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 test_name=test_name, wifi_client=wifi_clients[0],
                                 traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=60,
                                 device_ip=dut_addr_dict['dut_ip'], remote_ip=dut_addr_dict['client_ip'],
                                 ip_version=4, async_socket=1,
                                 )
        tcp_tx_obj.start()
        udp_rx_obj.start()
        time.sleep(5)

        tcp_tx_obj.wait_for_exit()
        udp_rx_obj.wait_for_exit()
        time.sleep(3)
        logger().info(f"TCP_TX & UDP_RX ran completed")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        time.sleep(10)
    finally:
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048, "priority": 8}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'ASUS_AP',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_verify_one_TCP_TX_and_TCP_RX_using_multithread_C689594(wifi_dut, wifi_clients, wifi_sniffer, net_perf_clients, wifi_access_point, sl_collections,utf_constants, request, channel):
    """ Verify  one TCP TX and TCP RX simultaneously using multi thread sockets
        steps:
          1:set_socket_config as per testrail
          2:DUT as AP should bring up and connect to client
          3:start 2 threads parallel
          4:run traffic using iperf in both threads parallel
          5:close all sockets and terminate threads
    """
    test_name = request.node.name
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{689594}.pcap")
        time.sleep(3)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.set_socket_config(total_sockets=2, total_tcp_sockets=2, tcp_tx_only_sockets=1,
                                                   tcp_rx_only_sockets=1)
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )

        tcp_tx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                               test_name=test_name, wifi_client=wifi_clients[0],
                               traffic_type="TX", protocol="TCP", net_perf_client=net_perf_clients[0], timeout=60,
                               device_ip=dut_addr_dict['dut_ip'], remote_ip=dut_addr_dict['client_ip'],
                               ip_version=4,async_socket=1,
                               )
        tcp_rx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                               test_name=test_name, wifi_client=wifi_clients[0],
                               traffic_type="RX", protocol="TCP", net_perf_client=net_perf_clients[1], timeout=60,
                               device_ip=dut_addr_dict['dut_ip'], remote_ip=dut_addr_dict['client_ip'],
                               ip_version=4, async_socket=1,
                               )
        tcp_tx_obj.start()
        tcp_rx_obj.start()
        time.sleep(5)

        tcp_tx_obj.wait_for_exit()
        tcp_rx_obj.wait_for_exit()
        time.sleep(3)
        logger().info(f"TCP_tx & tcp_Rx traffic ran successfully")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        time.sleep(10)
    finally:
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 3, "stack_len": 2048, "priority": 8}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_verify_one_TCP_RX_and_UDP_TX_using_multithread_C689595(wifi_dut, wifi_clients, request, wifi_sniffer, net_perf_clients, wifi_access_point, sl_collections,utf_constants,  channel):
    """ Verify  one TCP RX and UDP TX simultaneously using multi thread sockets
        steps:
          1:set_socket_config as per testrail
          2:DUT as AP should bring up and connect to client
          3:start 2 threads parallel
          4:run traffic using iperf in both threads parallel
          5:close all sockets and terminate threads.
        """
    test_name = request.node.name
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{689595}.pcap")
        time.sleep(3)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.set_socket_config(total_sockets=2, total_tcp_sockets=1, total_udp_sockets=1, udp_tx_only_sockets=1,
                                                   tcp_rx_only_sockets=1)
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )

        tcp_rx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 test_name=test_name, wifi_client=wifi_clients[0],
                                 traffic_type="RX", protocol="TCP", net_perf_client=net_perf_clients[0], timeout=60,
                                 device_ip=dut_addr_dict['dut_ip'], remote_ip=dut_addr_dict['client_ip'],
                                 ip_version=4, async_socket=1,
                                 )
        udp_tx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 test_name=test_name, wifi_client=wifi_clients[0],
                                 traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=60,
                                 device_ip=dut_addr_dict['dut_ip'], remote_ip=dut_addr_dict['client_ip'],
                                 ip_version=4, async_socket=0,
                                 )
        tcp_rx_obj.start()
        udp_tx_obj.start()
        time.sleep(5)

        tcp_rx_obj.wait_for_exit()
        udp_tx_obj.wait_for_exit()
        logger().info(f"TCP_RX & UDP_RX ran completed")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 3, "stack_len": 2048, "priority": 8}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_verify_one_TCP_RX_and_UDP_RX_using_multithread_C689596(wifi_dut, wifi_clients, request, wifi_sniffer, net_perf_clients, wifi_access_point, sl_collections,utf_constants,  channel):
    """ Verify  one TCP RX and UDP RX simultaneously using multi thread sockets
        steps:
          1:set_socket_config as per testrail
          2:DUT as AP should bring up and connect to client
          3:start 2 threads parallel
          4:run traffic using iperf in both threads parallel
          5:repeat steps 3&4 in loop for 3 times
          6:close all sockets and terminate threads.
        """
    iter_count = utf_constants.get('iter_count')
    test_name = request.node.name
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{689596}.pcap")
        time.sleep(3)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.set_socket_config(total_sockets=2, total_udp_sockets=1, udp_rx_only_sockets=1)
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )

        tcp_rx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 test_name=test_name, wifi_client=wifi_clients[0],
                                 traffic_type="RX", protocol="TCP", net_perf_client=net_perf_clients[0], timeout=60,
                                 device_ip=dut_addr_dict['dut_ip'], remote_ip=dut_addr_dict['client_ip'],
                                 ip_version=4, async_socket=1,
                                 )
        udp_rx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 test_name=test_name, wifi_client=wifi_clients[0],
                                 traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=60,
                                 device_ip=dut_addr_dict['dut_ip'], remote_ip=dut_addr_dict['client_ip'],
                                 ip_version=4, async_socket=1,
                                 )
        tcp_rx_obj.start()
        udp_rx_obj.start()
        time.sleep(5)

        tcp_rx_obj.wait_for_exit()
        udp_rx_obj.wait_for_exit()
        logger().info(f"TCP_RX & UDP_RX ran completed")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048, "priority": 8}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_verify_one_UDP_TX_and_UDP_RX_using_multithread_C689600(wifi_dut, wifi_clients, request, wifi_sniffer, net_perf_clients, wifi_access_point, sl_collections,utf_constants,  channel):
    """Verify  one UDP TX and UDP RX simultaneously using multi thread sockets
        steps:
          1:set_socket_config as per testrail
          2:DUT as AP should bring up and connect to client
          3:start 2 threads parallel
          4:run traffic using iperf in both threads parallel
          5:repeat steps 3&4 in loop for 3 times
          6:close all sockets and terminate threads.
        """
    test_name = request.node.name
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{689600}.pcap")
        time.sleep(3)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.set_socket_config(total_sockets=2, total_udp_sockets=2, total_tcp_sockets=0, udp_tx_only_sockets=1, tcp_rx_only_sockets=0,
                                                   tcp_rx_high_performance_sockets=0, udp_rx_only_sockets=1)
        dut_addr_dict= sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                  channel=11, ssid="SILABS_AP_MODE",
                                                  security="WPA2",
                                                  password="Automation@123",
                                                  dtim_count=1,
                                                  beacon_interval=100,
                                                  ping_count=10,
                                                  no_of_clients=1, leave=False
                                                  )

        udp_tx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 test_name=test_name, wifi_client=wifi_clients[0],
                                 traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[0], timeout=60,
                                 device_ip=dut_addr_dict['dut_ip'], remote_ip=dut_addr_dict['client_ip'],
                                 ip_version=4, async_socket=0,
                                 )
        udp_rx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 test_name=test_name, wifi_client=wifi_clients[0],
                                 traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=60,
                                 device_ip=dut_addr_dict['dut_ip'], remote_ip=dut_addr_dict['client_ip'],
                                 ip_version=4, async_socket=1,
                                 )
        udp_tx_obj.start()
        udp_rx_obj.start()
        time.sleep(5)

        udp_tx_obj.wait_for_exit()
        udp_rx_obj.wait_for_exit()
        logger().info(f"UDP_TX & UDP_RX traffic run is completed")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048, "priority": 8}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_verify_one_UDP_RX_and_UDP_TX_using_multithread_C689597(wifi_dut, wifi_clients, request, wifi_sniffer, net_perf_clients, wifi_access_point, sl_collections,utf_constants,  channel):
    """ Verify  one UDP RX and UDP TX simultaneously using multi thread sockets
        steps:
          1:set_socket_config as per testrail
          2:DUT as AP should bring up and connect to client
          3:start 2 threads parallel
          4:run traffic using iperf in both threads parallel
          5:repeat steps 3&4 in loop for 3 times
          6:close all sockets and terminate threads.
        """
    test_name = request.node.name
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{689597}.pcap")
        time.sleep(3)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.set_socket_config(total_sockets=2, total_udp_sockets=2, total_tcp_sockets=0, tcp_rx_high_performance_sockets=0,udp_tx_only_sockets=1, tcp_rx_only_sockets=0,
                                                   udp_rx_only_sockets=1)
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )

        udp_tx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 test_name=test_name, wifi_client=wifi_clients[0],
                                 traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[0], timeout=60,
                                 device_ip=dut_addr_dict['dut_ip'], remote_ip=dut_addr_dict['client_ip'],
                                 ip_version=4, async_socket=0,
                                 )
        udp_rx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 test_name=test_name, wifi_client=wifi_clients[0],
                                 traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=60,
                                 device_ip=dut_addr_dict['dut_ip'], remote_ip=dut_addr_dict['client_ip'],
                                 ip_version=4, async_socket=1,
                                 )
        udp_rx_obj.start()
        udp_tx_obj.start()
        time.sleep(5)

        udp_rx_obj.wait_for_exit()
        udp_tx_obj.wait_for_exit()
        logger().info(f"UDP_RX & UDP_TX run completed")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048, "priority": 8}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_verify_one_UDP_RX_and_TCP_RX_using_multithread_C689599(wifi_dut, wifi_clients, request, wifi_sniffer, net_perf_clients, wifi_access_point, sl_collections,utf_constants,  channel):
    """ Verify  one UDP RX and TCP RX simultaneously using multi thread sockets
        steps:
          1:set_socket_config as per testrail
          2:DUT as AP should bring up and connect to raspi as client
          3:start 2 threads parallel for TCP and UDP
          4:run traffic using iperf in both threads parallel
          5:close all sockets and terminate threads.
        """
    test_name = request.node.name
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{689599}.pcap")
        time.sleep(3)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.set_socket_config(total_sockets=2, total_tcp_sockets=1, total_udp_sockets=1,
                                                   udp_rx_only_sockets=1,
                                                   tcp_rx_only_sockets=1)
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )

        udp_rx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 test_name=test_name, wifi_client=wifi_clients[0],
                                 traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[0], timeout=60,
                                 device_ip= dut_addr_dict['dut_ip'],remote_ip=dut_addr_dict['client_ip'],
                                 ip_version=4, async_socket=1,
                                 )
        tcp_rx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 test_name=test_name, wifi_client=wifi_clients[0],
                                 traffic_type="RX", protocol="TCP", net_perf_client=net_perf_clients[1], timeout=60,
                                 device_ip=dut_addr_dict['dut_ip'], remote_ip=dut_addr_dict['client_ip'],
                                 ip_version=4, async_socket=1,
                                 )
        udp_rx_obj.start()
        tcp_rx_obj.start()
        time.sleep(5)

        udp_rx_obj.wait_for_exit()
        tcp_rx_obj.wait_for_exit()
        logger().info(f"UDP_rx & TCP_RX run successfully in multithreads")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.skip("validation is in progress")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 4, "stack_len": 2500, "priority": 8}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_verify_two_TCP_TX_and_TCP_RX_using_multithread_C689590(wifi_dut, wifi_clients, request, wifi_sniffer, remote_socket_factory, wifi_access_point, sl_collections, channel):
    """ Verify  two UDP RX and UDP TX simultaneously using multi thread sockets
        steps:
          1:set_socket_config as per testrail
          2:DUT as AP should bring up and connect to client
          3:start 2 threads parallel
          4:run traffic using iperf in both threads parallel
          5:repeat steps 3&4 in loop for 3 times
          6:close all sockets and terminate threads.
        """
    test_name = request.node.name
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{689590}.pcap")
        time.sleep(3)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.set_socket_config(total_sockets=4, total_tcp_sockets=4, tcp_rx_high_performance_sockets=2, tcp_rx_only_sockets=2,
                                                   tcp_tx_only_sockets=2)
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )
        tcp_tx_thread_1 = TCPThread(
            wifi_dut=wifi_dut,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=dut_addr_dict['client_ip'],
            dut_addr=dut_addr_dict,
            transfer_type="TX",
            port_number=5001,
        )
        tcp_tx_thread_2 = TCPThread(
            wifi_dut=wifi_dut,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=dut_addr_dict['client_ip'],
            dut_addr=dut_addr_dict,
            transfer_type="TX",
            port_number=5002,
        )
        tcp_rx_thread_1 = TCPThread(
            wifi_dut=wifi_dut,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=dut_addr_dict['client_ip'],
            dut_addr=dut_addr_dict,
            transfer_type="RX",
            port_number=5003,
        )
        tcp_rx_thread_2 = TCPThread(
            wifi_dut=wifi_dut,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=dut_addr_dict['client_ip'],
            dut_addr=dut_addr_dict,
            transfer_type="RX",
            port_number=5004,
        )
        tcp_tx_thread_1.start()
        tcp_tx_thread_1.wait_for_exit()
        tcp_tx_thread_2.start()
        tcp_tx_thread_2.wait_for_exit()
        tcp_rx_thread_1.start()
        tcp_rx_thread_1.wait_for_exit()
        tcp_rx_thread_2.start()
        tcp_rx_thread_2.wait_for_exit()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Submit the functions to the executor
            executor.submit(tcp_rx_thread_1.recv_tcp_data, 2)
            executor.submit(tcp_rx_thread_2.recv_tcp_data, 4)
            executor.submit(tcp_tx_thread_1.transmit_tcp_data)
            executor.submit(tcp_tx_thread_2.transmit_tcp_data)
        logger().info(f" TCP_TX  & TCP_RX ran in 2 threads is completed")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        wifi_dut.interfaces.wifi.stop_ap()

@pytest.mark.skip("validation is in progress")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 4, "stack_len": 2500, "priority": 8}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "beacon": 100,"channel": 11
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_verify_two_UDP_TX_and_UDP_RX_using_multithread_C689591(wifi_dut, wifi_clients, request, wifi_sniffer, remote_socket_factory, wifi_access_point, sl_collections, channel):
    """ Verify  two UDP RX and UDP TX simultaneously using multi thread sockets
        steps:
          1:set_socket_config as per testrail
          2:DUT as AP should bring up and connect to client
          3:start 2 threads parallel
          4:run traffic using iperf in both threads parallel
          5:repeat steps 3&4 in loop for 3 times
          6:close all sockets and terminate threads.
        """
    test_name = request.node.name
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{689590}.pcap")
        time.sleep(3)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.set_socket_config(total_sockets=4, total_tcp_sockets=0, tcp_rx_high_performance_sockets=0, tcp_rx_only_sockets=0,
                                                   tcp_tx_only_sockets=0, total_udp_sockets=4, udp_rx_only_sockets=2, udp_tx_only_sockets=2)
        dut_addr_dict = sl_collections.ap_mode_clients_connection(wifi_dut, wifi_clients,
                                                                  channel=11, ssid="SILABS_AP_MODE",
                                                                  security="WPA2",
                                                                  password="Automation@123",
                                                                  dtim_count=1,
                                                                  beacon_interval=100,
                                                                  ping_count=10,
                                                                  no_of_clients=1, leave=False
                                                                  )
        udp_tx_thread_1 = UDPThread(
            wifi_dut=wifi_dut,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=dut_addr_dict['client_ip'],
            dut_addr=dut_addr_dict,
            transfer_type="TX",
            port_number=1234,
        )
        udp_tx_thread_2 = UDPThread(
            wifi_dut=wifi_dut,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=dut_addr_dict['client_ip'],
            dut_addr=dut_addr_dict,
            transfer_type="TX",
            port_number=1235,
        )
        udp_rx_thread_1 = UDPThread(
            wifi_dut=wifi_dut,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=dut_addr_dict['client_ip'],
            dut_addr=dut_addr_dict,
            transfer_type="RX",
            port_number=1236,
        )
        udp_rx_thread_2 = UDPThread(
            wifi_dut=wifi_dut,
            remote_socket_factory=remote_socket_factory,
            remote_ip_address=dut_addr_dict['client_ip'],
            dut_addr=dut_addr_dict,
            transfer_type="RX",
            port_number=1237,
        )
        udp_tx_thread_1.start()
        udp_tx_thread_1.wait_for_exit()
        udp_tx_thread_2.start()
        udp_tx_thread_2.wait_for_exit()
        udp_rx_thread_1.start()
        udp_rx_thread_1.wait_for_exit()
        udp_rx_thread_2.start()
        udp_rx_thread_2.wait_for_exit()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Submit the functions to the executor
            executor.submit(udp_rx_thread_1.rev_udp_data, 2)
            executor.submit(udp_rx_thread_2.rev_udp_data, 4)
            executor.submit(udp_tx_thread_1.transmit_udp_data)
            executor.submit(udp_tx_thread_2.transmit_udp_data)
        logger().info(f" TCP_TX  & TCP_RX ran in 2 threads is completed")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        wifi_dut.interfaces.wifi.stop_ap()
