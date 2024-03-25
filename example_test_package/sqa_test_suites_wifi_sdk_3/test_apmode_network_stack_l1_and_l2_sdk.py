import re
import time
import test_apmode_sdk as ap
import string
import random
from utf.utils.thread_base import ThreadBase
from random import randint
from utf.utils.stopwatch import Stopwatch
from threading import Thread
import threading
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



def logger():
    return get_logger(__name__)

"""Test Author = Jyothi Nagireddy

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
class SocketDataTransfer:

    @staticmethod
    def close_socket(wifi_dut, socket_id, remote_socket):
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
        logger().info(f"Successfully closed socket_id '{socket_id}' in the DUT")
        remote_socket.interfaces.socket.stop()

    @staticmethod
    def send_data(remote_socket, tx_buffer, pkt_count=10, sock_id=None, use_server=True):
        for _ in range(pkt_count):
            if sock_id is None:
                remote_socket.interfaces.socket.send_data_tcp(tx_buffer, use_server)
            else:
                remote_socket.interfaces.socket.sockets[sock_id].send_data_tcp(tx_buffer, use_server)


    @staticmethod
    def recv_data(remote_socket, no_of_pkts, sock_id=None, data_size=1460, proto_type=0):
        remote_socket.interfaces.sockets[sock_id].set_recv_timeout(socket_type=0)
        data = remote_socket.interfaces.sockets[sock_id].recv_data_tcp(data_size)
        rcv_data = rcv_data + len(data)
        logger().info(f"Total bytes received on socket opened remotely -> {self.rcv_data}")



class data_transfer:
    def __init__(self, index=None):
        self.thread_lock = threading.Lock()
        self.sent_data = 0
        self.rcv_data = 0
        self.index = index

    def receive_data_socket(self, remote_socket_factory, no_of_pkts, data_size=1460, proto_type=0):
        fail_count = 0
        if proto_type == 0:
            remote_socket_factory.interfaces.sockets[self.index].set_recv_timeout(socket_type=0)
        else:
            remote_socket_factory.interfaces.sockets[self.index].set_recv_timeout(use_client_socket=True, socket_type=1)
        for count in range(0, no_of_pkts):
            if proto_type == 0:
                data = remote_socket_factory.interfaces.sockets[self.index].recv_data_tcp(data_size)
            else:
                data, address = remote_socket_factory.interfaces.sockets[self.index].recv_data_udp(data_size)
            if not isinstance(data, str):
                fail_count = fail_count + 1
                if fail_count == 5:
                    break
                else:
                    continue
            self.rcv_data = self.rcv_data + len(data)
        logger().info(f"Total bytes received on socket opened remotely -> {self.rcv_data}")



class ApmodeConnection(ThreadBase):
    def __init__(self, wifi_dut, wifi_clients):
        self.wifi_dut = wifi_dut
        self.wifi_clients = wifi_clients

    def  connect_clients_to_dut_as_ap(self, dut_ip=None):
        ip_dict = {}
        connected = False
        for i in range(len(self.wifi_clients)):
            logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is joining to DUT-AP")
            self.wifi_clients[i].interfaces.wifi.join()
            time.sleep(5)
            if dut_ip is None:
                ip_dict['dut_ip'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            else:
                ip_dict['dut_ip'] = dut_ip
            logger().info(f"********* Dut IP **********: {ip_dict['dut_ip']}")
            for retry_count in range(4):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{self.wifi_clients[i].name}' to DUT")
                    ip_dict[f'client{i + 1}_ip'] = self.wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client{i + 1}_ip: {ip_dict[f'client{i + 1}_ip']}")
                    ip_dict[f'rasp_mac_address_{i+1}'] = self.wifi_clients[i].interfaces.wifi.get_mac_address()
                    logger().info(f"raspi_mac: {ip_dict[f'rasp_mac_address{i+1}']}")
                    rc, stdout, stderr = self.wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {10} {ip_dict['dut_ip']}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except Exception as error:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT:\n{error}...retry count -> {retry_count+1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        return ip_dict

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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_DUTAP_tcp_remote_termiate_C19466(wifi_sniffer, sniffer_filter, wifi_access_point, net_perf_client, wifi_dut, utf_constants, protocol, sl_collections, wifi_clients):
    '''Run tcp iperf data transfer , check for remote terminate in the dut'''
    try:
        ap_dut_obj = ap.ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                                utf_constants, net_perf_client=net_perf_client, protocol=protocol,
                                                capture_filename="test_C19466",
                                                testcase_no=19465, traffic_type="Tx", leave=False,
                                                sniffer_stop=False)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        events = wifi_dut.interfaces.wifi.get_async_events()
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
@pytest.mark.skip("testagent issue")
def test_wifi_sdk_DUTAP_remote_terminate_while_sending_tcp_data_on_4sockets_C19482(wifi_access_point, utf_constants, sniffer_filter, wifi_sniffer, wifi_dut, wifi_client, remote_socket_factory, sl_collections, wifi_clients):
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
        logger().info(f"closing the socket on dut")
        wifi_dut.interfaces.wifi.close_sockets()
        events = wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.TCP_REMOTE_TERMINATE:
                remote_terminate = event.event_data
                assert remote_terminate, f"unable to find remote terminate event"
                logger().info("Remote terminate event is received by DUT when tcp socket connected is closed")
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584, "priority": 8}},
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
def  test_wifisdk_DUTAP_open_10_TCP_client_sockets_send_tx_C19473(wifi_sniffer, wifi_dut, wifi_client, utf_constants, remote_socket_factory, sl_collections, wifi_clients):
    '''Open 10 TCP client sockets and Data TX in ap mode'''
    try:
        no_of_pkts = 100
        pkt_length = 1460
        local_port = randint(5001, 6000)
        iter_count = utf_constants.get('iter_count')
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
        for count in range(1, iter_count + 1):
            client_ips = []
            client_sockets = []
            for _ in range(1, 10):
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
                tcp_socket_id = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
                if isinstance(tcp_socket_id, int):
                    logger().info(f"Socket open successfully : {tcp_socket_id}")
                else:
                    logger().error(f"Unable to open socket id: {tcp_socket_id}")
                    raise RuntimeError(tcp_socket_id)
                dut_sockets.append(tcp_socket_id)
                time.sleep(5)
                bind_response = wifi_dut.interfaces.wifi.bind(tcp_socket_id, dut_addr_dict['dut_ip'], 4, server_port= server_port, timeout=5)
                time.sleep(3)
                logger().info(f"connecting to the server")
                connect_response = wifi_dut.interfaces.wifi.bsdSocketConnect(tcp_socket_id, dut_addr_dict['client_ip'],
                                                                         server_port=server_port)
                logger().info(f"Connect response : {connect_response}")
            data_sent = []
            for _ in client_sockets:
                data_sent.append(get_random_data(1460))

            for index in dut_sockets:
                send_bytes = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=dut_sockets[index], data=data_sent,
                                                                         timeout=120)
                logger().info(f"********{send_bytes}")
            # results = ThreadBase.call_functions_simultaneously(
            #     [(wifi_dut.interfaces.wifi.bsdSocketSend, dut_sockets[index], len(data), data) for index, data in
            #      enumerate(data_sent)]
            # )
            for index, client_socket in enumerate(client_sockets):
                data = data_sent[index]
                logger().info(f"Data sent to client {index} - {data}")
                data_recv = client_socket.recv_data_tcp(len(data))
                logger().info(f"Data received in client {index} - {data_recv}")
                assert data_recv == data
            # for index in range(10):
            #     server_port = server_base_port + index
            #     tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))
            #     send_bytes = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=socket_id, data=tx_buffer,
            #                                                              timeout=120)
            #     logger().info(f'SEND-Bytes = {send_bytes}')
                # data_transfer_obj = data_transfer(index=index)
                # th_start = Thread(target=data_transfer_obj.receive_data_socket,
                #                   args=(remote_socket_factory, no_of_pkts, pkt_length, 1), daemon=True)
                # th_start.start()
                # bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(dut_sockets[index], pkt_length, no_of_pkts,
                #                                                      server_ip=client_ips[index],
                #                                                      server_port=server_port)
                # logger().info(f"Number of bytes sent by dut {bytes_sent}")
                # th_start.join(5)

            logger().info(f"closing the sockets on remote side")
            remote_socket_factory.interfaces.socket.close_all()
            time.sleep(15)
            logger().info("Stop the sniffer")
            wifi_sniffer.interfaces.capture.stop_capture()
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
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "client_socket_limit": 10,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.skip("testagent issue")
def test_DUTAP_LTCP_socket_connection_when_max_sockets_limit_to_11_C19472(wifi_access_point, wifi_clients, wifi_sniffer, sl_collections, wifi_dut, utf_constants, remote_socket_factory):
    '''Checking maximum socket limit(11) on the Dut in ap mode connection'''
    try:
        socket_limit = 11
        ap_dut_obj = ap.ApMode_ClientConns(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                           utf_constants,
                                           dtim_count=None, dut_addr_dict=None,
                                           beacon=None, testcase_no=19465)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        server_base_port = 5001
        dut_sockets = []
        for index in range(socket_limit):
            server_port = server_base_port + index
            logger().info(f"opening socket_id_{index}")
            sock = wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP",
                                                   timeout=15)
            dut_sockets.append(sock)
            wifi_dut.interfaces.wifi.bind(sock, dut_ip, server_port)
            time.sleep(2)
        wifi_dut.interfaces.wifi.close_sockets()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


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
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
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
def test_wifisdk_DUTAP_open_10_UDP_client_sockets_send_tx_C19474(wifi_sniffer, wifi_dut, wifi_client, utf_constants, remote_socket_factory, sl_collections, wifi_clients):
    try:
        no_of_pkts = 10000
        pkt_length = 1460
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
        client_ips = []
        for _ in range(0, 10):
            client_ips.append(dut_addr_dict['client_ip'])
            client_socket = remote_socket_factory.interfaces.socket.create_socket(
                interface="wlan0"
            )
            client_sockets.append(client_socket)
        server_base_port = 5001
        dut_sockets = []
        for index, client_socket in enumerate(client_sockets):
            server_port = server_base_port + index
            logger().info(f"Client socket: {client_socket}")
            client_socket.start_server(
                server_ip=client_ips[index], port=server_port, socket_type=1,
            )
            udp_socket_id = wifi_dut.interfaces.wifi.socket(stream_type="SOCK_DGRAM",
                                                            protocol="IPPROTO_UDP")
            logger().info(f"Socket open successfully : {udp_socket_id}")
            dut_sockets.append(udp_socket_id)
            logger().info(
                f"Successfully opened tcp client socket and socket id received is {udp_socket_id} which is expected")
            bind_response = wifi_dut.interfaces.wifi.bind(socket_fd=udp_socket_id,
                                                          device_ip=dut_addr_dict['dut_ip'], ip_len=4,
                                                          server_port=server_port, timeout=5)
            logger().info(f"Bind socket successfully: {bind_response}")
            logger().info("DUT is connecting to server socket")
        for index in range(10):
            server_port = server_base_port + index
            data_transfer_obj = data_transfer(index=index)
            th_start = Thread(target=data_transfer_obj.receive_data_socket,
                              args=(remote_socket_factory, no_of_pkts, pkt_length, 1), daemon=True)
            th_start.start()
            bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(dut_sockets[index], pkt_length, no_of_pkts,
                                                                 server_ip=client_ips[index], server_port=server_port)
            logger().info(f"Number of bytes sent by dut {bytes_sent}")
            th_start.join(5)
            result = wifi_dut.interfaces.wifi.get_socket_rx_stats(dut_sockets[index])
            bytes_received = int(result.split(b":")[1])
            logger().info(f"bytes received on socket {index} -> {bytes_received}")
        # data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))
        # logger().info(f"*********{data}")
        # for index in range(10):
        #     wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=dut_sockets[index], data=data, timeout=120)
        #
        # for index, client_socket in enumerate(client_sockets):
        #     data = data[index]
        #     logger().info(f"Data sent to client {index} - {data}")
        #     data_recv = client_socket.recv_data_tcp(len(data))
        #     logger().info(f"Data received in client {index} - {data_recv}")
        #     assert data_recv == data

        for index in dut_sockets:
           wifi_dut.interfaces.wifi.bsdSockClose(dut_sockets[index])

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
                    else:
                        logger().info(f"************2nd raspi: {net_perf_clients[i].name}*********")
                        sl_collections.run_traffic(wifi_dut, net_perf_client, protocol, ap_dut_obj.dut_addr_dict['dut_ip'], client_ip_1, timeout,
                                                   traffic_type="RX")
                        time.sleep(15)
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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
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
def test_wifisdk_DUTAP_open_10_tcp_server_sockets_rx_C19475(wifi_dut, wifi_sniffer, wifi_client, utf_constants, remote_socket_factory, sl_collections, wifi_clients):
    """Open 10 TCP server sockets and Data RX"""
    try:
        ap_dut_obj = ap.ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                                utf_constants,
                                                capture_filename="test_C19475",
                                                testcase_no=19465,  leave=False, sniffer_stop=False)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
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
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=ap_dut_obj.dut_addr_dict['dut_ip'],
                                          server_port=local_port, timeout=5, asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)
            ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1, count),
                    (client_socket[count].connect_client_tcp, ap_dut_obj.dut_addr_dict['dut_ip'], local_port),
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

        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()


    finally:
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
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
def test_wifisdk_DUTAP_open_10_udp_server_sockets_rx_C19476(wifi_dut, wifi_sniffer, wifi_client,
                                                                   utf_constants, remote_socket,
                                                                   sl_collections, wifi_clients):
    """Open 10 UDP server sockets and Data RX"""
    try:
        udp_socks = []
        ap_dut_obj = ap.ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                                utf_constants,
                                                capture_filename="test_C19476",
                                                testcase_no=19465, leave=False, sniffer_stop=False)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        start_port = 8001
        start_port_dut = 6001
        for sock_count in range(0, 10):
            port = start_port + sock_count
            port_dut = start_port_dut + sock_count
            remote_socket.interfaces.socket.start_server(port=port, socket_type=1)
            sock_id = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
            udp_socks.append(sock_id)
            logger().info(
                f"Successfully opened UDP client socket and socket id received is {sock_id} which is expected")
            wifi_dut.interfaces.wifi.bind(socket_fd=sock_id, device_ip= ap_dut_obj.dut_addr_dict['dut_ip'],
                                          server_port=port_dut, asynch=1)

        for socket_no in range(0, 10):
            data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
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
            logger().info(f"###################### start_port from DUT : {start_port_dut}  ######################")

            remote_socket.interfaces.socket.send_data_udp(
                tx_buffer=data_sent, server_ip=ap_dut_obj.dut_addr_dict['dut_ip'], port=start_port_dut)
            time.sleep(2)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket_no)
            logger().info(f"###################### Buffer Data  {data_sent}  ######################")
            logger().info(f"###################### Buffer Data Length  {data_length}  ######################")
            logger().info(f"###################### Received Data: {buffer_rx} ######################")
            assert data_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {socket_no} opened in the DUT is not matched "
        time.sleep(2)
        for socket in udp_socks:
            logger().info(f"Closing socket_id->{socket}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket)
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()

    finally:
        wifi_dut.interfaces.wifi.stop_ap()