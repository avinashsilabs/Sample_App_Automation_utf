import re
import time
import test_apmode_sdk.py as ap
from threading import Thread
from random import randint
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
import pytest as pytest
from utf.utils import get_random_data
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf import UtfDatabaseProperties
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
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
                server_ip=client_ips[index], port=server_port, socket_type=SOCKET_TYPE_UDP
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
    def __init__(self, wifi_dut, remote_socket, utf_constants):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.remote_socket = remote_socket
        self.utf_constants = utf_constants

    def run_tcp_traffic(self, dut_ip=None):
        logger().info("Starting TCP server socket remotely")
        proto_type = "TCP"
        no_of_packets = 10000
        packet_length = 4
        local_port = randint(6000, 6100)
        self.remote_socket.interfaces.socket.interface = "wlan0"
        logger().info("Starting TCP Server socket at remote device")
        self.remote_socket.interfaces.socket.start_server(port=local_port)
        server_ip = self.remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = self.remote_socket.interfaces.socket.server_port

        logger().info(f"DUT opens tcp client socket")
        tcp_socket_id = self.wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                        protocol="IPPROTO_TCP",
                                                        timeout=15)
        logger().info(f"Socket open successfully : {tcp_socket_id}")
        time.sleep(5)

        logger().info(f"Socket binds at (device_ip, 5001) in DUT")
        bind_response = self.wifi_dut.interfaces.wifi.bind(tcp_socket_id, dut_ip, local_port)
        logger().info(f"Bind socket successfully: {bind_response}")

        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(tcp_socket_id, self.remote_socket.interfaces.socket, server_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")
        time.sleep(3)
        # Send and receive data.
        # t1 = Thread(target=receive_data_socket, args=(self.remote_socket, no_of_packets, packet_length, proto_type), )
        for count in range(3):
            try:
                logger().info("Receiving TCP data from DUT")
                # t1.start()
                time.sleep(2)
                logger().info("DUT Sending Data packets")
                bytes_sent = self.wifi_dut.interfaces.wifi.send_data_pkts(tcp_socket_id, pkt_length=packet_length,
                                                                     no_of_pkts=no_of_packets,
                                                                     server_ip=server_ip, server_port=server_port)
                logger().info(f"Number of bytes sent by dut {bytes_sent}")
                break
            except Exception as err:
                logger().info(f"Error is {err}")
                error_code = "0x9"
                if error_code in str(err):
                    raise err
                logger().info(f"Unable to send data packets from DUT...retry:{count + 1}")
                # t1.join()
                time.sleep(30)

        time.sleep(5)
        logger().info("Closing opened socket in DUT")
        try:
            result = self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=tcp_socket_id)
            assert b"success" in result, "Unable to close the udp socket"
            logger().info("Socket closed successfully")
        except:
            logger().info("Unable to close the socket")
        # t1.join()

    def run_udp_traffic(self, dut_ip=None):
        proto_type = "UDP"
        no_of_packets = 10000
        packet_length = 4
        local_port = randint(5001, 6000)
        logger().info("Starting UDP server socket at remote device")
        self.remote_socket.interfaces.socket.interface = "wlan0"
        self.remote_socket.interfaces.socket.start_server(socket_type=1)  # 0-TCP, 1-UDP
        server_ip = self.remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = self.remote_socket.interfaces.socket.server_port

        logger().info("Opening UDP client socket in DUT")
        udp_socket_id = self.wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
        logger().info(f"Successfully opened UDP client socket on DUT with socket id:'{udp_socket_id}'")

        logger().info("Initiating socket bind from DUT")
        self.wifi_dut.interfaces.wifi.bind(udp_socket_id, dut_ip, local_port)
        logger().info("Socket binding is success")

        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                self.wifi_dut.interfaces.wifi.connect_to_server(udp_socket_id, self.remote_socket.interfaces.socket, server_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")
        time.sleep(3)

        logger().info("Receiving UDP data from DUT")
        # t1 = Thread(target=receive_data_socket, args=(self.remote_socket, no_of_packets, packet_length, proto_type), )
        # t1.start()
        time.sleep(2)
        logger().info("DUT is sending UDP data packets")
        bytes_sent = self.wifi_dut.interfaces.wifi.send_data_pkts(udp_socket_id, pkt_length=packet_length,
                                                             no_of_pkts=no_of_packets,
                                                             server_ip=server_ip, server_port=server_port)
        logger().info(f"Number of bytes sent by dut {bytes_sent}")
        time.sleep(5)
        try:
            logger().info("Closing opened socket in DUT")
            result = self.wifi_dut.interfaces.wifi.close_socket(udp_socket_id)
            assert b"success" in result, "Unable to close the udp socket"
            logger().info("Successfully closed opened socket in DUT")
        except:
            logger().info("Unable to close the socket")
        # t1.join()
        time.sleep(30)
        logger().info("\n\n")





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
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "12345678", "channel": 11
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_sdk_DUTAP_Validate_UDP_Rx_data_C19465(wifi_sniffer, net_perf_client, wifi_clients, wifi_dut, protocol,
                                           utf_constants, teardown, sl_collections, wifi_access_point, sniffer_filter):
    '''Validate UDP Tx data on Remote peer in ap mode connection'''
    iter_count = utf_constants.get('iter_count')
    try:
        for count in range(iter_count):
            logger().info(f"Initiating test for iteration: {count + 1}")
            ap_dut_obj = ap.ApMode_ClientConns(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections, utf_constants,
                                            dtim_count=None, dut_addr_dict=None, beacon=None,
                                            testcase_no=19465)
            ap_dut_obj.start()
            ap_dut_obj.wait_for_exit()
            sl_collections.run_iperf_rx()
            logger().info("Stop sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info(f"Iteration '{count + 1}' completed")
            sl_collections.ap_sniffer_validation(wifi_sniffer, sniffer_filter, dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'], rasp_mac_address= ap_dut_obj.dut_addr_dict['client_ip'])

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



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
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "12345678", "channel": 11
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_DUTAP_Validate_TCP_Rx_data_C19464(wifi_sniffer, net_perf_client, wifi_dut, protocol,
                                           utf_constants, teardown, sl_collections, wifi_clients, wifi_access_point, sniffer_filter):
    '''Validate TCP Rx data on Remote peer in ap mode connection'''
    iter_count = utf_constants.get('iter_count')
    try:
        for count in range(iter_count):
            logger().info(f"Initiating test for iteration: {count + 1}")
            ap_dut_obj = ap.ApMode_ClientConns(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections, utf_constants,
                                            dtim_count=None, dut_addr_dict=None,
                                            beacon=None, testcase_no=19465)
            ap_dut_obj.start()
            ap_dut_obj.start()
            ap_dut_obj.wait_for_exit()
            sl_collections.run_iperf_rx()
            sl_collections.ap_sniffer_validation(wifi_sniffer, sniffer_filter, dut_mac_address= ap_dut_obj.dut_addr_dict['dut_mac_address'], rasp_mac_address= ap_dut_obj.dut_add_dict['client_ip'])
            logger().info(f"Iteration '{count + 1}' completed")

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
        "client_socket_limit": 10,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "12345678", "channel": 11
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_DUTAP_Validate_TCP_Tx_data_C19462(wifi_sniffer, net_perf_client, wifi_dut, protocol,
                                           utf_constants, teardown, sniffer_filter, sl_collections, wifi_clients, dtim_period, wifi_access_point):
    '''Validate TCP Tx data on Remote peer in ap mode connection'''
    try:
        iter_count = utf_constants.get('iter_count')
        for count in range(iter_count):
            logger().info(f"Initiating test for iteration: {count + 1}")
            ap_dut_obj = ap.ApMode_ClientConns(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                               utf_constants,
                                               dtim_count=None, dut_addr_dict=None,
                                               beacon=None, testcase_no=19465)
            ap_dut_obj.start()
            ap_dut_obj.wait_for_exit()
            sl_collections.run_iperf_tx()
            sl_collections.ap_sniffer_validation(wifi_sniffer, sniffer_filter, dut_mac_address= ap_dut_obj.dut_addr_dict['dut_mac_address'], rasp_mac_address= ap_dut_obj.dut_addr_dict['client_ip'])
            logger().info(f"Iteration '{count + 1}' completed")

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
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "12345678", "channel": 11
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_sdk_DUTAP_Validate_UDP_Tx_data_C19463(wifi_sniffer, net_perf_client, wifi_dut, protocol,
                                           utf_constants, teardown, sl_collections, sniffer_filter, wifi_clients, dtim_period,  wifi_access_point):
    '''Validate UDP Tx data on Remote peer in ap mode connection'''
    try:
        iter_count = utf_constants.get('iter_count')
        for count in range(iter_count):
            logger().info(f"Initiating test for iteration: {count + 1}")
            ap_dut_obj = ap.ApMode_ClientConns(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                               utf_constants,
                                               dtim_count=None, dut_addr_dict=None,
                                               beacon=None, testcase_no=19465)
            ap_dut_obj.start()
            ap_dut_obj.wait_for_exit()
            sl_collections.run_iperf_tx()
            sl_collections.ap_sniffer_validation(wifi_sniffer, sniffer_filter, dut_mac_address= ap_dut_obj.dut_addr_dict['dut_mac_address'], rasp_mac_address= ap_dut_obj.dut_addr_dict['client_ip'])
            logger().info(f"Iteration '{count + 1}' completed")
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
        "client_socket_limit": 10,
        "server_socket_limit": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "12345678", "channel": 11
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
def test_wifi_sdk_DUTAP_TCP_Socket_Create_Transfer_Terminate_30min_C19480(wifi_sniffer,sniffer_filter, remote_socket, wifi_dut,
                                                                utf_constants, teardown, wifi_access_point, sl_collections, wifi_clients, dtim_period):
    '''By creating socket need to test tcp data transfer functionality in ap mode for 30mins'''
    try:
        expected_error_count = 2,
        test_run_time = utf_constants.get('time_duration')
        ap_dut_obj = ap.ApMode_ClientConns(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                           utf_constants,
                                           dtim_count=None, dut_addr_dict=None,
                                           beacon=None, testcase_no=19465)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        sw = Stopwatch()
        logger().info(
            f"***** Starting TCP Socket creation and data transfer for {round((test_run_time / 60), 2)} min *****")
        error_count = 0
        while sw.elapsed_sec <= test_run_time:
            time_left = round(((test_run_time - sw.elapsed_sec) / 60), 2)
            logger().info(f"Remaining time to complete test is '{time_left}' minutes")
            logger().info("***** Initiating UDP TX traffic from DUT *****")
            try:
                wifi_obj = SocketDataTransfer(wifi_dut, remote_socket, utf_constants)
                wifi_obj.run_tcp_traffic(dut_ip=ap_dut_obj.dut_add_dict['device_ip'])
                time.sleep(30)
                logger().info("\n\n")
            except Exception as err:
                logger().error(f"********** {str(err)}********")
                if "0x9" in str(err):
                    error_count += 1
        logger().info(f"***** error count observed : {error_count}")
        sl_collections.ap_sniffer_validation(wifi_sniffer, sniffer_filter,
                                             dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                             rasp_mac_address=ap_dut_obj.dut_addr_dict['client_ip'])


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
        "client_socket_limit": 10,
        "server_socket_limit": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "12345678", "channel": 11
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
def test_wifi_sdk_DUTAP_UDP_Socket_Create_Transfer_Terminate_30min_C19481(wifi_sniffer, wifi_access_point, remote_socket, wifi_dut,
                                                                 utf_constants, sniffer_filter, teardown, sl_collections, wifi_clients, dtim_period):
    '''By creating socket need to test udp data transfer functionality in ap mode for 30mins'''
    try:
        expected_error_count = 2
        test_run_time = utf_constants.get('time_duration')
        ap_dut_obj = ap.ApMode_ClientConns(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                           utf_constants,
                                           dtim_count=None, dut_addr_dict=None,
                                           beacon=None, testcase_no=19465)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        sw = Stopwatch()
        logger().info(
            f"***** Starting UDP Socket creation and data transfer for {round((test_run_time / 60), 2)} min *****")
        while sw.elapsed_sec <= test_run_time:
            time_left = round(((test_run_time - sw.elapsed_sec) / 60), 2)
            logger().info(f"Remaining time to complete test is '{time_left}' minutes")
            wifi_obj = SocketDataTransfer(wifi_dut, remote_socket, utf_constants)
            wifi_obj.run_udp_traffic(dut_ip=ap_dut_obj.dut_add_dict['device_ip'])
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.ap_sniffer_validation(wifi_sniffer, sniffer_filter,
                                             dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                             rasp_mac_address=ap_dut_obj.dut_addr_dict['client_ip'])

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


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
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "12345678", "channel": 11
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_DUTAP_tcp_remote_termiate_C19466(wifi_sniffer, sniffer_filter, wifi_access_point, net_perf_client, wifi_dut, channel, utf_constants, protocol, sl_collections, wifi_clients, dtim_period, beacon):
    '''Run tcp iperf data transfer , check for remote terminate in the dut'''
    iter_count = utf_constants.get('iter_count')
    try:
        for count in range(1, iter_count):
            logger().info(f"Initiating test for iteration: {count}")
            ap_dut_obj = ap.ApMode_ClientConns(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                           utf_constants,
                                           dtim_count=None, dut_addr_dict=None,
                                           beacon=None, testcase_no=19465)
            ap_dut_obj.start()
            ap_dut_obj.wait_for_exit()
            sl_collections.run_iperf_tx()
            logger().info("Stop sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            events = wifi_dut.interfaces.wifi.get_async_events()
            for event in events:
                # if event.event_type == RS9116AsyncEventType.TCP_REMOTE_TERMINATE:
                    remote_terminate = event.event_data
                    assert remote_terminate, f"unable to find remote terminate event"
                    logger().info("Remote terminate event is received by DUT when tcp socket connected is closed")
            sl_collections.ap_sniffer_validation(wifi_sniffer, sniffer_filter,
                                                 dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                                 rasp_mac_address=ap_dut_obj.dut_addr_dict['client_ip'])
            logger().info(f"Iteration '{count + 1}' completed")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


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
        "client_socket_limit": 4,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "12345678", "channel": 11
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
def test_wifi_sdk_DUTAP_remote_terminate_while_sending_tcp_data_on_4sockets_C19482(wifi_access_point, utf_constants, sniffer_filter, wifi_sniffer, wifi_dut, wifi_client, channel, utf_constants, remote_socket_factory, sl_collections, wifi_clients):
    '''create 4 sockets ,do the data transfer check for remote terminate event in the dut'''
    iter_count = utf_constants.get('iter_count')
    try:
        for count in range(1, iter_count + 1):
            ap_dut_obj = ap.ApMode_ClientConns(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                           utf_constants,
                                           dtim_count=None, dut_addr_dict=None,
                                           beacon=None, testcase_no=19465)
            socket_obj = MultiSocketsConnectionTx(wifi_dut, wifi_client, remote_socket_factory, utf_constants,
                                                  remote_close=True)
            ap_dut_obj.start()
            ap_dut_obj.wait_for_exit()
            socket_obj.multi_sockets_tx(socket_count=4)
            sl_collections.ap_sniffer_validation(wifi_sniffer, sniffer_filter,
                                                 dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                                 rasp_mac_address=ap_dut_obj.dut_addr_dict['client_ip'])

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


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
def test_wifisdk_DUTAP_open_10_client_sockets_send_tx_C19473(wifi_access_point, wifi_sniffer, sniffer_filter, wifi_dut, wifi_client, utf_constants, remote_socket_factory, sl_collections, wifi_clients):
    '''Open 10 TCP client sockets and Data TX in ap mode'''
    try:
        iter_count = utf_constants.get('iter_count')
        for count in range(1, iter_count + 1):
            ap_dut_obj = ap.ApMode_ClientConns(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
                                           utf_constants,
                                           dtim_count=None, dut_addr_dict=None,
                                           beacon=None, testcase_no=19465)
            socket_obj = MultiSocketsConnectionTx(wifi_dut, wifi_client, remote_socket_factory, utf_constants,
                                                  remote_close=True)
            ap_dut_obj.start()
            ap_dut_obj.wait_for_exit()
            socket_obj.multi_sockets_tx(socket_count=10)
            logger().info("Stop sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info(f"Iteration '{count}' completed")
            sl_collections.ap_sniffer_validation(wifi_sniffer, sniffer_filter,
                                                 dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                                 rasp_mac_address=ap_dut_obj.dut_addr_dict['client_ip'])

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


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
def test_DUTAP_LTCP_socket_connection_when_max_sockets_limit_to_11_C19472(wifi_access_point, wifi_clients, wifi_sniffer, sl_collections, wifi_dut, utf_constants, remote_socket_factory):
    '''Checking maximum socket limit(11) on the Dut in ap mode connection'''
    try:
        socket_limit = 11
        ap_dut_obj =  ap.ApMode_ClientConns(wifi_dut, wifi_clients, wifi_sniffer, wifi_access_point, sl_collections,
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

