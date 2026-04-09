import time
import pytest
import string
import random
from retry import retry
from threading import Thread
from random import randint
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.socket import SOCKET_TYPE_TCP, SOCKET_TYPE_UDP
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xOperatingMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xModuleType
)
import re

"""
Test author: CG Team
The testcases added in this file run below test steps for DUT-Si91x
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new TCP or UDP socket
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.
        7. Run socket select command
        8. Send data from the remote peer
        9. Check whether socket select api returns with the correct socket id on which data is available 
        10. Send and receive the data over the socket. Verify the data integrity and packet loss checks.
    setup requirement:
        1. DUT(Si91x)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC device for Sniffer
"""


def logger():
    return get_logger(__name__)


class ssl_connection:
    """
    Class to configure SSL and Rejoin parameters in DUT along with WLAN and SSL Socket Connection.
    """

    def __init__(self, wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections,
                 listen_interval=0, rejoin_params=None):
        self.wifi_dut = wifi_dut
        self.wifi_sniffer = wifi_sniffer
        self.rejoin_params = rejoin_params
        self.sl_collections = sl_collections
        self.listen_interval = listen_interval
        self.capture_filename = capture_filename
        self.wifi_access_point = wifi_access_point

    def join_get_ip(self, sniff_capture=True, power_save=True):
        if sniff_capture:
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        if not self.rejoin_params:
            self.rejoin_params = [20, 6, 40, 0]
        result = self.sl_collections.join_to_wifi_network_with_rejoin(self.wifi_dut, self.wifi_access_point,
                                                                      self.rejoin_params, power_save=power_save,
                                                                      listen_interval=self.listen_interval,
                                                                      associated=False)
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        return dut_ip, dut_mac_address


class SocketDataTransfer:
    def __init__(self):
        self.connected = False
        self.sock = None

    @retry(Exception, delay=1, tries=5)
    def open_socket_and_data_transfer(self, wifi_dut, remote_socket, dut_ip, numberOfFds=0, close_socket=True,
                                      test_run_time=30):
        self.sock = 0
        try:
            if not self.connected:
                local_port = randint(20001, 40000)
                server_port = randint(6000, 6100)
                remote_socket.interfaces.socket.time_limit = 3600
                remote_socket.interfaces.socket.start_server(socket_type=0, port=server_port)  # 0-TCP, 1-UDP
                server_ip = remote_socket.interfaces.socket.server_ip
                self.sock = wifi_dut.interfaces.wifi.socket()
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {self.sock} which is expected")
                wifi_dut.interfaces.wifi.bind(socket_fd=self.sock, device_ip=dut_ip, server_port=local_port, timeout=15)
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=self.sock, server_ip=server_ip, server_port=server_port)
                self.connected = True
                if numberOfFds:
                    wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=numberOfFds, time=60)

            sw = Stopwatch()
            while sw.elapsed_sec <= test_run_time:
                tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger().info(f"Remote peer sending data over socket {self.sock} and data:{tx_buffer}")
                remote_socket.interfaces.socket.send_data_tcp(tx_buffer, use_server_socket=True)
                time.sleep(1)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=self.sock, async_timeout=40, timeout=40)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{self.sock} opened in the DUT is not matched"
                logger().info("Data sent by remote peer and received on DUT is matching")
            if close_socket:
                self.close_socket(wifi_dut, self.sock, remote_socket)
            return self.sock
        except Exception as error:
            if "0x1" in str(error) or "0x7" in str(error):
                logger().error(f"*********** Data Receive failed due to AP-Power Off ************")

    @staticmethod
    def close_socket(wifi_dut, socket_id, remote_socket):
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
        logger().info(f"Successfully closed socket_id '{socket_id}' in the DUT")
        remote_socket.interfaces.socket.stop()

    @staticmethod
    def send_data(remote_socket_factory, socket_no, udp_buffer, dut_ip, start_port, pkt_count=1, remote_socket=None):
        for _ in range(pkt_count):
            if remote_socket:
                remote_socket.interfaces.socket.send_data_udp(udp_buffer, dut_ip, start_port)
            else:
                remote_socket_factory.interfaces.socket.sockets[socket_no].send_data_udp(udp_buffer, dut_ip,
                                                                                         port=start_port + socket_no)

    @staticmethod
    def send_data_tcp(remote_socket, tx_buffer, pkt_count=1, sock_id=None, use_server_socket=True, wait_time=0):
        if wait_time > 0:
            logger().info(f"Waiting for '{wait_time}' seconds before sending data")
            time.sleep(wait_time)
            logger().info(f"Sending data from remote peer, data --> {tx_buffer}")
        for _ in range(pkt_count):
            if sock_id is None:
                remote_socket.interfaces.socket.send_data_tcp(tx_buffer, use_server_socket)
            elif isinstance(sock_id, (list, tuple)):
                for sock in sock_id:
                    remote_socket.interfaces.socket.sockets[sock].send_data_tcp(tx_buffer, use_server_socket)
            else:
                remote_socket.interfaces.socket.sockets[sock_id].send_data_tcp(tx_buffer, use_server_socket)

    @staticmethod
    def send_and_receive(tcp_socks, client_socket, wifi_dut, logger):
        sw = Stopwatch()
        while sw.elapsed_sec <= 30:
            count = 0
            for sock_no in tcp_socks:
                tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
                logger.info(f"Remote peer is sending data over socket {sock_no + 1} and data:{tx_buffer}")
                client_socket[count].send_data_tcp(tx_buffer)
                count += 1
                time.sleep(1)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_no + 1, timeout=30)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock_no} opened in the DUT is not matched"
                logger.info("Data sent by remote peer and received on DUT is matching")

    @staticmethod
    def bsd_socket_select(wifi_dut, totalfds, logger):
        sw = Stopwatch()
        while sw.elapsed_sec <= 30:
            time.sleep(5)
            status, data = wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=totalfds, time=10)
            if not "Timeout" in str(data):
                data = int(re.findall(r'((?<=total sockets:) \d+)', str(data))[0])
                assert data <= totalfds, f"Total sockets opened in the DUT is not matched with the expected value"
                logger.info(f"Total sockets opened in the DUT is matched with the expected value")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(2),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "server_socket_limit": 4,
        "client_socket_limit": 4,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("repeat_count", [10])
@pytest.mark.legacy_deployed
@pytest.mark.WLAN_Dev_sanity_917
def test_wifi_sdk_socket_select_tcp_TC19325(wifi_sniffer, wifi_dut, wifi_access_point, remote_socket, logger,
                                            repeat_count, sl_collections):
    """
    Verify Data receive functionality after checking the availability of the data on the socket ID using select function over TCP client
    """
    try:
        capture_filename = "test_wifi_sdk_socket_select_tcp_TC19325"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap")
        port = 5001
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        remote_socket.interfaces.socket.start_server(port=port)
        server_ipp = remote_socket.interfaces.socket.hostname_or_ip_address(ip_version=4)
        # # DUT opens tcp client socket
        sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, ip_len=4, server_port=port, asynch=1)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ipp, ip_len=4, server_port=port)
        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=1, time=10)
        for i in range(repeat_count):
            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            buffer_length = len(tx_buffer)
            remote_socket.interfaces.socket.send_data_tcp(tx_buffer, True)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=30)
            assert buffer_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
    finally:
        wifi_sniffer.interfaces.capture.stop_capture()
        remote_socket.interfaces.socket.stop()
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(2),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_socket_select_udp_c19328(wifi_sniffer, wifi_dut, wifi_access_point, remote_socket, logger,
                                           sl_collections, sniffer_filter):
    """
    Verify Data receive functionality after checking the availability of the data on the socket ID using select function over UDP client
    """
    try:
        sock_obj = SocketDataTransfer()
        capture_filename = "test_wifi_sdk_socket_select_udp_c19328"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        port = 5001
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        remote_socket.interfaces.socket.start_server(socket_type=1)

        sock = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, ip_len=4, server_port=port)
        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=1, time=10)
        time.sleep(3)
        sw = Stopwatch()
        while sw.elapsed_sec <= 30:
            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=90))
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            trf_thread = Thread(target=sock_obj.send_data, args=(None, sock, tx_buffer, device_ip, port, 2,
                                                                 remote_socket))
            trf_thread.start()
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=60)
            assert len(tx_buffer) == len(buffer_rx), (f"buffer length sent by remote peer and received on the socket "
                                                      f"id {sock} opened in the DUT is not matched ")
            trf_thread.join()
            logger.info("Data sent by remote peer and received in DUT is matching")
            time.sleep(0.5)

        logger.info(f"Closing socket_id->{sock}")
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        remote_socket.interfaces.socket.stop()

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(2),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "server_socket_limit": 4,
        "client_socket_limit": 4,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("repeat_count", [10])
@pytest.mark.legacy_deployed
def test_wifi_sdk_socket_select_dut_tcp_server_TC19326(
        wifi_sniffer, wifi_dut, wifi_access_point, remote_socket_factory, logger, repeat_count, sl_collections
):
    """
    Verify Data receive functionality after checking the availability of the data on the socket ID using select function over TCP server
    """
    try:
        capture_filename = "test_wifi_sdk_socket_select_dut_tcp_server_TC19326"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap")
        port = 5001
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=port, timeout=15, asynch=1)
        wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)
        result = ThreadBase.call_functions_simultaneously(
            [
                (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1),
                (
                    client_socket.connect_client_tcp,
                    device_ip,
                    port,
                ),
            ],
            timeout=10,
        )

        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=1, time=10)
        for packets in range(repeat_count):
            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            buffer_length = len(tx_buffer)
            client_socket.send_data_tcp(tx_buffer)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            time.sleep(2)
            rx_buffer = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=1, timeout=30)
            assert buffer_length == len(
                rx_buffer), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
    finally:
        wifi_sniffer.interfaces.capture.stop_capture()
        remote_socket_factory.interfaces.socket.close_all()
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(2),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_socket_select_tcp_server_multiple_sockets_c19327(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                   remote_socket_factory, logger, sl_collections,
                                                                   sniffer_filter):
    """
    Verify Data receive functionality after checking the availability of the data on the socket ID using select function over UDP client
    """
    try:
        capture_filename = "test_wifi_sdk_socket_select_tcp_server_multiple_sockets_c19327"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        start_port = 5001
        client_socket = []
        tcp_socks = []
        for count in range(4):
            server_port = start_port + count
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port, timeout=15,
                                          asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)
            time.sleep(3)
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            ThreadBase.call_functions_simultaneously(
                [(client_socket[count].connect_client_tcp, device_ip, server_port),
                 (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1)], timeout=10)

        time.sleep(3)
        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=4, time=10)
        sw = Stopwatch()
        while sw.elapsed_sec <= 30:
            count = 0
            for sock_no in tcp_socks:
                tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger.info(f"Remote peer is sending data over socket {sock_no + 1} and data:{tx_buffer}")
                client_socket[count].send_data_tcp(tx_buffer)
                count += 1
                time.sleep(1)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_no + 1, timeout=30)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock_no} opened in the DUT is not matched"
                logger.info("Data sent by remote peer and received on DUT is matching")

        for sock_id in tcp_socks:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(2),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_socket_select_tcp_c19331(switch, wifi_sniffer, wifi_dut, wifi_access_point, remote_socket, logger,
                                           sl_collections, sniffer_filter):
    """
    Verify Data receive functionality after checking the availability of the data
    on the socket ID using select function over TCP client after connecting to AP second time,
    the first time connection loss is due to rejoin failure
    """
    try:
        capture_filename = "test_wifi_sdk_socket_select_tcp_c19331"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        for count in range(2):
            count += 1
            logger.info(f"Initiating test for iteration:'{count}'")
            ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
            device_ip, dut_mac_address = ssl_obj.join_get_ip(sniff_capture=False)
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger.info(f'AP BSSID = {ap_bssid}')

            socket_obj = SocketDataTransfer()
            trf_thread = Thread(target=socket_obj.open_socket_and_data_transfer,
                                args=(wifi_dut, remote_socket, device_ip), kwargs={'numberOfFds': 1,
                                                                                   'close_socket': False})
            trf_thread.start()
            time.sleep(25)
            if count == 1:
                logger.info("\n\nTurning off the AP")
                switch.interfaces.pdu_switch.turn_off(delay=15)
                logger.info("Successfully powered off AP")

                # logger.info("\n\nDisabling Wireless in AP")
                # wifi_access_point.interfaces.wifi.stop_ap()
                # time.sleep(5)
                # logger.info("Disabled Wireless in AP")

                logger.info("Checking for rejoin fail event from dut, this may take some time....")
                sw = Stopwatch()
                rejoin_msg = 0
                since_time = time.perf_counter_ns()
                while sw.elapsed_sec <= 500:
                    events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
                    for event in events:
                        if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT:
                            rejoin_msg = 1
                    if rejoin_msg:
                        break
                assert rejoin_msg == 1, f"Rejoin Error not found from DUT even after AP is switched off for 500 seconds"
                logger.info("Rejoin Error Received from DUT")

                logger.info("\n\nAgain turning on the AP")
                switch.interfaces.pdu_switch.turn_on(delay=100)
                logger.info("Successfully powered on AP")

                # logger.info("\n\nEnabling Wireless in AP")
                # wifi_access_point.interfaces.wifi.start_ap()
                # time.sleep(60)
                # logger.info("Enabled Wireless in AP")
            trf_thread.join()
            logger.info(f"Iteration '{count}' completed\n\n")
            logger.info(f"Closing socket_id->{socket_obj.sock}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_obj.sock)

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(2),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_socket_select_after_remote_socket_close_c19333(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                 sniffer_filter, remote_socket_factory, logger,
                                                                 sl_collections):
    """
    Execute rsi_select() api on the socket ID when the socket is opened second time. The first opened socket is closed
    due to remote terminate or closed intentionally by DUT
    """
    try:
        capture_filename = "test_wifi_sdk_socket_select_after_remote_socket_close_c19333"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        server_port = 5001
        for count in range(2):
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port, timeout=15,
                                          asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=0, asynch=1)
            time.sleep(3)
            client_socket = remote_socket_factory.interfaces.socket.create_socket()
            ThreadBase.call_functions_simultaneously(
                [(wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1),
                 (client_socket.connect_client_tcp, device_ip, server_port)], timeout=30)

            time.sleep(3)
            wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=1, time=10)
            sw = Stopwatch()
            while sw.elapsed_sec <= 30:
                tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger.info(f"Remote peer is sending data over socket {sock + 1} and data:{tx_buffer}")
                client_socket.send_data_tcp(tx_buffer)
                time.sleep(1)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(sock + 1, timeout=30)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock + 1} opened in the DUT is not matched"
                logger.info("Data sent by remote peer and received on DUT is matching")
            if count == 0:
                logger.info("\n\nClosing remote socket from remote peer as per the test step")
                remote_socket_factory.interfaces.socket.close_all()
                remote_socket_factory.interfaces.socket.sockets = []
                logger.info("Successfully closed remote socket at remote side")
                wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
                logger.info("\n\nRe-Opening remote socket and connecting again")

        logger.info(f"Closing socket_id->{sock}")
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(2),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_socket_select_tcp_close_stress_c19334(wifi_sniffer, wifi_dut, wifi_access_point, sl_collections,
                                                        remote_socket_factory, logger, sniffer_filter,
                                                        utf_constants):
    """
    Open tcp client socket, receive data over the socket after checking the availability of the data on the socket ID
    using select function at every one second  and close the socket.
    """
    try:
        sock_opened = []
        capture_filename = "test_wifi_sdk_socket_select_tcp_close_stress_c19334"
        test_run_time = utf_constants.get('time_duration')
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections,
                                 listen_interval=700)
        device_ip, dut_mac_address = ssl_obj.join_get_ip()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        err_count = []
        expected_err_count = 0
        iter_count = 0
        sw = Stopwatch()
        while sw.elapsed_sec < test_run_time:
            iter_count += 1
            time_left = int((test_run_time - sw.elapsed_sec) / 60)
            logger.info(f"Remaining time to complete test is '{time_left}' minutes and iteration is:{iter_count}")
            try:
                start_port = 5001
                for sock_count in range(4):
                    socket_port = start_port + sock_count
                    sock = wifi_dut.interfaces.wifi.Asyncsocket()
                    assert sock == sock_count, f"Sock ID must be {sock_count} but received {sock}"
                    sock_opened.append(sock)
                    server_socket = remote_socket_factory.interfaces.socket.create_socket()
                    server_socket.time_limit = 3600
                    server_socket.start_server(port=socket_port, socket_type=SOCKET_TYPE_TCP)
                    server_ip = server_socket.hostname_or_ip_address(ip_version=4)
                    wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=socket_port,
                                                  timeout=15)
                    wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                              server_port=socket_port)
                    time.sleep(2)

                wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=4, time=30)
                for sock_id in range(4):
                    tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
                    logger.info(f"Remote peer sending data over socket {sock_id} and data:{tx_buffer}")
                    remote_socket_factory.interfaces.socket.sockets[sock_id].send_data_tcp(tx_buffer, True)
                    time.sleep(1)
                    wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                    buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_id, timeout=30)
                    assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                                   f"{sock_id} opened in the DUT is not matched"
                    logger.info("Data sent by remote peer and received on DUT is matching")

                for sock_id in sock_opened:
                    logger.info(f"Closing socket_id->{sock_id}")
                    wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
                sock_opened.clear()
                remote_socket_factory.interfaces.socket.close_all()
                remote_socket_factory.interfaces.socket.sockets = []
            except Exception as error:
                logger.warning(f"Observed error in iteration '{iter_count}': {error} ")
                err_count.append(iter_count)
                for sock_id in sock_opened:
                    logger.info(f"Closing socket_id->{sock_id}")
                    wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
                sock_opened.clear()
                remote_socket_factory.interfaces.socket.close_all()
                remote_socket_factory.interfaces.socket.sockets = []

        for count in err_count:
            logger.info(f"Errors occurred in iteration:{count}")
        assert len(err_count) <= expected_err_count, f"Number of times failures occurred is '{len(err_count)}'," \
                                                     f"which is greater than expected error count '{expected_err_count}'"
        logger.info(f"**************** Number of times failures observed during span of {test_run_time / 60} minutes "
                    f"of test run is '{len(err_count)}', Which is less than expected failure count '{expected_err_count}'. "
                    f"Hence marking the testcase as PASS ****************\n")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            4),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_socket_select_multiple_sockets_tcp_udp_c19329(wifi_sniffer, wifi_dut, wifi_access_point, logger,
                                                                remote_socket_factory, sl_collections, sniffer_filter):
    """
    Verify Data receive functionality after checking the availability of the data on the socket ID
    using select function over 2 udp sockets and 2 tcp sockets
    """
    tcp_socks = []
    udp_socks = []
    try:
        sock_obj = SocketDataTransfer()
        capture_filename = "test_wifi_sdk_socket_select_multiple_sockets_tcp_udp_c19329"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        start_port = 5001
        client_socket = []

        for count in range(4):
            server_port = start_port + count
            if count in range(2):
                server_socket = remote_socket_factory.interfaces.socket.create_socket()
                server_socket.start_server(port=server_port, socket_type=SOCKET_TYPE_UDP)

                sock = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
                udp_socks.append(sock)
                wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port, timeout=15)
            else:
                sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
                tcp_socks.append(sock)
                wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port, timeout=15)
                wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)
                client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
                ThreadBase.call_functions_simultaneously(
                    [(client_socket[count - 2].connect_client_tcp, device_ip, server_port),
                     (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1)], timeout=10)

        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=4, time=10)
        wifi_dut.interfaces.wifi.bsdAsyncEvent(time=40)
        time.sleep(3)

        sw = Stopwatch()
        while sw.elapsed_sec <= 40:
            count = 0
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            for socket_no in range(2):
                udp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=90))
                logger.info(f"UDP --> Remote peer is sending data over socket {socket_no}")
                trf_thread = Thread(target=sock_obj.send_data, args=(remote_socket_factory, socket_no, udp_buffer,
                                                                     device_ip, start_port, 3))
                trf_thread.start()
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=40)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket_no, timeout=60)
                assert len(udp_buffer) == len(buffer_rx), (f"buffer length sent by remote peer and received on the"
                                                           f" socket id {socket_no} opened in the DUT is not matched")
                logger.info("UDP --> Data sent by remote peer and received on DUT is matching")
                trf_thread.join()
            for socket_no in tcp_socks:
                tcp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=90))
                logger.info(f"TCP --> Remote peer is sending data over socket {socket_no + 1}")
                client_socket[count].send_data_tcp(tcp_buffer)
                count += 1
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=40)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_no + 1, timeout=60)
                assert tcp_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                                f"{socket_no + 1} opened in the DUT is not matched"
                logger.info("TCP --> Data sent by remote peer and received on DUT is matching")
            time.sleep(1)
            logger.info("\n\n")
        for sock_id in udp_socks:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        udp_socks.clear()
        for sock_id in tcp_socks:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        tcp_socks.clear()
        remote_socket_factory.interfaces.socket.close_all()

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        for sock_id in udp_socks:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        udp_socks.clear()
        for sock_id in tcp_socks:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        tcp_socks.clear()
        remote_socket_factory.interfaces.socket.close_all()
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(2),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_verify_data_rx_func_of_multiple_tcp_socks_after_rejoin_c19330(switch, wifi_sniffer, wifi_dut, logger,
                                                                                sl_collections, remote_socket_factory,
                                                                                wifi_access_point, sniffer_filter):
    """
    Verify Data receive functionality after checking the availability of the data on the socket ID
    using select function over TCP client after successful rejoin.
    """
    try:
        capture_filename = "test_wifi_sdk_verify_data_rx_func_of_multiple_tcp_socks_after_rejoin_c19330"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        start_port = 5001
        for count in range(4):
            server_port = start_port + count
            sock = wifi_dut.interfaces.wifi.Asyncsocket()
            assert sock == count, f"socket id received is wrong, expected is {count}"
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.time_limit = 3600
            server_socket.start_server(port=server_port, socket_type=SOCKET_TYPE_TCP)
            server_ip = server_socket.hostname_or_ip_address(ip_version=4)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port,
                                          timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                      server_port=server_port)
            time.sleep(3)

        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=4, time=30)
        ap_power_off = False
        sw = Stopwatch()
        while sw.elapsed_sec <= 200:
            for sock_id in range(4):
                tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger.info(f"Remote peer sending data over socket {sock_id} and data:{tx_buffer}")
                remote_socket_factory.interfaces.socket.sockets[sock_id].send_data_tcp(tx_buffer, True)
                time.sleep(1)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_id, timeout=30)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock_id} opened in the DUT is not matched"
                logger.info("Data sent by remote peer and received on DUT is matching")
                if int(sw.elapsed_sec) in range(30, 40):
                    ap_power_off = True

            if ap_power_off:
                logger.info("Turning off the AP")
                switch.interfaces.pdu_switch.turn_off(delay=5)
                # wifi_access_point.interfaces.wifi.stop_ap()
                # time.sleep(5)
                logger.info("Successfully powered off AP")

                logger.info("Again turning on the AP")
                switch.interfaces.pdu_switch.turn_on(delay=80)
                # wifi_access_point.interfaces.wifi.start_ap()
                # time.sleep(80)
                ap_power_off = 0
                logger.info("Successfully powered on AP")
                logger.info("Pinging to DUT to check rejoin process is completed or not")
                status = sl_collections.ping(device_ip, 30, 5)
                assert status, "Pinging to DUT is failed, DUT not rejoined to AP"

        for sock_id in range(4):
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(2),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_socket_select_udp_bidirectional_c19338(wifi_sniffer, wifi_dut, wifi_access_point, sniffer_filter,
                                                         remote_socket_factory, logger, sl_collections):
    """
    Verify send and receive data over socket ID(UDP)parallel when the socket id is added in the socket_select() api
    """
    socks_opened = []
    try:
        sock_obj = SocketDataTransfer()
        capture_filename = "test_socket_select_udp_bidirectional_TC19338"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        start_port = 5001
        for count in range(4):
            server_port = start_port + count
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.start_server(port=server_port, socket_type=SOCKET_TYPE_UDP)
            sock = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
            socks_opened.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port, timeout=15,
                                          asynch=1)

        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=4, time=10)
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            for socket_no in range(0, 4):
                server_ip = remote_socket_factory.interfaces.socket.sockets[socket_no].hostname_or_ip_address(
                    ip_version=4)
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger.info(f"DUT is sending data over socket {socket_no}")
                wifi_dut.interfaces.wifi.bsdSocketSendTo(socket_fd=socket_no, data=data, ip_addr=server_ip,
                                                         ip_len=4, port=start_port + socket_no)

                time.sleep(1)
                rx_data, address = remote_socket_factory.interfaces.socket.sockets[socket_no].recv_data_udp(len(data))
                logger.info(f"Remote peer received data ->  {rx_data} from address {address}")
                assert data == rx_data, "Data sent by DUT and received on server is not matching"
                logger.info("Data sent by DUT and received on remote peer is matching")

                tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger.info(f"Remote peer is sending data over socket {socket_no}")
                wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                trf_thread = Thread(target=sock_obj.send_data,
                                    args=(remote_socket_factory, socket_no, tx_buffer, device_ip, start_port, 3))
                trf_thread.start()
                time.sleep(1)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket_no, timeout=80)
                assert len(tx_buffer) == len(buffer_rx), (f"buffer length sent by remote peer and received on the"
                                                          f" socket id {socket_no} opened in the DUT is not matched")
                trf_thread.join()
                logger.info("Data sent by remote peer and received on DUT is matching\n\n")
        for sock_id in socks_opened:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        socks_opened.clear()
        remote_socket_factory.interfaces.socket.close_all()

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        for sock_id in socks_opened:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        socks_opened.clear()
        remote_socket_factory.interfaces.socket.close_all()
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3) |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_sync_socket_select_with_timeout_null_c19335(wifi_sniffer, wifi_access_point, wifi_dut, remote_socket,
                                                              logger, sl_collections, sniffer_filter):
    """
    Execute synchronous rsi_select() api when timeout argument given is NULL.
    """
    try:
        capture_filename = 'test_wifi_sdk_sync_select_c19335'

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        server_port = random.randint(5001, 5020)
        local_port = random.randint(40001, 60000)
        remote_socket.interfaces.socket.time_limit = 3600
        remote_socket.interfaces.socket.start_server(port=server_port)
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address(ip_version=4)
        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
        time.sleep(3)

        buffer_length = 100
        sock_obj = SocketDataTransfer()
        sw = Stopwatch()
        time_interval = 300
        while sw.elapsed_sec <= 30:
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
            trf_thread = Thread(target=sock_obj.send_data_tcp, args=(remote_socket, tx_buffer, 1),
                                kwargs={'wait_time': time_interval})
            trf_thread.start()
            wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=1, time='NULL', timeout=time_interval + 10,
                                                     async_timeout=time_interval + 10)
            trf_thread.join()
            count = 0
            for pkt_count in range(5):
                tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
                logger.info(f"Sending data from remote peer, data --> {tx_buffer}")
                sock_obj.send_data_tcp(remote_socket, tx_buffer, count)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=120,
                                                                          async_timeout=120)
                assert len(tx_buffer) == len(
                    buffer_rx), f"buffer length sent by remote peer and received on the socket " \
                                f"id {sock} opened in the DUT is not matched"
                logger.info("Data sent by remote peer and received at DUT is matching")
                count = 1

        logger.info(f"Closing socket_id->{sock}")
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        remote_socket.interfaces.socket.stop()
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            5),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_sync_socket_select_with_time_interval_1_30_60_sec_c19336_case1(wifi_sniffer, remote_socket_factory,
                                                                                 wifi_dut, logger, sl_collections,
                                                                                 wifi_access_point, sniffer_filter):
    """
    Execute synchronous rsi_select() api with different timeout values(1 sec, 30 sec, 60 sec).
    """
    socks_opened = list()
    try:
        sock_obj = SocketDataTransfer()
        capture_filename = f'test_wifi_sdk_sync_select_c19336_case1'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        start_port = 5001
        for count in range(4):
            server_port = start_port + count
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == count, f"socket id received is wrong, expected is {count}"
            socks_opened.append(sock)
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.start_server(port=server_port, socket_type=SOCKET_TYPE_TCP)
            server_ip = server_socket.hostname_or_ip_address(ip_version=4)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port,
                                          timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
            time.sleep(3)

        for time_interval in [1, 30, 60]:
            logger.info("\n\n")
            logger.info(f"************* Socket select time interval: '{time_interval}' Seconds *************")
            logger.info(f"Waiting till timeout '{time_interval}' seconds reached")
            wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=4, time=time_interval, timeout=time_interval + 10,
                                                     async_timeout=time_interval + 10)
            logger.info(f"Timeout '{time_interval}' seconds elapsed")
            time.sleep(5)
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=90))
            logger.info(f"Sending data from remote peer, data --> {tx_buffer}")
            count = 2 if time_interval == 60 else 1
            trf_thread = Thread(target=sock_obj.send_data_tcp,
                                args=(remote_socket_factory, tx_buffer, count, socks_opened))
            trf_thread.start()
            trf_thread.join()
            time.sleep(3)
            wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=4, time=time_interval, timeout=time_interval + 10,
                                                     async_timeout=time_interval + 10)
            time.sleep(3)
            for sock_id in range(4):
                wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_id, timeout=120, async_timeout=120)
                time.sleep(1)
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        for sock_id in socks_opened:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            5),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_sync_socket_select_with_time_interval_300_sec_c19336_case2(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                             remote_socket_factory, logger,
                                                                             sl_collections,
                                                                             sniffer_filter):
    """
    Execute synchronous rsi_select() api with different timeout value 300 seconds.
    """
    socks_opened = list()
    try:
        sock_obj = SocketDataTransfer()
        capture_filename = f'test_wifi_sdk_sync_select_c19336_case2'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        start_port = 5001
        for count in range(4):
            server_port = start_port + count
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == count, f"socket id received is wrong, expected is {count}"
            socks_opened.append(sock)
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.time_limit = 3600
            server_socket.start_server(port=server_port, socket_type=SOCKET_TYPE_TCP)
            server_ip = server_socket.hostname_or_ip_address(ip_version=4)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port,
                                          timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
            time.sleep(3)

        time_interval = 300
        logger.info("\n\n")
        logger.info(f"************* Socket select time interval: '{time_interval}' Seconds *************")
        logger.info(f"Waiting till timeout '{time_interval}' seconds reached")
        wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=4, time=time_interval, timeout=time_interval + 10,
                                                 async_timeout=time_interval + 10)
        logger.info(f"Timeout '{time_interval}' seconds elapsed")
        time.sleep(5)
        tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=90))
        logger.info(f"Sending data from remote peer, data --> {tx_buffer}")
        trf_thread = Thread(target=sock_obj.send_data_tcp,
                            args=(remote_socket_factory, tx_buffer, 5, socks_opened))
        trf_thread.start()
        time.sleep(3)
        wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=4, time=60, timeout=60, async_timeout=60)
        trf_thread.join()
        for sock_id in range(4):
            wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_id, timeout=120, async_timeout=120)
            time.sleep(1)
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        for sock_id in socks_opened:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            5),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_sync_socket_select_with_time_interval_900_sec_c19336_case3(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                             remote_socket_factory, logger,
                                                                             sl_collections,
                                                                             sniffer_filter):
    """
    Execute synchronous rsi_select() api with different timeout value 300 seconds.
    """
    socks_opened = list()
    try:
        sock_obj = SocketDataTransfer()
        capture_filename = f'test_wifi_sdk_sync_select_c19336_case3'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        start_port = 5001
        for count in range(4):
            server_port = start_port + count
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == count, f"socket id received is wrong, expected is {count}"
            socks_opened.append(sock)
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.time_limit = 3600
            server_socket.start_server(port=server_port, socket_type=SOCKET_TYPE_TCP)
            server_ip = server_socket.hostname_or_ip_address(ip_version=4)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port,
                                          timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
            time.sleep(3)

        time_interval = 900
        logger.info("\n\n")
        logger.info(f"************* Socket select time interval: '{time_interval}' Seconds *************")
        logger.info(f"Waiting till timeout '{time_interval}' seconds reached")
        wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=4, time=time_interval, timeout=time_interval + 10,
                                                 async_timeout=time_interval + 10)
        logger.info(f"Timeout '{time_interval}' seconds elapsed")
        time.sleep(5)
        tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=90))
        logger.info(f"Sending data from remote peer, data --> {tx_buffer}")
        trf_thread = Thread(target=sock_obj.send_data_tcp,
                            args=(remote_socket_factory, tx_buffer, 5, socks_opened))
        trf_thread.start()
        time.sleep(3)
        wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=4, time=60, timeout=60, async_timeout=60)
        trf_thread.join()
        for sock_id in range(4):
            wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_id, timeout=120, async_timeout=120)
            time.sleep(1)
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        for sock_id in socks_opened:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            4),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_socket_select_tcp_bidirectional_c19337(wifi_sniffer, wifi_dut, wifi_access_point, sniffer_filter,
                                                         remote_socket_factory, logger, sl_collections):
    """
    Verify send and receive data over socket ID(tcp)parallel when the socket id is added in the socket_select() api
    """
    try:
        capture_filename = "test_wifi_sdk_socket_select_tcp_bidirectional_c19337"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        start_port = 5001
        client_socket = []
        tcp_socks = []
        for count in range(4):
            server_port = start_port + count
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port, timeout=15,
                                          asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=0, asynch=1)
            time.sleep(3)
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            ThreadBase.call_functions_simultaneously(
                [(client_socket[count].connect_client_tcp, device_ip, server_port),
                 (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1)], timeout=10)
        time.sleep(3)

        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=4, time=30)
        sw = Stopwatch()
        while sw.elapsed_sec <= 60:
            count = 0
            for sock_no in tcp_socks:
                wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger.info(f"DUT is sending data over TCP socket_no {sock_no + 1} and data --> {data_sent}")
                trf_thread = Thread(target=wifi_dut.interfaces.wifi.bsdSocketSend, args=(sock_no + 1, data_sent))
                trf_thread.start()
                logger.info(f"Remote peer is sending data over socket {sock_no + 1} and data --> {tx_buffer}")
                client_socket[count].connected_tcp_socket = client_socket[count]
                client_socket[count].send_data_tcp(tx_buffer)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=30)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_no + 1, timeout=30)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock_no} opened in the DUT is not matched"
                logger.info(f"Data received at DUT --> {buffer_rx}")
                logger.info("Data sent by remote peer and received on DUT is matching")

                data_received = client_socket[count].recv_data_tcp(len(data_sent), True)
                assert data_received == data_sent, "Data sent by DUT and received on remote peer is not matching"
                logger.info(f"Data received at remote peer --> {data_received}")
                logger.info("Data sent by DUT and received on remote peer is matching")
                trf_thread.join()
                count += 1

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        for sock_id in tcp_socks:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        tcp_socks.clear()
    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            4),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("test_run_time", [900])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_tcp_rx_without_socket_select_for_first_time_c19339(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                     remote_socket_factory, sniffer_filter,
                                                                     logger, test_run_time, sl_collections):
    """
    Receive data over tcp socket for 15 minutes continuously every second when the socket ID is not added in the
    select() api. Then add the socket id in the rsi_select() api.
    """
    try:
        capture_filename = "test_wifi_sdk_tcp_rx_without_socket_select_for_first_time_c19339"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        start_port = 5001
        client_socket = []
        tcp_socks = []
        for count in range(4):
            server_port = start_port + count
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port, timeout=15,
                                          asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=0, asynch=1)
            time.sleep(3)
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            ThreadBase.call_functions_simultaneously(
                [(client_socket[count].connect_client_tcp, device_ip, server_port),
                 (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1)], timeout=10)
        time.sleep(3)
        logger.info("\n\n")
        sock_obj = SocketDataTransfer()
        sw = Stopwatch()
        logger.info("********* Receiving data without adding socket id using socket select command *********")
        while sw.elapsed_sec < int(test_run_time / 2):
            count = 0
            for sock_no in tcp_socks:
                wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger.info(f"Remote peer is sending data over socket {sock_no + 1} and data --> {tx_buffer}")
                trf_thread = Thread(target=sock_obj.send_data_tcp,
                                    args=(remote_socket_factory, tx_buffer, 1, count, False))
                trf_thread.start()
                time.sleep(1)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_no + 1, timeout=30)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock_no} opened in the DUT is not matched"
                logger.info(f"Data received at DUT --> {buffer_rx}")
                logger.info("Data sent by remote peer and received on DUT is matching")
                count += 1
                trf_thread.join()
        logger.info("\n\n")
        sw = Stopwatch()
        logger.info("************ Receiving data by adding socket id using socket select command ************")
        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=4, time=30)
        while sw.elapsed_sec < int(test_run_time / 2):
            count = 0
            for sock_no in tcp_socks:
                wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger.info(f"Remote peer is sending data over socket {sock_no + 1} and data --> {tx_buffer}")
                trf_thread = Thread(target=sock_obj.send_data_tcp,
                                    args=(remote_socket_factory, tx_buffer, 1, count, False))
                trf_thread.start()
                time.sleep(1)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=30)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_no + 1, timeout=30)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock_no} opened in the DUT is not matched"
                logger.info(f"Data received at DUT --> {buffer_rx}")
                logger.info("Data sent by remote peer and received on DUT is matching")
                count += 1
                trf_thread.join()

        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        for sock_id in tcp_socks:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        tcp_socks.clear()
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(2),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable"])
@pytest.mark.legacy_deployed
def test_socket_select_neg_TCC19332(wifi_sniffer, wifi_dut, wifi_access_point, remote_socket, logger, sl_collections):
    """
    Execute select() api when no socket is opened in the DUT
    pass if the expected error(0x0009) code is received
    """
    try:
        capture_filename = "test_socket_select_neg_TCC19332"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        data = wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=1, time=60, expected_status=SLStatus.SL_STATUS_FAIL)
        logger.info(f"Received data from DUT {data}")
        if "errno: 9" in data.decode():
            logger.info("Expected error code received")
        else:
            assert False, "Expected error code not received"
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(2),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "server_socket_limit": 4,
        "client_socket_limit": 4,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("repeat_count", [1])
@pytest.mark.legacy_deployed
def test_wifi_sdk_socket_select_dut_tcp_server_timeout0_TC538014(
        wifi_sniffer, wifi_dut, wifi_access_point, remote_socket_factory, logger, repeat_count, sl_collections
):
    """
    Verify socket select with timeout value 0.
    """
    try:
        capture_filename = "test_wifi_sdk_socket_select_dut_tcp_server_timeout0_TC538014_1"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap")
        port = 5001
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=port, timeout=15, asynch=0)
        wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=0)
        result = ThreadBase.call_functions_simultaneously(
            [
                (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 0),
                (
                    client_socket.connect_client_tcp,
                    device_ip,
                    port,
                ),
            ],
            timeout=10,
        )
        start = time.process_time()
        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=1, time=0)
        end = time.process_time()
        assert end - start < 1, f"Select function is not returning immediately"
        for packets in range(repeat_count):
            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            buffer_length = len(tx_buffer)
            client_socket.send_data_tcp(tx_buffer)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            time.sleep(2)
            rx_buffer = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=1, timeout=30)
            assert buffer_length == len(
                rx_buffer), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
    finally:
        wifi_sniffer.interfaces.capture.stop_capture()
        remote_socket_factory.interfaces.socket.close_all()
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("repeat_count", [1])
@pytest.mark.legacy_deployed
def test_wifi_sdk_4tcp_client_socket_select_TC538008(wifi_sniffer, wifi_dut, wifi_access_point, remote_socket, logger,
                                            repeat_count, sl_collections, sniffer_filter):
    """
    Verify Data receive functionality after checking the availability of the data on the socket ID using select function over 4 TCP client sockets
    """
    try:
        sock_opened = []
        capture_filename = "test_wifi_sdk_4tcp_client_socket_select_TC538008"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        start_port = 5001
        for sock_count in range(4):
            socket_port = start_port + sock_count
            remote_socket.interfaces.socket.start_server(port=socket_port)
            server_ipp = remote_socket.interfaces.socket.hostname_or_ip_address(ip_version=4)
            # # DUT opens tcp client socket
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
            assert sock == sock_count, f"Sock ID must be {sock_count} but received {sock}"
            sock_opened.append(sock)
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, ip_len=4, server_port=socket_port, asynch=1)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ipp, ip_len=4, server_port=socket_port)
        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=4, time=30)
        for sock_id in range(4):
            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
            buffer_length = len(tx_buffer)
            remote_socket.interfaces.socket.send_data_tcp(tx_buffer, True)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=45)
            assert buffer_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "

        for sock_id in sock_opened:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        sock_opened.clear()

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
    finally:
        wifi_sniffer.interfaces.capture.stop_capture()
        remote_socket.interfaces.socket.stop()
        for sock_id in sock_opened:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        sock_opened.clear()
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(10),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset','init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_socket_select_tcp_10server_sockets_c538019(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                   remote_socket_factory, logger, sl_collections,
                                                                   sniffer_filter):
    """
    Verify socket select functionality with 10 TCP server sockets.
    """
    try:
        capture_filename = "test_wifi_sdk_socket_select_tcp_10server_sockets_c538019"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        start_port = 5001
        client_socket = []
        tcp_socks = []
        for count in range(10):
            server_port = start_port + count
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port, timeout=15,
                                          asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)
            time.sleep(3)
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            ThreadBase.call_functions_simultaneously(
                [(client_socket[count].connect_client_tcp, device_ip, server_port),
                 (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1)], timeout=10)

        time.sleep(3)
        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=10, time=10)
        sw = Stopwatch()
        while sw.elapsed_sec <= 30:
            count = 0
            for sock_no in tcp_socks:
                tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
                logger.info(f"Remote peer is sending data over socket {sock_no + 1} and data:{tx_buffer}")
                client_socket[count].send_data_tcp(tx_buffer)
                count += 1
                time.sleep(1)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_no + 1, timeout=30)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock_no} opened in the DUT is not matched"
                logger.info("Data sent by remote peer and received on DUT is matching")

        for sock_id in tcp_socks:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
    finally:
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(10),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset','init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_check_total_number_of_sockets_c667724(wifi_sniffer, wifi_dut, wifi_access_point,
                                                        remote_socket_factory, logger, sl_collections):
    """Verify sl_si91x_select returns total number of socket ID or not when sl_si91x_select API call synchronously"""
    try:
        totalfds = 4
        capture_filename = "c667724"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        start_port = 5001
        client_socket = []
        tcp_socks = []
        for count in range(totalfds):
            server_port = start_port + count
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port, timeout=15,
                                          asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)
            time.sleep(3)
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            ThreadBase.call_functions_simultaneously(
                [(client_socket[count].connect_client_tcp, device_ip, server_port),
                 (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1)], timeout=10)

        time.sleep(3)

        ThreadBase.call_functions_simultaneously(
            [(SocketDataTransfer.send_and_receive, tcp_socks, client_socket, wifi_dut, logger),
             (SocketDataTransfer.bsd_socket_select, wifi_dut, totalfds, logger)], timeout=15)

    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

    finally:
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(10),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ip_change_notification_c538012(wifi_sniffer, wifi_dut, wifi_access_point, remote_socket_factory,
                                                 logger, sl_collections, sniffer_filter, wifi_client, remote_socket):
    """Verify remote socket termination when socket select timeout configured to NULL"""
    try:
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.50", dhcp_end="192.168.50.100", dhcp_lease="240")
        time.sleep(60)
        capture_filename = "C538012"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap")
        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.init(mode="client")
        dut_addr = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point,
                                                       power_save=True,
                                                       associated=wifi_dut.interfaces.wifi.associated)

        device_ip, dut_mac_address = dut_addr['device_ip'], dut_addr['dut_mac_address']

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        local_port = 6001
        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        server_socket = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
        wifi_dut.interfaces.wifi.bind(socket_fd=server_socket, device_ip=device_ip, ip_len=4, server_port=local_port,
                                      asynch=1)
        wifi_dut.interfaces.wifi.listen(socket_fd=server_socket, backlog=1, asynch=1)

        ThreadBase.call_functions_simultaneously(
            [(client_socket.connect_client_tcp, device_ip, local_port),
             (wifi_dut.interfaces.wifi.bsdSocketAccept, server_socket, 1)], timeout=300)

        logger.info("Changing the DHCP pool in the AP")
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.20", dhcp_end="192.168.50.30", dhcp_lease="120")
        time.sleep(60)
        wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=1, time=100, timeout_disable=1, async_timeout=300, expected_status=SLStatus.SL_STATUS_TIMEOUT)

        ip_change_notification = None
        events = wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            logger.info(f"Event Type: {event.event_type}, Event Data: {event.event_data}")
            ip_change_notification = "10000004" if event.event_type =="10000004" else None
        assert ip_change_notification, "IP change notification is not received"
        logger.info(f"IP Change Notification: {ip_change_notification}")

    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

    finally:
        remote_socket.interfaces.socket.stop()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(10),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_rejoin_fail_notification_c538013(wifi_sniffer, wifi_dut, wifi_access_point, remote_socket_factory,
                                                 logger, sl_collections, sniffer_filter, switch, request):
    """
    Steps:
        1. Configure the Wi-Fi sniffer to capture packets on the same channel as the access point.
        2. Start packet capture using the Wi-Fi sniffer.
        3. Initialize the Wi-Fi DUT (Device Under Test) in client mode.
        4. Enable advanced client configuration on the DUT to allow rejoin attempts with specific parameters.
        5. Connect the DUT to the Wi-Fi network using the access point.
        6. Simulate conditions that cause the DUT to lose connection and attempt to rejoin.
        7. Verify that the DUT receives a rejoin failure notification.
        8. Validate the captured packets to ensure expected behavior.
        9. Handle any exceptions and clean up resources after the test.

        Parameters:
        - wifi_sniffer: Object to capture and analyze Wi-Fi packets.
        :param wifi_sniffer:
        :param wifi_dut:
        :param wifi_access_point:
        :param remote_socket_factory:
        :param logger:
        :param sl_collections:
        :param request:
        :param switch:
        :param remote_socket:
        :return:
    """
    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=request.node.name)
        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.init(mode="client")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=5, scan_interval=1,
                                                                      beacon_missed_count=40,
                                                                      first_time_retry_enable=1)
        dut_addr = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point,
                                                       power_save=True,
                                                       associated=wifi_dut.interfaces.wifi.associated)
        device_ip, dut_mac_address = dut_addr['device_ip'], dut_addr['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        local_port = 6001
        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        server_socket = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
        wifi_dut.interfaces.wifi.bind(socket_fd=server_socket, device_ip=device_ip, ip_len=4, server_port=local_port,
                                      asynch=1)
        wifi_dut.interfaces.wifi.listen(socket_fd=server_socket, backlog=1, asynch=1)

        ThreadBase.call_functions_simultaneously(
            [(client_socket.connect_client_tcp, device_ip, local_port),
             (wifi_dut.interfaces.wifi.bsdSocketAccept, server_socket, 1)], timeout=300)

        logger.info("\r\n Initiating Socket Select Functionality with timeout as NULL \r\n")
        wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=1, time=100, timeout_disable=1, async_timeout=300, expected_status=SLStatus.SL_STATUS_TIMEOUT)

        logger.info(f"Turning off the switch for 20 seconds to simulate disconnection...")
        switch.interfaces.pdu_switch.turn_off()
        time.sleep(20)
        rejoin_error_notification = False
        with TimeMeasurer() as t:
            logger.info("Waiting up to 180 seconds for rejoin error event...")
            sw = Stopwatch()
            while sw.elapsed_sec < 180:
                events = wifi_dut.interfaces.wifi.get_async_events()
                rejoin_error_events = [
                    event
                    for event in events
                    if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT
                ]
                if len(rejoin_error_events):
                    rejoin_error_notification = True
                    break
                time.sleep(0.1)
        assert rejoin_error_notification, "\n Rejoin error notification not received within the timeout period \n"
        logger.info(f"Received rejoin error event after {t.duration:.2f}s")

    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

    finally:
        switch.interfaces.pdu_switch.turn_on()
        remote_socket_factory.interfaces.socket.close_all()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
        | Si91xTCPIPFeatureBitMap.DNSClient
        | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(10),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["reset"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_verify_remote_socket_termination_c538011(
    wifi_sniffer,
    wifi_dut,
    wifi_access_point,
    remote_socket_factory,
    logger,
    sl_collections,
    remote_socket,
    request,
):
    """
    Test Case ID: C538011

    Objective:
    Verify the behavior of the DUT (Device Under Test) when a remote socket is terminated while the DUT is connected.

    Steps:
    1. Configure the Wi-Fi DUT to connect to the access point.
    2. Initialize the DUT in client mode and establish a connection to the AP.
    3. Create a remote socket and bind it to the DUT's IP address.
    4. Start listening on the remote socket for incoming connections.
    5. Simulate remote socket termination by closing the socket.
    6. Verify that the DUT handles the remote socket termination gracefully.
    7. Capture network traffic using the Wi-Fi sniffer for analysis.
    8. Validate that the DUT receives an IP change notification if applicable.
    9. Ensure proper cleanup of resources after the test.

    Parameters:
    - wifi_sniffer: The Wi-Fi sniffer used to capture network traffic.
    - wifi_dut: The Wi-Fi Device Under Test (DUT).
    - wifi_access_point: The Wi-Fi access point used for the test.
    - remote_socket_factory: Factory for creating and managing remote sockets.
    - logger: Logger instance for logging test details.
    - sl_collections: Collection of utility functions for Wi-Fi operations.
    - sniffer_filter: Filter configuration for the Wi-Fi sniffer.
    - wifi_client: The Wi-Fi client interface.
    - remote_socket: The remote socket interface.
    - request: Pytest request object for test metadata.

    Assertions:
    - Verify that the DUT detects the remote socket termination.
    - Ensure the DUT remains stable and operational after the remote socket is terminated.
    - Confirm that no unexpected errors or crashes occur during the test.
    """
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.init(mode="client")
        dut_addr = sl_collections.join_to_wifi_network(
            wifi_dut,
            wifi_access_point,
            power_save=True,
            associated=wifi_dut.interfaces.wifi.associated,
        )

        device_ip, dut_mac_address = dut_addr["device_ip"], dut_addr["dut_mac_address"]
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f"AP BSSID = {ap_bssid}")

        local_port = 6001
        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        server_socket = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
        wifi_dut.interfaces.wifi.bind(
            socket_fd=server_socket,
            device_ip=device_ip,
            ip_len=4,
            server_port=local_port,
            asynch=1,
        )
        wifi_dut.interfaces.wifi.listen(socket_fd=server_socket, backlog=1, asynch=1)

        ThreadBase.call_functions_simultaneously(
            [
                (client_socket.connect_client_tcp, device_ip, local_port),
                (wifi_dut.interfaces.wifi.bsdSocketAccept, server_socket, 1),
            ],
            timeout=300,
        )

        logger.info(f"\n Registering remote socket termination callback \n")
        wifi_dut.interfaces.wifi.set_remote_terminate_callback()

        ThreadBase.call_functions_simultaneously(
            [
                (wifi_dut.interfaces.wifi.bsdSocketSelect, 1, 100, 1, 300),
                (remote_socket_factory.interfaces.socket.close_all,),
            ]
        )
        event_data_output = ""
        time.sleep(5)
        events = wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.REMOTE_TERMINATE:
                event_data_output = event.event_data

        logger.info(
            f" ***************** EVENT DATA IS : {event_data_output} ********************** "
        )

        assert (
            "Remote Terminate" in event_data_output
        ), "expected error code not found. Expected is Remote Terminate"
        logger.info("*********** Remote Termination is Successful *************")

    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

    finally:
        remote_socket.interfaces.socket.stop()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
        | Si91xTCPIPFeatureBitMap.DNSClient
        | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(10)
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORD,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": [
            (
                "ca-chain.cert.pem",
                "SL_NET_SIGNING_CERTIFICATE",
                "SL_NET_TLS_SERVER_CREDENTIAL_START",
            )
        ],
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.deployed_25q4
def test_wifi_sdk_verify_socket_select_functionality_ssl_tx_rx_with_16k_length_c538018(
    wifi_sniffer,
    wifi_dut,
    wifi_access_point,
    logger,
    sl_collections,
    ssl_server,
    request,
):
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        dut_addr = sl_collections.join_to_wifi_network(
            wifi_dut,
            wifi_access_point,
            power_save=True,
            associated=wifi_dut.interfaces.wifi.associated,
        )

        device_ip, dut_mac_address = dut_addr["device_ip"], dut_addr["dut_mac_address"]
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f"AP BSSID = {ap_bssid}")

        ssl_server_port = ssl_server.interfaces.ssl.config["device_port1"]
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=ssl_server_port)
        server_ip = ssl_server.interfaces.ssl.server_ip

        socket_id = wifi_dut.interfaces.wifi.Asyncsocket()
        assert (
            socket_id > -1
        ), f"Sock ID must be greater than -1 but received {socket_id}"

        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(
            socket_fd=socket_id, option_name="TCP_ULP", option_val="tls_1_2"
        )

        wifi_dut.interfaces.wifi.bind(
            socket_fd=socket_id,
            device_ip=device_ip,
            ip_len=4,
            server_port=randint(5001, 20000),
        )
        wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(
            socket_fd=socket_id, cert_index=0
        )
        wifi_dut.interfaces.wifi.bsdSocketConnect(
            socket_fd=socket_id, server_ip=server_ip, server_port=ssl_server_port
        )
        wifi_dut.interfaces.wifi.bsdSocketSelect(
            numberOfFds=1,
            time=30,
            expected_status=SLStatus.SL_STATUS_OK,
        )
        rx_buffer_data_length = 16000
        while rx_buffer_data_length > 0:
            tx_buffer = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=1600)
            )
            logger.info(
                f"Sending data over socket {socket_id + 1} and length of TX data:{len(tx_buffer)}"
            )
            buffer_length = len(tx_buffer)
            ssl_server.interfaces.ssl.send_data(
                socket_no=socket_id + 1,
                pkt_count=1,
                msg_length=len(tx_buffer),
                message=tx_buffer,
            )
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=0)
            rx_buffer_data_length -= len(buffer_rx)
            logger.info(
                f"TX Data Length from Server is {buffer_length} and Received Data Length is {len(buffer_rx)}"
            )
            assert (
                len(buffer_rx) <= 1472
            ), f"buffer length sent by remote peer and received on the socket id {socket_id} opened in the DUT is more than 1460 bytes"
        logger.info(f"Starting TCP TX Data Transfer")
        tx_data_buffer_length = 16000
        while tx_data_buffer_length > 0:
            tx_buffer = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=1000)
            )
            wifi_dut.interfaces.wifi.bsdSocketSend(
                socket_fd=socket_id, data=tx_buffer, higher_data_len=1
            )
            rx_buffer = ssl_server.interfaces.ssl.data_recv_content(
                1, buffer_size=len(tx_buffer)
            )
            logger.info(f"\n\nRECEIVED DATA:  {rx_buffer} \n\n")
            assert (
                tx_buffer == rx_buffer.decode()
            ), f"Sent data: {tx_buffer} didn't match received data: {rx_buffer}"
            tx_data_buffer_length -= len(rx_buffer)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

    finally:
        ssl_server.interfaces.ssl.stop_server()
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket_id)
