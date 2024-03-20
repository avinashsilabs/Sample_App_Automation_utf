import time
import pytest
import string
import random
from retry import retry
from threading import Thread
from random import randint
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.interfaces.socket import SOCKET_TYPE_TCP, SOCKET_TYPE_UDP
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
                                                                      listen_interval=self.listen_interval)
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        return dut_ip, dut_mac_address


class SocketDataTransfer:
    def __init__(self):
        self.connected = False

    @retry(Exception, delay=1, tries=5)
    def open_socket_and_data_transfer(self, wifi_dut, remote_socket, dut_ip, numberOfFds=0, close_socket=True,
                                      test_run_time=30):
        sock = 0
        try:
            if not self.connected:
                local_port = randint(20001, 40000)
                server_port = randint(6000, 6100)
                remote_socket.interfaces.socket.time_limit = 3600
                remote_socket.interfaces.socket.start_server(socket_type=0, port=server_port)  # 0-TCP, 1-UDP
                server_ip = remote_socket.interfaces.socket.server_ip
                sock = wifi_dut.interfaces.wifi.socket()
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=dut_ip, server_port=local_port, timeout=15)
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
                self.connected = True
                if numberOfFds:
                    wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=numberOfFds, time=60)

            sw = Stopwatch()
            while sw.elapsed_sec <= test_run_time:
                tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger().info(f"Remote peer sending data over socket {sock} and data:{tx_buffer}")
                remote_socket.interfaces.socket.send_data_tcp(tx_buffer, use_server_socket=True)
                time.sleep(1)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, async_timeout=10)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock} opened in the DUT is not matched"
                logger().info("Data sent by remote peer and received on DUT is matching")
            if close_socket:
                self.close_socket(wifi_dut, sock, remote_socket)
            return sock
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
    def send_data_tcp(remote_socket, tx_buffer, pkt_count=1, sock_id=None, use_server_socket=True):
        for _ in range(pkt_count):
            if sock_id is not None:
                remote_socket.interfaces.socket.sockets[sock_id].send_data_tcp(tx_buffer, use_server_socket)
            else:
                remote_socket.interfaces.socket.send_data_tcp(tx_buffer, use_server_socket)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "server_socket_limit": 4,
        "client_socket_limit": 4,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("repeat_count", [10])
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
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "server_socket_limit": 4,
        "client_socket_limit": 4,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("repeat_count", [10])
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
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
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
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable"])
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
                switch.interfaces.pdu_switch.turn_off(delay=5)
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
                switch.interfaces.pdu_switch.turn_on(delay=60)
                logger.info("Successfully powered on AP")

                # logger.info("\n\nEnabling Wireless in AP")
                # wifi_access_point.interfaces.wifi.start_ap()
                # time.sleep(60)
                # logger.info("Enabled Wireless in AP")
            trf_thread.join()
            logger.info(f"Iteration '{count}' completed\n\n")

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
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
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
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
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
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
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
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
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
        remote_socket.interfaces.socket.start_server(port=server_port)
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address(ip_version=4)
        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
        time.sleep(3)

        buffer_length = 100
        sock_obj = SocketDataTransfer()
        sw = Stopwatch()
        while sw.elapsed_sec <= 30:
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
            logger.info(f"Sending data from remote peer, data --> {tx_buffer}")
            trf_thread = Thread(target=sock_obj.send_data_tcp, args=(remote_socket, tx_buffer))
            trf_thread.start()
            time.sleep(1)
            wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=1, time='NULL')
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=30)
            assert len(tx_buffer) == len(buffer_rx), f"buffer length sent by remote peer and received on the socket " \
                                                     f"id {sock} opened in the DUT is not matched"
            logger.info("Data sent by remote peer and received at DUT is matching")
            trf_thread.join()
            time.sleep(1)

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
def test_wifi_sdk_sync_socket_select_with_diff_time_interval_c19336(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                    remote_socket_factory,
                                                                    logger, sl_collections, sniffer_filter):
    """
    Execute synchronous rsi_select() api with different timeout values(1 sec, 30 sec, 60 sec, 300 sec, 900 sec).
    """
    try:
        sock_obj = SocketDataTransfer()
        capture_filename = f'test_wifi_sdk_sync_select_c19336'
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
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.time_limit = 3600
            server_socket.start_server(port=server_port, socket_type=SOCKET_TYPE_TCP)
            server_ip = server_socket.hostname_or_ip_address(ip_version=4)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port,
                                          timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
            time.sleep(3)
        for time_interval in [1, 30, 60, 300, 900]:
            logger.info("\n\n")
            logger.info(f"************* Socket select time interval: '{time_interval}' *************")
            sw = Stopwatch()
            while sw.elapsed_sec <= 30:
                for sock_id in range(4):
                    tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=90))
                    logger.info(f"Sending data from remote peer, data --> {tx_buffer}")
                    trf_thread = Thread(target=sock_obj.send_data_tcp,
                                        args=(remote_socket_factory, tx_buffer, 1, sock_id))
                    trf_thread.start()
                    time.sleep(1)
                    wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=4, time=time_interval)
                    buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_id, timeout=30)
                    assert len(tx_buffer) == len(buffer_rx), f"buffer length sent by remote peer and received on " \
                                                             f"the socket id {sock_id} opened in the DUT is not matched"
                    logger.info("Data sent by remote peer and received on DUT is matching")
                    trf_thread.join()
                    time.sleep(0.5)
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


"""Below testcase needs rework on next announcements"""
# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
#         "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
#             1),
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
#         "server_socket_limit": 4,
#         "client_socket_limit": 4,
#     }
# )
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
# def test_socket_select_neg_TCC19332(
#         wifi_sniffer, wifi_dut, wifi_access_point, remote_socket, logger, sl_collections
# ):
#     """
#     Execute rsi_select() api when no socket is opened in the DUT
#     pass if the expected error(0x0009) code is received
#     """
#     try:
#         capture_filename = "test_socket_select_neg_TCC19332"
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel)
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file=f"{capture_filename}.pcap"
#         )
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
#                                                                  retry_count=3, rejoin_parms=[0, 6, 40, 0])
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         logger.info("Run socket select command before opening any socket")
#         wifi_dut.interfaces.wifi.set_fd(socket_count=1) #not available
#         with pytest.raises(WlanError) as exc_info:
#             wifi_dut.interfaces.wifi.bsdSocketSelect(0, timeout=60)
#         assert exc_info.value.error_code == 0xFFFFFFFF, "DUT sent wrong error code, expected is 0xFFFFFFFF"
#         with pytest.raises(WlanError) as exc_info:
#             wifi_dut.interfaces.wifi.wlan_get_status()  #not available
#         assert exc_info.value.error_code == 0x0009, "DUT sent wrong error code, expected is 0x0009"
#         if exc_info.value.error_code == 0x0009:
#             logger.info(f"DUT sent expected error code {exc_info.value.error_code}")
#         wifi_dut.interfaces.wifi.leave()
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger.info("Stop Sniffer finally")
#         validation = True
#         packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         logger.info(f"PS-POLL packets are captured in the sniffer")
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
