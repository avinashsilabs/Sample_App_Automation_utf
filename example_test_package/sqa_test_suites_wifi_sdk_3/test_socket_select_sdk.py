import time
import math
import pytest
import string
import random
from random import randint
from threading import Thread
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import ping
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.socket import SOCKET_TYPE_TCP, SOCKET_TYPE_UDP
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xOperatingMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xConfigFeatureBitMap
)


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

    @retry(Exception, delay=10, tries=3)
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
                logger().info(f"Remote peer sending data over socket {sock + 1} and data:{tx_buffer}")
                remote_socket.interfaces.socket.send_data_tcp(tx_buffer, use_server_socket=True)
                time.sleep(1)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock} opened in the DUT is not matched"
                logger().info("Data sent by remote peer and received on DUT is matching")
            if close_socket:
                self.close_socket(wifi_dut, sock, remote_socket)
        except Exception as error:
            logger().info(f"Exception Occurred: {error}")
            self.close_socket(wifi_dut, sock, remote_socket)
            raise error

    @staticmethod
    def close_socket(wifi_dut, socket_id, remote_socket):
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
        logger().info(f"Successfully closed socket_id '{socket_id}' in the DUT")
        remote_socket.interfaces.socket.stop()


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
def test_wifi_sdk_socket_select_tcp_TC19325(
        wifi_sniffer, wifi_dut, wifi_access_point, remote_socket, logger, repeat_count, sl_collections
):
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
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)
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
def test_wifi_sdk_socket_select_udp_TC19328(
        wifi_sniffer, wifi_dut, wifi_access_point, remote_socket, logger, repeat_count, sl_collections
):
    """
    Verify Data receive functionality after checking the availability of the data on the socket ID using select function over UDP client
    """
    try:
        capture_filename = "test_wifi_sdk_socket_select_udp_TC19328"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap")
        port = 5001
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        remote_socket.interfaces.socket.start_server(socket_type=1)
        server_ipp = remote_socket.interfaces.socket.hostname_or_ip_address(ip_version=4)
        # # DUT opens tcp client socket
        sock = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, ip_len=4, server_port=port, asynch=1)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ipp, ip_len=4, server_port=port)
        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=1, time=10)
        for i in range(repeat_count):
            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            buffer_length = len(tx_buffer)
            remote_socket.interfaces.socket.send_data_udp(tx_buffer, device_ip, port)
            time.sleep(2)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)
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
            rx_buffer = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=1)
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
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
            device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False, sniff_capture=False)
            wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger.info(f'AP BSSID = {ap_bssid}')

            socket_obj = SocketDataTransfer()
            socket_obj.open_socket_and_data_transfer(wifi_dut, remote_socket, device_ip, numberOfFds=1)

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
                logger.info("Enabled Wireless in AP")
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
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
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        err_count = 0
        expected_err_count = 5
        sw = Stopwatch()
        while sw.elapsed_sec < test_run_time:
            time_left = int((test_run_time - sw.elapsed_sec) / 60)
            logger.info(f"Remaining time to complete test is '{time_left}' minutes")
            try:
                for sock_count in range(4):
                    sock = wifi_dut.interfaces.wifi.Asyncsocket()
                    assert sock == sock_count, f"Sock ID must be {sock_count} but received {sock}"
                    sock_opened.append(sock)
                    if sock_count == 0:
                        socket_port = 5001
                    elif sock_count == 1:
                        socket_port = 5002
                    elif sock_count == 2:
                        socket_port = 5003
                    else:
                        socket_port = 5004
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
                    logger.info(f"Remote peer sending data over socket {sock_id + 1} and data:{tx_buffer}")
                    remote_socket_factory.interfaces.socket.sockets[sock_id].send_data_tcp(tx_buffer, True)
                    time.sleep(1)
                    wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                    buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_id)
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
                logger.warning(f"Observed Error: {error}")
                err_count += 1
                for sock_id in sock_opened:
                    logger.info(f"Closing socket_id->{sock_id}")
                    wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
                sock_opened.clear()
                remote_socket_factory.interfaces.socket.close_all()
                remote_socket_factory.interfaces.socket.sockets = []

        assert err_count <= expected_err_count, f"Number of times failure occurred is {err_count}," \
                                                f"which is greater than expected error count {expected_err_count}"
        logger.info(f"**************** Number of times failures observed during span of {test_run_time / 60} minutes "
                    f"test run is '{err_count}', Which is less than expected failure count {expected_err_count}."
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
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
        for count in range(4):
            server_port = start_port + count
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
            assert sock == count, f"socket id received is wrong, expected is {count}"
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port, timeout=15,
                                          asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)

        client_socket = []
        for count in range(4):
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            ThreadBase.call_functions_simultaneously(
                [(wifi_dut.interfaces.wifi.bsdSocketAccept, count, 1),
                 (client_socket[count].connect_client_tcp, device_ip, start_port + count)], timeout=10)

        time.sleep(3)
        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=4, time=10)
        sw = Stopwatch()
        while sw.elapsed_sec <= 60:
            for index in range(4):
                tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                client_socket[index].send_data_tcp(tx_buffer)
                time.sleep(1)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=index + 4)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{index} opened in the DUT is not matched"
                logger.info("Data sent by remote peer and received on DUT is matching")

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
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_socket_select_after_remote_socket_close_c19333(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                 sniffer_filter, remote_socket_factory, logger,
                                                                 sl_collections):
    """
    Execute rsi_select() api on the socket ID when the socket is opened second time.
    The first opened socket is closed due to remote terminate or closed intentially by DUT
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
            server_port = server_port + count
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port, timeout=15,
                                          asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)

            client_socket = remote_socket_factory.interfaces.socket.create_socket()
            ThreadBase.call_functions_simultaneously(
                [(wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1),
                 (client_socket.connect_client_tcp, device_ip, server_port)], timeout=10)

            time.sleep(3)
            wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=1, time=10)
            sw = Stopwatch()
            while sw.elapsed_sec <= 30:
                tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                client_socket.send_data_tcp(tx_buffer)
                time.sleep(1)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(sock + 1)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock + 1} opened in the DUT is not matched"
                logger.info("Data sent by remote peer and received on DUT is matching")

            if count == 0:
                logger.info("\n\nClosing remote socket from remote peer as per the test step")
                remote_socket_factory.interfaces.socket.close_all()
                remote_socket_factory.interfaces.socket.sockets = []
                time.sleep(30)
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_socket_select_udp_bidirectional_c19338(wifi_sniffer, wifi_dut, wifi_access_point, sniffer_filter,
                                                         remote_socket_factory, logger, sl_collections):
    """
    Verify send and receive data over socket ID(UDP)parallel when the socket id is added in the socket_select() api
    """
    try:
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
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_UDP")
            assert sock == count, f"socket id received is wrong, expected is {count}"
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port, timeout=15,
                                          asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)

        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=4, time=10)
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            for socket_no in range(0, 4):
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger.info(f"Remote peer sending data over socket {remote_socket_factory + 1} and data:{data}")
                wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=socket_no, data=data)
                time.sleep(0.5)
                data_receive, address = remote_socket_factory.interfaces.socket.sockets[socket_no].recv_data_udp(
                    len(data))
                logger.info(f"DUT Received data ->  {data_receive} from address {address}")
                assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
                logger.info("Data sent by DUT and received on remote peer is matching")

                tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                remote_socket_factory.interfaces.socket.sockets[socket_no].send_data_udp(tx_buffer, device_ip,
                                                                                         port=start_port + socket_no)
                time.sleep(1)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket_no)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{socket_no} opened in the DUT is not matched"
                logger.info("Data sent by remote peer and received on DUT is matching")

        for sock_id in range(4):
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        remote_socket_factory.interfaces.socket.close_all()

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


"""Below testcases needs rework on next announcements"""
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
#
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
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={"thread_config": {"wifi": {"count": 1, "stack_len": 2048}, }})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
# def test_socket_select_synchronous_timeout_NULL_tcp_TC19335(
#         wifi_sniffer, wifi_dut, wifi_access_point, remote_socket, logger, sl_collections
# ):
#     """
#     Verify the synchronous rsi_select() api when timeout argument given is NULL
#     """
#     try:
#         capture_filename = "test_socket_select_synchronous_timeout_NULL_tcp_TC19335"
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel)
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file=f"{capture_filename}.pcap"
#         )
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
#                                                                  retry_count=3, rejoin_parms=[0, 6, 40, 0])
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#
#         remote_socket.interfaces.socket.start_server()
#         # DUT opens tcp client socket
#         sock = wifi_dut.interfaces.wifi.socket(protocol="IPPROTO_TCP")
#         assert sock == 0, f"socket id received is wrong, expected is 0"
#         # Socket binds at (device_ip, 5001) in DUT
#         wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=5001,
#                                       timeout=15)
#         # tcp socket opened in DUT connects to the tcp server
#         wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=remote_socket.interfaces.socket)
#         tx_buffer = "12345678901234567890123456789012345678901234567890"
#         buffer_length = len(tx_buffer)
#         wifi_dut.interfaces.wifi.set_fd(socket_count=1) #not available
#         thread = Thread(target=send_data, args=(remote_socket, tx_buffer, 30, logger), )
#         thread.start()
#         sock_fd = wifi_dut.interfaces.wifi.socket_select(0, select_timeout=0, asynchronous=0, timeout=180) #not available
#         sock = get_socket_id(sock_fd)
#         sock_list=[]
#         sock_list.append(sock)
#         data_receive(wifi_dut, sock_list, buffer_length, tx_buffer)
#         for sock_count in range(0, 1):
#             logger.info(f"Closing socket_id->{sock_count}")
#             result = wifi_dut.interfaces.wifi.bsdSockClose(sock_count)
#             assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
#             logger.info(f"Successfully closed socket_id->{sock_count}")
#         remote_socket.interfaces.socket.socket_close_indication(1)
#         time.sleep(1)
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
#
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
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={"thread_config": {"wifi": {"count": 1, "stack_len": 2048}, }})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
# def test_socket_select_synchronous_timeout_diff_time_intervals_tcp_TC19336(
#         wifi_sniffer, wifi_dut, wifi_access_point, remote_socket, logger, sl_collections
# ):
#     """
#     verify synchronous rsi_select() api with different timeout values(1 sec, 30 sec, 60 sec, 300 sec, 900 sec)
#     """
#     try:
#         capture_filename = "test_socket_select_synchronous_timeout_diff_time_intervals_tcp_TC19336"
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel)
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file=f"{capture_filename}.pcap"
#         )
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
#                                                                  retry_count=3, rejoin_parms=[0, 6, 40, 0])
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#
#         remote_socket.interfaces.socket.time_limit = 3600
#         remote_socket.interfaces.socket.start_server()
#         # DUT opens tcp client socket
#         sock = wifi_dut.interfaces.wifi.socket(protcol="IPPROTO_TCP")
#         assert sock == 0, f"socket id received is wrong, expected is 0"
#         # Socket binds at (device_ip, 5001) in DUT
#         wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=5001,
#                                       timeout=15)
#         # tcp socket opened in DUT connects to the tcp server
#         wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=remote_socket.interfaces.socket)
#         tx_buffer = "12345678901234567890123456789012345678901234567890"
#         buffer_length = len(tx_buffer)
#
#         for iteration in range(1, 11):
#             wifi_dut.interfaces.wifi.set_fd(socket_count=1) #not available
#             if (iteration % 2) == 0:
#                 thread = Thread(target=send_data, args=(remote_socket, tx_buffer, 10, logger), )
#                 thread.start()
#             if iteration < 3:
#                 socket_select_timeout = 20
#             elif (iteration > 2) and (iteration < 5):
#                 socket_select_timeout = 30
#             elif (iteration > 4) and (iteration < 7):
#                 socket_select_timeout = 60
#             elif (iteration > 6) and (iteration < 9):
#                 socket_select_timeout = 300
#             elif (iteration > 8) and (iteration < 11):
#                 socket_select_timeout = 900
#             if (iteration % 2) == 0:
#                 sock_fd = wifi_dut.interfaces.wifi.socket_select(0, select_timeout=socket_select_timeout, asynchronous=0,
#                                                                  timeout=(socket_select_timeout + 2)) #not available
#                 if sock_fd != 0:
#                     socket_no = get_socket_id(sock_fd)
#                     logger.info(f"Data is received on socket id {socket_no}")
#                 else:
#                     logger.info(f"Data is not received on socket id {sock} within time->{socket_select_timeout} seconds")
#                     assert False, f"Data is not received on socket id {sock} within time->{socket_select_timeout} seconds"
#             else:
#                 with TimeMeasurer() as t:
#                     sock_fd = wifi_dut.interfaces.wifi.socket_select(0, select_timeout=socket_select_timeout,
#                                                                      asynchronous=0,
#                                                                      timeout=(socket_select_timeout + 2)) #not available
#                     if sock_fd == 0:
#                         logger.info("Socket select returned 0 when there is no data on the socket which is expected")
#                     assert sock_fd == 0, "Socket select response returned socket id even though there is no data on the " \
#                                          "socket "
#                 socket_select_response_timeout = t.duration
#                 logger.info(
#                     f"Socket select API returned after {socket_select_response_timeout} seconds when there is no "
#                     f"data received on the opened socket when timeout given in the API is {socket_select_timeout}")
#
#             if (iteration % 2) == 0:
#                 sock_list = []
#                 sock_list.append(socket_no)
#                 data_receive(wifi_dut, sock_list, buffer_length, tx_buffer)
#
#         for sock_count in range(0, 1):
#             logger.info(f"Closing socket_id->{sock_count}")
#             result = wifi_dut.interfaces.wifi.bsdSockClose(sock_count)
#             assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
#             logger.info(f"Successfully closed socket_id->{sock_count}")
#         remote_socket.interfaces.socket.socket_close_indication(1)
#         time.sleep(1)
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
#
# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
#         "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
#         "server_socket_limit": 4,
#         "client_socket_limit": 4,
#
#     }
# )
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
# @pytest.mark.parametrize("repeat_count", [30])
# def test_socket_select_multiple_sockets_tcp_udp_TC19329(
#         wifi_sniffer, wifi_dut, wifi_access_point, remote_socket_factory, logger, repeat_count, sl_collections
# ):
#     """
#     Verify Data receive functionality after checking the availability of the data on the socket ID
#     using select function over 2 udp sockets and 2 tcp sockets
#     """
#     try:
#         capture_filename = "test_socket_select_multiple_sockets_TC19329"
#         since_time = 0
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel)
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file=f"{capture_filename}.pcap"
#         )
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
#                                                                  retry_count=3, rejoin_parms=[0, 6, 40, 0])
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         start_port = 5001
#         for sock_count in range(0, 4):
#             port = start_port + sock_count
#             server_socket = remote_socket_factory.interfaces.socket.create_socket()
#             server_socket.time_limit = 3600
#             if sock_count < 2:
#                 server_socket.start_server(port=port, socket_type=SOCKET_TYPE_TCP)
#             else:
#                 server_socket.start_server(port=port, socket_type=SOCKET_TYPE_UDP)
#             if sock_count < 2:
#                 # DUT opens tcp client socket
#                 sock = wifi_dut.interfaces.wifi.socket(protcol="IPPROTO_TCP")
#             else:
#                 # DUT opens udp client socket
#                 sock = wifi_dut.interfaces.wifi.socket(protocol="IPPROTO_UDP")
#             if sock_count == 0:
#                 local_port = 5001
#                 assert sock == 0, f"socket id received is wrong, expected is 0"
#             elif sock_count == 1:
#                 local_port = 5002
#                 assert sock == 1, f"socket id received is wrong, expected is 1"
#             elif sock_count == 2:
#                 local_port = 5003
#                 assert sock == 2, f"socket id received is wrong, expected is 2"
#             else:
#                 local_port = 5004
#                 assert sock == 3, f"socket id received is wrong, expected is 3"
#             # Socket binds at (device_ip, 5001) in DUT
#             wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
#                                           timeout=15)
#             if sock_count < 2:
#                 wifi_dut.interfaces.wifi.bsdSocketConnect(
#                     socket_fd=sock, server_ip=server_socket
#                 )
#
#         for iteration in range(1, repeat_count):
#             logger.info(f"#####################################################Iteration count -> {iteration}")
#             for socket_no in range(0, 4):
#                 wifi_dut.interfaces.wifi.set_fd(socket_count=4, start_sock_no=0) #not available
#                 socket_id = 3
#                 wifi_dut.interfaces.wifi.bsdSocketSelect(socket_id, select_timeout=60)
#                 tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
#                 buffer_length = len(tx_buffer)
#                 if socket_no < 2:
#                     remote_socket_factory.interfaces.socket.sockets[socket_no].send_data_tcp(tx_buffer, True)
#                 else:
#                     if socket_no == 2:
#                         server_port = 5003
#                     else:
#                         server_port = 5004
#                     remote_socket_factory.interfaces.socket.sockets[socket_no].send_data_udp(tx_buffer, device_ip,
#                                                                                              port=server_port)
#                 events = None
#                 for i in range(0, 3):
#                     time.sleep(5)
#                     events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time) #not available
#                     if len(events) >= 1:
#                         break
#                     logger.info(f"Socket select event not received retrying")
#                 assert len(events) >= 1, "Socket select asynchronous event is not received"
#                 logger.info(f"Socket select event received")
#                 sock_list = []
#                 for event in events:
#                     if event.event_type == RS9116AsyncEventType.SOCKET_SELECT_EVENT:
#                         socket_select_event_payload = event.event_data
#                         since_time = event.timestamp + 1
#                         logger.info(f"Socket select event received with payload->{socket_select_event_payload}")
#                         sock_fd = int(socket_select_event_payload.split(b",")[1].split(b":")[1].strip(b"\r\n"))
#                         sock_id = get_socket_id(sock_fd)
#                         if sock_id is not None:
#                             sock_list.append(sock_id)
#                 if not (len(sock_list)):
#                     logger.info("Data is not received on any socket opened in the DUT even though sent by remote peer")
#                 assert len(sock_list) > 0, "Data is not received on any socket opened in the DUT"
#
#                 data_receive(wifi_dut, sock_list, buffer_length, tx_buffer)
#
#         for sock_count in range(0, 4):
#             logger.info(f"Closing socket_id->{sock_count}")
#             result = wifi_dut.interfaces.wifi.bsdSockClose(sock_count)
#             assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
#             logger.info(f"Successfully closed socket_id->{sock_count}")
#         time.sleep(2)
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
#
# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
#         "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
#         "server_socket_limit": 4,
#         "client_socket_limit": 4,
#     }
# )
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
# @pytest.mark.parametrize("repeat_count", [30])
# def test_socket_select_tcp_server_multiple_sockets_rejoin_TC19330(
#         wifi_sniffer, wifi_dut, wifi_access_point, remote_socket_factory, logger, repeat_count, sl_collections
# ):
#     """
#     Verify Data receive functionality after checking the availability of the data on the socket ID
#     using select function over TCP client after successful rejoin
#     """
#     try:
#         capture_filename = "test_socket_select_tcp_server_multiple_sockets_rejoin_TC19330"
#         since_time = 0
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel)
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file=f"{capture_filename}.pcap"
#         )
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
#                                                                  retry_count=3, rejoin_parms=[0, 6, 40, 0])
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#
#         server_port_base = 5001
#         for count in range(0, 4):
#             server_port = server_port_base + count
#             # The below api opens ssl server socket in the DUT
#             sock = wifi_dut.interfaces.wifi.socket(protocol="IPPROTO_TCP")
#             if count == 0:
#                 assert sock == 0, f"socket id received is wrong, expected is 0"
#             if count == 1:
#                 assert sock == 1, f"socket id received is wrong, expected is 1"
#             if count == 2:
#                 assert sock == 2, f"socket id received is wrong, expected is 2"
#             if count == 3:
#                 assert sock == 3, f"socket id received is wrong, expected is 3"
#             # Socket binds at (device_ip, 5001) in DUT
#
#             wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port,
#                                           timeout=15)
#             wifi_dut.interfaces.wifi.listen(sock, backlog=1)
#         client_socket = []
#         for count in range(0, 4):
#             client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
#             server_port = server_port_base + count
#             result = ThreadBase.call_functions_simultaneously(
#                 [
#                     (wifi_dut.interfaces.wifi.bsdSocketAccept, count),
#                     (
#                         client_socket[count].connect_client_tcp,
#                         device_ip,
#                         server_port,
#                     ),
#                 ],
#                 timeout=10,
#             )
#
#             socket_id = result[0]
#             if count == 0:
#                 assert socket_id == 4, f"socket id received is wrong, expected is 4"
#             if count == 1:
#                 assert socket_id == 5, f"socket id received is wrong, expected is 5"
#             if count == 2:
#                 assert socket_id == 6, f"socket id received is wrong, expected is 6"
#             if count == 3:
#                 assert socket_id == 7, f"socket id received is wrong, expected is 7"
#
#         for iteration in range(1, repeat_count):
#             logger.info(f"#####################################################Iteration count -> {iteration}")
#             if iteration == 10:
#                 logger.info(f"Disabling Wireless in AP")
#                 wifi_access_point.interfaces.wifi.stop_ap()
#                 time.sleep(10)
#                 logger.info(f"Enabling Wireless in AP")
#                 wifi_access_point.interfaces.wifi.start_ap()
#                 time.sleep(2)
#             for socket_no in range(0, 4):
#                 wifi_dut.interfaces.wifi.set_fd(socket_count=4, start_sock_no=4) #not available
#                 socket_id = 7
#                 wifi_dut.interfaces.wifi.bsdSocketSelect(socket_id, select_timeout=60)
#                 tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
#                 buffer_length = len(tx_buffer)
#                 client_socket[socket_no].send_data_tcp(tx_buffer)
#                 events = None
#                 for i in range(0, 3):
#                     time.sleep(5)
#                     events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time) #not available
#                     if len(events) >= 1:
#                         break
#                     logger.info(f"Socket select event not received retrying")
#                 assert len(events) >= 1, "Socket select asynchronous event is not received"
#                 logger.info(f"Socket select event received")
#                 sock_list = []
#                 for event in events:
#                     if event.event_type == RS9116AsyncEventType.SOCKET_SELECT_EVENT:
#                         socket_select_event_payload = event.event_data
#                         since_time = event.timestamp + 1
#                         logger.info(f"Socket select event received with payload->{socket_select_event_payload}")
#                         sock_fd = int(socket_select_event_payload.split(b",")[1].split(b":")[1].strip(b"\r\n"))
#                         sock_id = get_socket_id(sock_fd)
#                         if sock_id is not None:
#                             sock_list.append(sock_id)
#                 if not (len(sock_list)):
#                     logger.info("Data is not received on any socket opened in the DUT even though sent by remote peer")
#                 assert len(sock_list) > 0, "Data is not received on any socket opened in the DUT"
#
#                 data_receive(wifi_dut, sock_list, buffer_length, tx_buffer)
#
#         sock_count = 7
#         while sock_count >= 0:
#             logger.info(f"Closing socket_id->{sock_count}")
#             result = wifi_dut.interfaces.wifi.bsdSockClose(sock_count)
#             assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
#             logger.info(f"Successfully closed socket_id->{sock_count}")
#             sock_count = sock_count - 1
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
#
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
# def test_socket_select_after_remote_terminate_TC19333(
#         wifi_sniffer, wifi_dut, wifi_access_point, remote_socket_factory, logger, sl_collections
# ):
#     """
#     Execute rsi_select() api on the socket ID when the socket is opened second time.
#     The first opened socket is closed due to remote terminate or closed intentially by DUT
#     """
#     try:
#         capture_filename = "test_socket_select_after_remote_terminate_TC19333"
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel)
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file=f"{capture_filename}.pcap"
#         )
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
#                                                                  retry_count=3, rejoin_parms=[0, 6, 40, 0])
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#
#         device_port = 5001
#         # The below api opens ssl server socket in the DUT
#         server_sock = wifi_dut.interfaces.wifi.socket(protocol="IPPROTO_TCP")
#         assert server_sock == 0, f"socket id received is wrong, expected is 0"
#         # Socket binds at (device_ip, 5001) in DUT
#         wifi_dut.interfaces.wifi.bind(socket_fd=server_sock, device_ip=device_ip, server_port=device_port,
#                                       timeout=15)
#         wifi_dut.interfaces.wifi.listen(server_sock, backlog=1)
#         since_time = 0
#         for count in range(0, 20):
#             logger.info(f"#####################################################Iteration count -> {count}")
#             if (count == 0) or (count == 11):
#                 client_socket = remote_socket_factory.interfaces.socket.create_socket()
#                 result = ThreadBase.call_functions_simultaneously(
#                     [
#                         (wifi_dut.interfaces.wifi.bsdSocketAccept, server_sock),
#                         (
#                             client_socket.connect_client_tcp,
#                             device_ip,
#                             device_port,
#                         ),
#                     ],
#                     timeout=10,
#                 )
#             socket_id = result[0]
#             wifi_dut.interfaces.wifi.set_fd(socket_count=2) #not available
#             wifi_dut.interfaces.wifi.bsdSocketSelect(socket_id, select_timeout=60)
#             tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
#             buffer_length = len(tx_buffer)
#             client_socket.send_data_tcp(tx_buffer)
#             events = None
#             for i in range(0, 3):
#                 time.sleep(5)
#                 events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time) #not available
#                 if len(events) >= 1:
#                     break
#                 logger.info(f"Socket select event not received retrying")
#             assert len(events) >= 1, "Socket select asynchronous event is not received"
#             logger.info(f"Socket select event received")
#             sock_list = []
#             for event in events:
#                 if event.event_type == RS9116AsyncEventType.SOCKET_SELECT_EVENT:
#                     socket_select_event_payload = event.event_data
#                     since_time = event.timestamp + 1
#                     logger.info(f"Socket select event received with payload->{socket_select_event_payload}")
#                     sock_fd = int(socket_select_event_payload.split(b",")[1].split(b":")[1].strip(b"\r\n"))
#                     sock_id = get_socket_id(sock_fd)
#                     if sock_id is not None:
#                         sock_list.append(sock_id)
#             if not (len(sock_list)):
#                 logger.info("Data is not received on any socket opened in the DUT even though sent by remote peer")
#             assert len(sock_list) > 0, "Data is not received on any socket opened in the DUT"
#
#             data_receive(wifi_dut, sock_list, buffer_length, tx_buffer)
#
#             if count == 10:
#                 client_socket.stop()
#                 for i in range(0, 3):
#                     time.sleep(5)
#                     events = wifi_dut.interfaces.wifi.get_async_events() #not available
#                     if len(events) >= 1:
#                         break
#                 assert len(events) >= 1, "TCP Remote terminate event not found"
#                 for event in events:
#                     since_time = event.timestamp + 1
#                     if event.event_type == RS9116AsyncEventType.TCP_REMOTE_TERMINATE:
#                         logger.info("Received TCP_REMOTE_TERMINATE event")
#                         remote_terminate = event.event_data
#                         socket_id = int(remote_terminate.split(b",")[1].split(b":")[1])
#                         bytes_sent = int(remote_terminate.split(b",")[2].split(b":")[1])
#                         logger.info(f"Number of bytes sent on socket {socket_id}->  {bytes_sent}")
#                         assert 0 == bytes_sent, f"Number of bytes triggered and actually sent by dut are not matched. " \
#                                                 f"triggered {0} bytes, But actually sent {bytes_sent} bytes by DUT"
#
#                     else:
#                         logger.info(f"Remote terminate event is not received by DUT even though tcp socket connected is "
#                                     f"closed ")
#                         assert False, f"Remote terminate event is not received by DUT even though tcp socket connected is " \
#                                       f"closed "
#         sock_count = 1
#         while sock_count >= 0:
#             logger.info(f"Closing socket_id->{sock_count}")
#             result = wifi_dut.interfaces.wifi.bsdSockClose(sock_count)
#             assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
#             logger.info(f"Successfully closed socket_id->{sock_count}")
#             sock_count = sock_count - 1
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
#
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
#             4),
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
#         "server_socket_limit": 4,
#         "client_socket_limit": 4,
#     }
# )
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
# @pytest.mark.parametrize("test_run_time", [300])
# def test_socket_select_tcp_server_bidirectional_TC19337(
#         wifi_sniffer, wifi_dut, wifi_access_point, remote_socket_factory, logger, test_run_time, sl_collections
# ):
#     """
#     Verify send and receive data over socket ID(tcp)parallel when the socket id is added in the socket_select() api
#     """
#     try:
#         capture_filename = "test_socket_select_tcp_server_bidirectional_TC19337"
#         since_time = 0
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel)
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file=f"{capture_filename}.pcap"
#         )
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
#                                                                  retry_count=3, rejoin_parms=[0, 6, 40, 0])
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#
#         server_port_base = 5001
#         for count in range(0, 4):
#             server_port = server_port_base + count
#             # The below api opens ssl server socket in the DUT
#             sock = wifi_dut.interfaces.wifi.socket(protocol="IPPROTO_TCP")
#             if count == 0:
#                 assert sock == 0, f"socket id received is wrong, expected is 0"
#             if count == 1:
#                 assert sock == 1, f"socket id received is wrong, expected is 1"
#             if count == 2:
#                 assert sock == 2, f"socket id received is wrong, expected is 2"
#             if count == 3:
#                 assert sock == 3, f"socket id received is wrong, expected is 3"
#             # Socket binds at (device_ip, 5001) in DUT
#             wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port,
#                                           timeout=15)
#             wifi_dut.interfaces.wifi.listen(sock, backlog=1)
#         client_socket = []
#         for count in range(0, 4):
#             client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
#             time.sleep(3)
#             result = ThreadBase.call_functions_simultaneously(
#                 [
#                     (wifi_dut.interfaces.wifi.bsdSocketAccept, count),
#                     (
#                         client_socket[count].connect_client_tcp,
#                         device_ip,
#                         server_port_base + count,
#                     ),
#                 ],
#                 timeout=10,
#             )
#
#             socket_id = result[0]
#             if count == 0:
#                 assert socket_id == 4, f"socket id received is wrong, expected is 4"
#             if count == 1:
#                 assert socket_id == 5, f"socket id received is wrong, expected is 5"
#             if count == 2:
#                 assert socket_id == 6, f"socket id received is wrong, expected is 6"
#             if count == 3:
#                 assert socket_id == 7, f"socket id received is wrong, expected is 7"
#         iteration = 0
#         sw = Stopwatch()
#         while sw.elapsed_sec < test_run_time:
#             iteration = iteration + 1
#             logger.info(f"#####################################################Iteration count -> {iteration}")
#             for socket_no in range(0, 4):
#                 data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
#                 data_length = len(data_sent)
#                 wifi_dut.interfaces.wifi.bsdSocketsend((socket_no + 4), data=data_sent)
#                 client_socket[socket_no].connected_tcp_socket = client_socket[socket_no]
#                 data_receive = client_socket[socket_no].recv_data_tcp(data_length, True)
#                 logger.info(f"Data Received:{data_receive}")
#                 assert data_sent == data_receive, "Data sent by DUT and received on remote peer is not matched"
#                 logger.info(f"Data sent by DUT and received on remote peer is matched")
#
#                 events = 0
#                 for count in range(5):
#                     try:
#                         wifi_dut.interfaces.wifi.set_fd(socket_count=4, start_sock_no=4) #not available
#                         socket_id = 7
#                         wifi_dut.interfaces.wifi.bsdSocketSelect(socket_id, select_timeout=60)
#                         tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
#                         buffer_length = len(tx_buffer)
#                         client_socket[socket_no].send_data_tcp(tx_buffer)
#                         time.sleep(5)
#                         events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time) #not available
#                         assert len(events) >= 1, "Socket select asynchronous event is not received"
#                         logger.info(f"Socket select event received")
#                         break
#                     except:
#                         logger.info(f"Socket select asynchronous event is not received --> retry_count{count + 1}")
#                         time.sleep(5)
#                 assert len(events) >= 1, "Socket select asynchronous event is not received"
#
#                 sock_list = []
#                 for event in events:
#                     if event.event_type == RS9116AsyncEventType.SOCKET_SELECT_EVENT:
#                         socket_select_event_payload = event.event_data
#                         since_time = event.timestamp + 1
#                         logger.info(f"Socket select event received with payload->{socket_select_event_payload}")
#                         sock_fd = int(socket_select_event_payload.split(b",")[1].split(b":")[1].strip(b"\r\n"))
#                         sock_id = get_socket_id(sock_fd)
#                         if sock_id is not None:
#                             sock_list.append(sock_id)
#                 if not (len(sock_list)):
#                     logger.info("Data is not received on any socket opened in the DUT even though sent by remote peer")
#                 assert len(sock_list) > 0, "Data is not received on any socket opened in the DUT"
#                 sock_list = set(sock_list)
#                 data_receive(wifi_dut, sock_list, buffer_length, tx_buffer)
#             time.sleep(10)
#
#         sock_count = 7
#         while sock_count >= 0:
#             logger.info(f"Closing socket_id->{sock_count}")
#             result = wifi_dut.interfaces.wifi.bsdSockClose(sock_count)
#             assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
#             logger.info(f"Successfully closed socket_id->{sock_count}")
#             sock_count = sock_count - 1
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
#
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
#             4),
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
#         "server_socket_limit": 4,
#         "client_socket_limit": 4,
#
#     }
# )
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
# @pytest.mark.parametrize("test_run_time", [300])
# def test_socket_select_udp_bidirectional_TC19338(
#         wifi_sniffer, wifi_dut, wifi_access_point, remote_socket_factory, logger, test_run_time, sl_collections
# ):
#     """
#     Verify send and receive data over socket ID(UDP)parallel when the socket id is added in the socket_select() api
#     """
#     try:
#         capture_filename = "test_socket_select_udp_bidirectional_TC19338"
#         since_time = 0
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel)
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file=f"{capture_filename}.pcap"
#         )
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
#                                                                  retry_count=3, rejoin_parms=[0, 6, 40, 0])
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#         start_port = 5001
#         sock = None
#         for sock_count in range(4):
#             port = start_port + sock_count
#             # remote_socket_factory.interfaces.socket.time_limit = 3000
#             server_socket = remote_socket_factory.interfaces.socket.create_socket()
#             server_socket.start_server(port=port, socket_type=SOCKET_TYPE_UDP)
#             sock = wifi_dut.interfaces.wifi.socket(protocol="IPPROTO_UDP")
#             if sock_count == 0:
#                 local_port = 5001
#                 assert sock == 0, f"socket id received is wrong, expected is 0"
#             elif sock_count == 1:
#                 local_port = 5002
#                 assert sock == 1, f"socket id received is wrong, expected is 1"
#             elif sock_count == 2:
#                 local_port = 5003
#                 assert sock == 2, f"socket id received is wrong, expected is 2"
#             else:
#                 local_port = 5004
#                 assert sock == 3, f"socket id received is wrong, expected is 3"
#             # Socket binds at (device_ip, 5001) in DUT
#             wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
#                                           timeout=15)
#
#         server_ip = remote_socket_factory.interfaces.socket.sockets[0].hostname_or_ip_address()
#         iteration = 0
#         sw = Stopwatch()
#         while sw.elapsed_sec < test_run_time:
#             iteration = iteration + 1
#             logger.info(f"##################################################### Iteration count --> '{iteration}'")
#             for socket_no in range(0, 4):
#                 data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
#                 data_length = len(data_sent)
#                 if socket_no == 0:
#                     server_port = 5001
#                 elif socket_no == 1:
#                     server_port = 5002
#                 elif socket_no == 2:
#                     server_port = 5003
#                 else:
#                     server_port = 5004
#
#                 wifi_dut.interfaces.wifi.bsdSocketsend(sock_fd=sock, data=data_sent)
#                 data_receive, address = remote_socket_factory.interfaces.socket.sockets[socket_no].recv_data_udp(
#                     data_length)
#                 logger.info(f"DUT Received data ->  {data_receive} from address {address}")
#                 if isinstance(data_receive, str):
#                     assert len(data_sent) == len(
#                         data_receive), "data length sent by DUT and received on remote peer is not matching"
#                     logger.info("data length sent by DUT and received on remote peer is matching")
#
#                 events = 0
#                 for count in range(5):
#                     try:
#                         wifi_dut.interfaces.wifi.set_fd(socket_count=4, start_sock_no=0) #not available
#                         socket_id = 3
#                         wifi_dut.interfaces.wifi.bsdSocketSelect(socket_id, select_timeout=60)
#                         tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
#                         buffer_length = len(tx_buffer)
#                         remote_socket_factory.interfaces.socket.sockets[socket_no].send_data_udp(tx_buffer, device_ip,
#                                                                                                  port=server_port)
#                         time.sleep(5)
#                         events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time) #not available
#                         assert len(events) >= 1, "Socket select asynchronous event is not received"
#                         logger.info(f"Socket select event received")
#                         break
#                     except:
#                         logger.info(f"Socket select asynchronous event is not received --> retry_count{count + 1}")
#                         time.sleep(10)
#                 assert len(events) >= 1, "Socket select asynchronous event is not received"
#
#                 sock_list = []
#                 for event in events:
#                     if event.event_type == RS9116AsyncEventType.SOCKET_SELECT_EVENT:
#                         socket_select_event_payload = event.event_data
#                         since_time = event.timestamp + 1
#                         logger.info(f"Socket select event received with payload->{socket_select_event_payload}")
#                         sock_fd = int(socket_select_event_payload.split(b",")[1].split(b":")[1].strip(b"\r\n"))
#                         sock_id = get_socket_id(sock_fd)
#                         if sock_id is not None:
#                             sock_list.append(sock_id)
#
#                 if not (len(sock_list)):
#                     logger.info("Data is not received on any socket opened in the DUT even though sent by remote peer")
#                 assert len(sock_list) > 0, "Data is not received on any socket opened in the DUT"
#
#                 sock_list = set(sock_list)
#                 data_receive(wifi_dut, sock_list, buffer_length, tx_buffer)
#
#         for sock_count in range(0, 4):
#             logger.info(f"Closing socket_id->{sock_count}")
#             result = wifi_dut.interfaces.wifi.bsdSockClose(sock_count)
#             assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
#             logger.info(f"Successfully closed socket_id->{sock_count}")
#
#         logger.info("Initiating wlan disconnect from DUT")
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
#
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
#             4),
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
#         "server_socket_limit": 4,
#         "client_socket_limit": 4,
#     }
# )
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
# @pytest.mark.parametrize("test_run_time", [900])
# def test_socket_select_tcp_socket_fd_disable_TC19339(
#         wifi_sniffer, wifi_dut, wifi_access_point, remote_socket_factory, logger, test_run_time, sl_collections
# ):
#     """
#     Receive data over tcp socket for 15 minutes continuously every second when the socket ID is not added in the select() api.
#     Then add the socket id in the rsi_select() api.
#     """
#     try:
#         capture_filename = "test_socket_select_disable_enable_tcp_server_multiple_sockets_TC19339"
#         since_time = 0
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel)
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file=f"{capture_filename}.pcap"
#         )
#         result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
#                                                                  retry_count=3, rejoin_parms=[0, 6, 40, 0])
#         device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
#
#         server_port_base = 5001
#         for count in range(0, 4):
#             server_port = server_port_base + count
#             # The below api opens ssl server socket in the DUT
#             sock = wifi_dut.interfaces.wifi.socket(protocol="IPPROTO_TCP")
#             if count == 0:
#                 assert sock == 0, f"socket id received is wrong, expected is 0"
#             if count == 1:
#                 assert sock == 1, f"socket id received is wrong, expected is 1"
#             if count == 2:
#                 assert sock == 2, f"socket id received is wrong, expected is 2"
#             if count == 3:
#                 assert sock == 3, f"socket id received is wrong, expected is 3"
#             # Socket binds at (device_ip, 5001) in DUT
#
#             wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=server_port,
#                                           timeout=15)
#             wifi_dut.interfaces.wifi.listen(sock, backlog=1)
#         client_socket = []
#         for count in range(0, 4):
#             client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
#             server_port = server_port_base + count
#             result = ThreadBase.call_functions_simultaneously(
#                 [
#                     (wifi_dut.interfaces.wifi.bsdSocketAccept, count),
#                     (
#                         client_socket[count].connect_client_tcp,
#                         device_ip,
#                         server_port_base + count,
#                     ),
#                 ],
#                 timeout=10,
#             )
#
#             socket_id = result[0]
#             if count == 0:
#                 assert socket_id == 4, f"socket id received is wrong, expected is 4"
#             if count == 1:
#                 assert socket_id == 5, f"socket id received is wrong, expected is 5"
#             if count == 2:
#                 assert socket_id == 6, f"socket id received is wrong, expected is 6"
#             if count == 3:
#                 assert socket_id == 7, f"socket id received is wrong, expected is 7"
#
#         iteration = 0
#         sw = Stopwatch()
#         fd_disable_time = test_run_time / 2
#
#         while sw.elapsed_sec < fd_disable_time:
#             logger.info(f"#####################################################Iteration count -> {iteration}")
#             iteration = iteration + 1
#             for socket_no in range(0, 4):
#                 tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
#                 buffer_length = len(tx_buffer)
#                 client_socket[socket_no].send_data_tcp(tx_buffer)
#                 time.sleep(1)
#                 sock = socket_no + 4
#                 buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_id=sock)
#                 if not (buffer_length == buffer_length_rx):
#                     logger.info(
#                         f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is "
#                         f"not matched ")
#                 else:
#                     logger.info(
#                         f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is "
#                         f"matched ")
#                 assert buffer_length == buffer_length_rx, f"buffer length sent by remote peer and received on the " \
#                                                           f"socket id {sock} opened in the DUT is not matched "
#                 if not (tx_buffer.encode() == buffer_rx):
#                     logger.info(
#                         f"contents of data sent by remote peer and received on the socket id {sock} opened in the DUT "
#                         f"is not matched ")
#                 else:
#                     logger.info(
#                         f"contents of data sent by remote peer and received on the socket id {sock} opened in the DUT "
#                         f"is matched ")
#                 assert tx_buffer.encode() == buffer_rx, f"contents of data sent by remote peer and received on the " \
#                                                         f"socket " \
#                                                         f"id {sock} opened in the DUT is not matched "
#
#         test_run_time = test_run_time + 120
#         while sw.elapsed_sec < test_run_time:
#             iteration = iteration + 1
#             logger.info(f"#####################################################Iteration count -> {iteration}")
#             for socket_no in range(0, 4):
#                 wifi_dut.interfaces.wifi.set_fd(socket_count=4, start_sock_no=4) #not available
#                 socket_id = 7
#                 wifi_dut.interfaces.wifi.bsdSocketSelect(socket_id, select_timeout=60)
#                 tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
#                 buffer_length = len(tx_buffer)
#                 client_socket[socket_no].send_data_tcp(tx_buffer)
#                 events = None
#                 for i in range(0, 3):
#                     time.sleep(5)
#                     events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time) #not available
#                     if len(events) >= 1:
#                         break
#                     logger.info(f"Socket select event not received retrying")
#                 assert len(events) >= 1, "Socket select asynchronous event is not received"
#                 logger.info(f"Socket select event received")
#                 sock_list = []
#                 for event in events:
#                     if event.event_type == RS9116AsyncEventType.SOCKET_SELECT_EVENT:
#                         socket_select_event_payload = event.event_data
#                         since_time = event.timestamp + 1
#                         logger.info(f"Socket select event received with payload->{socket_select_event_payload}")
#                         sock_fd = int(socket_select_event_payload.split(b",")[1].split(b":")[1].strip(b"\r\n"))
#                         sock_id = get_socket_id(sock_fd)
#                         if sock_id is not None:
#                             sock_list.append(sock_id)
#                 if not (len(sock_list)):
#                     logger.info("Data is not received on any socket opened in the DUT even though sent by remote peer")
#                 assert len(sock_list) > 0, "Data is not received on any socket opened in the DUT"
#                 data_receive(wifi_dut, sock_list, buffer_length, tx_buffer)
#
#         sock_count = 7
#         while sock_count >= 0:
#             logger.info(f"Closing socket_id->{sock_count}")
#             result = wifi_dut.interfaces.wifi.bsdSockClose(sock_count)
#             assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
#             logger.info(f"Successfully closed socket_id->{sock_count}")
#             sock_count = sock_count - 1
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
