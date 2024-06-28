import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xExtCustomFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xCertificateType, Si91xCertIdentifier, Cipher, Si91xModuleType
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from random import randint


def logger():
    return get_logger(__name__)


""" Test Steps:
        1. Configure the DUT in Wlan & coex mode for 2.4Ghz.
        2. Initiate the Scan from DUT.
        3. Initiate the connection with third party Access Point.
        4. Start SSL Server 
        4. Run the traffic TCP TX & RX.
        5. Verify the throughput of values TCP TX & RX values.  

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Benazeer.K@silabs
"""


class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi connectivity ,powersave ,data transfer"""

    def __init__(self, wifi_sniffer=None, wifi_dut=None, wifi_access_point=None, ssl_server=None, sl_collections=None,
                 sniffer_filter=None, data_transfer=None, traffic_type=None, testcase=None, test_case_no=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.ssl_server = ssl_server
        self.testcase = testcase
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.data_transfer = data_transfer
        self.traffic_type = traffic_type
        self.test_case_no = test_case_no
        self.device_ip = None
        self.dut_mac_address = None
        self.dut_addr = None

    def run(self):
        logger().info("starting the sniffer again")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        device_ip, dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                  wifi_access_point=self.wifi_access_point,
                                                                  associated=self.wifi_dut.interfaces.wifi.associated,
                                                                  retry_count=3, ping_after_power_save=False,
                                                                  power_save=False)
        self.wifi_dut.interfaces.wifi.switch_host_frequency()
        time.sleep(2)
        if self.data_transfer:
            if self.traffic_type == "TX":
                buffer_length = 1370
                port1 = self.ssl_server.interfaces.ssl.config['device_port1']
                self.ssl_server.interfaces.ssl.start_server()
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                # Open ssl client socket in the DUT
                sock = self.wifi_dut.interfaces.wifi.socket()
                assert sock == 0, "Socket id received is wrong. expected is 0"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                local_port = randint(5001, 60000)
                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                              timeout=15)
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
                self.ssl_server.interfaces.ssl.start_server()
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.set_socket_config()
                # Open ssl client socket in the DUT
                time.sleep(2)
                sock = self.wifi_dut.interfaces.wifi.async_sdk_socket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                                 protocol="IPPROTO_TCP")
                assert sock == 0, "Socket id received is wrong. expected is 0"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                local_port = randint(5001, 60000)
                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                              timeout=15)
                time.sleep(3)
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                          server_port=port1)
                socket_no = 1
                pkt_count = 50000
                duration = 60
                self.ssl_server.interfaces.ssl.send_data(socket_no, pkt_count, msg_length=buffer_length, duration=duration)
                time.sleep(80)
                bytes_sent = self.ssl_server.interfaces.ssl.data_send_stats(socket_no)
                result = self.wifi_dut.interfaces.wifi.get_socket_rx_stats(sock, no_of_pkts="pkt_count", ttl=30)
                logger().info(f"*** result of rx_stats in wifidut {result}")
                bytes_received = int(result)
                logger().info(f"bytes sent by remote peer -> {bytes_sent}")
                logger().info(f"bytes received on socket {sock} -> {bytes_received}")
                logger().info(f"SSL rx throughput ->  {((bytes_received * 8) / (1000 * 1000 * duration))} Mbps")
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                logger().info("Successfully closed opened socket in the DUT")
                self.ssl_server.interfaces.ssl.stop_server()
                time.sleep(5)

        self.wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        self.wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL |
                              Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
            "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
                                   | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                                  Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                                  Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1) |
                                  Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
            "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
            "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
        }
    )
]


@pytest.mark.firmware_app("test_480K_M4SS_192K")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
def test_wifi_sdk_ssl_standalone_tx_480_192K_c20742(firmware_loader, wifi_access_point, sniffer_filter, sl_collections, wifi_dut, ssl_server,
                                           logger, wifi_sniffer, request):
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, sl_collections=sl_collections, ssl_server=ssl_server,
                              data_transfer=True, traffic_type="TX")
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_480K_M4SS_192K")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_standalone_rx_480_192K_C20743(firmware_loader, wifi_access_point, sniffer_filter, request, sl_collections, wifi_dut,
                                           ssl_server, logger, utf_constants, wifi_sniffer):
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, sl_collections=sl_collections, ssl_server=ssl_server,
                              data_transfer=True, traffic_type="RX")
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_480K_M4SS_192K")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'n'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
def test_wifi_sdk_ssl_11N_standalone_tx_480_192K_C537718(firmware_loader, wifi_access_point, sniffer_filter, sl_collections, wifi_dut, ssl_server,
                                           logger, wifi_sniffer, request):
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, sl_collections=sl_collections, ssl_server=ssl_server,
                              data_transfer=True, traffic_type="TX")
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_480K_M4SS_192K")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'n'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_11N_standalone_rx_480_192K_C537719(firmware_loader, wifi_access_point, sniffer_filter, request, sl_collections, wifi_dut,
                                           ssl_server, logger, utf_constants, wifi_sniffer):
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, sl_collections=sl_collections, ssl_server=ssl_server,
                              data_transfer=True, traffic_type="RX")
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL |
                              Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
            "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
                                   | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                                  Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                                  Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1) |
                                  Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
            "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
            "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
        }
    )
]


@pytest.mark.firmware_app("test_416K_M4SS_256K")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
def test_wifi_sdk_ssl_standalone_tx_416_256K_C532894(firmware_loader, wifi_access_point, sniffer_filter, sl_collections, wifi_dut, ssl_server,
                                           logger, wifi_sniffer, request):
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, sl_collections=sl_collections, ssl_server=ssl_server,
                              data_transfer=True, traffic_type="TX")
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_416K_M4SS_256K")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_standalone_rx416_256K_C532895(firmware_loader, wifi_access_point, sniffer_filter, request, sl_collections, wifi_dut,
                                           ssl_server, logger, utf_constants, wifi_sniffer):
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, sl_collections=sl_collections, ssl_server=ssl_server,
                              data_transfer=True, traffic_type="RX")
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_416K_M4SS_256K")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'n'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
def test_wifi_sdk_ssl_11n_standalone_tx416_256K_C537724(firmware_loader, wifi_access_point, sniffer_filter, sl_collections, wifi_dut, ssl_server,
                                           logger, wifi_sniffer, request):
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, sl_collections=sl_collections, ssl_server=ssl_server,
                              data_transfer=True, traffic_type="TX")
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_416K_M4SS_256K")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'n'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_11n_standalone_rx416_256K_C537725(firmware_loader, wifi_access_point, sniffer_filter, request, sl_collections, wifi_dut,
                                           ssl_server, logger, utf_constants, wifi_sniffer):
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, sl_collections=sl_collections, ssl_server=ssl_server,
                              data_transfer=True, traffic_type="RX")
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL |
                              Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
            "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
                                   | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                                  Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                                  Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1) |
                                  Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
            "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
            "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
        }
    )
]


@pytest.mark.firmware_app("test_352K_M4SS_320K")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
def test_wifi_sdk_ssl_standalone_tx_352_320K_C532928(firmware_loader, wifi_access_point, sniffer_filter, sl_collections, wifi_dut, ssl_server,
                                           logger, wifi_sniffer, request):
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, sl_collections=sl_collections, ssl_server=ssl_server,
                              data_transfer=True, traffic_type="TX")
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_352K_M4SS_320K")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_standalone_rx_352_320K_C532929(firmware_loader, wifi_access_point, sniffer_filter, request, sl_collections, wifi_dut,
                                           ssl_server, logger, utf_constants, wifi_sniffer):
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, sl_collections=sl_collections, ssl_server=ssl_server,
                              data_transfer=True, traffic_type="RX")
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_352K_M4SS_320K")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'n'})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
def test_wifi_sdk_ssl_11n_standalone_tx_352_320K_C537730(firmware_loader, wifi_access_point, sniffer_filter, sl_collections, wifi_dut, ssl_server,
                                           logger, wifi_sniffer, request):
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, sl_collections=sl_collections, ssl_server=ssl_server,
                              data_transfer=True, traffic_type="TX")
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_352K_M4SS_320K")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'n'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_11n_standalone_rx_352_320K_C537731(firmware_loader, wifi_access_point, sniffer_filter, request, sl_collections, wifi_dut,
                                           ssl_server, logger, utf_constants, wifi_sniffer):
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, sl_collections=sl_collections, ssl_server=ssl_server,
                              data_transfer=True, traffic_type="RX")
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)