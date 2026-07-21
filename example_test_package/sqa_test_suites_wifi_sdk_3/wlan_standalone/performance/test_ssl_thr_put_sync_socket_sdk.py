import time
import re
import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xExtCustomFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap
from utf_wiseconnect_3.tests.interfaces import Protocol
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.thread_base import ThreadBase
from threading import Thread
from random import randint


def logger():
    return get_logger(__name__)


""" Test Steps:
        1. Configure the DUT in WLAN standalone mode for 2.4GHz 11ax.
        2. Join third party Access Point.
        3. Open SSL client with synchronous BSD socket.
        4. Run SSL RX throughput (and optional 16K-record HTTP file download).
        5. Verify SSL RX throughput.

    Reference: test_ssl_thr_put_with_http_down_sdk.py (async socket variants)
    Difference: uses sync socket (socket()) instead of async_sdk_socket.

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        
    Author: K Benazeer
"""


def sync_socket_rx_stats(wifi_if, sock_id, size, ttl, no_of_pkts, host_wait_margin=30):
    """
    Sync get_socket_rx_stats at test level with host wait > DUT ttl.

    Shared CLI uses async_timeout=ttl+1 which is too tight for sock_type=1
    (DUT blocks for ~ttl sec). Do not change sl_wifi_test_agent_cli.py.
    """
    line = f"get_socket_rx_stats {sock_id} 1 -b {size} -t {ttl} -p {no_of_pkts}"
    logger().info(
        f"sync RX via test-level CLI: {line} (host async_timeout={ttl + host_wait_margin})")
    if wifi_if.test_agent_thread_enabled:
        status, data = wifi_if.issue_command_in_thread(
            line, Protocol.WIFI, [], async_timeout=ttl + host_wait_margin)
    else:
        status, data = wifi_if.issue_command(line=line, timeout=ttl + host_wait_margin)
    wifi_if.verify_status(status, SLStatus.SL_STATUS_OK)
    return re.sub(r"\D", "", data.decode())


class WifiJoinThread(ThreadBase):
    dut_addr = None
    """Wi-Fi join + SSL RX using synchronous BSD socket."""

    def __init__(self, wifi_sniffer=None, wifi_dut=None,
                 wifi_access_point=None, wifi_client=None,
                 iteration_count=None, sl_collections=None, ping_count=None,
                 data_transfer=None, traffic_type=None, testcase=None,
                 test_case_no=None, ssl_server=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.wifi_client = wifi_client
        self.iteration_count = iteration_count
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.data_transfer = data_transfer
        self.traffic_type = traffic_type
        self.test_case_no = test_case_no
        self.ssl_server = ssl_server

    def run(self):
        logger().info("Test Execution Started")
        time.sleep(2)

        WifiJoinThread.dut_addr = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
            retry_count=3, ping_after_power_save=False,
            ping_count=self.ping_count, power_save=False)
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.switch_host_frequency()
        time.sleep(2)
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        if self.data_transfer and self.traffic_type == "RX":
            buffer_length = 1370
            port1 = self.ssl_server.interfaces.ssl.config['device_port1']
            time.sleep(2)

            logger().info("Opening SSL client with synchronous BSD socket")
            sock = self.wifi_dut.interfaces.wifi.socket()
            assert sock == 0, "Socket id received is wrong. expected is 0"
            logger().info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP")
            local_port = randint(5001, 60000)
            self.wifi_dut.interfaces.wifi.bind(
                socket_fd=sock, device_ip=WifiJoinThread.dut_addr['device_ip'],
                server_port=local_port, timeout=15)
            time.sleep(3)
            self.ssl_server.interfaces.ssl.start_server()
            server_ip = self.ssl_server.interfaces.ssl.server_ip
            self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                socket_fd=sock, server_ip=server_ip, server_port=port1)

            socket_no = 1
            pkt_count = 50000
            duration = 60

            # Sync recv must run WHILE the server is sending. If send finishes first,
            # peer closes and DUT recv returns error / host times out (0x7).
            # Start DUT sync RX first, then kick off SSL send.
            rx_holder = {"result": None, "error": None}

            def _sync_rx_worker():
                try:
                    # Test-level helper: longer host wait than shared get_socket_rx_stats
                    rx_holder["result"] = sync_socket_rx_stats(
                        self.wifi_dut.interfaces.wifi,
                        sock_id=sock,
                        size=buffer_length,
                        ttl=duration,
                        no_of_pkts=pkt_count,
                        host_wait_margin=30,
                    )
                except Exception as exc:
                    rx_holder["error"] = exc

            logger().info("Starting synchronous socket RX thread (DUT enters recv)")
            rx_thread = Thread(target=_sync_rx_worker, name="ssl_sync_rx", daemon=True)
            rx_thread.start()
            time.sleep(2)

            logger().info("Starting SSL server send (overlaps with sync RX)")
            self.ssl_server.interfaces.ssl.send_data(
                socket_no, pkt_count, msg_length=buffer_length, duration=duration)

            rx_thread.join(timeout=duration + 50)
            if rx_holder["error"] is not None:
                raise rx_holder["error"]
            assert not rx_thread.is_alive(), "sync RX thread did not finish in time"

            result = rx_holder["result"]
            logger().info(f"*** result of rx_stats in wifidut {result}")
            bytes_received = int(result) if result else 0
            assert bytes_received > 0, (
                f"SSL sync RX received 0 bytes (got '{result}'). "
                f"Check get_socket_rx_stats sock_type=1 / no_of_pkts / ttl."
            )

            # send_data is async on ssl_server; poll until send_bytes is published
            bytes_sent = 0
            for _ in range(20):
                time.sleep(3)
                try:
                    bytes_sent = self.ssl_server.interfaces.ssl.data_send_stats(socket_no)
                except KeyError:
                    logger().info("send_bytes not ready yet; waiting for SSL send thread")
                    continue
                if bytes_sent > 0:
                    break
            if not bytes_sent:
                logger().info(
                    "SSL send_bytes still unavailable after poll; "
                    "continuing with DUT RX stats only"
                )

            logger().info(f"bytes sent by remote peer -> {bytes_sent}")
            logger().info(f"bytes received on socket {sock} -> {bytes_received}")
            logger().info(f"SSL rx throughput ->  {((bytes_received * 8) / (1000 * 1000 * duration))} Mbps")
            time.sleep(5)
            if self.test_case_no == 100001:
                time.sleep(25)
            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
            logger().info("Successfully closed opened socket in the DUT")
            self.ssl_server.interfaces.ssl.stop_server()
            time.sleep(5)


class http_download(WifiJoinThread):
    def __init__(self, wifi_dut, sl_collections=None, http_server=None, index_path=None, https=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.sl_collections = sl_collections
        self.http_server = http_server
        self.index_path = index_path
        self.https = https

    def run(self):
        time.sleep(30)
        logger().info("in http download method")
        self.sl_collections.http_file_download(
            wifi_dut=self.wifi_dut,
            http_server=self.http_server,
            index_path=self.index_path,
            device_ip=WifiJoinThread.dut_addr['device_ip'],
            https=0,
            server_port=5001
        )


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wlan_ssl_rx_tput_sync_soc_11ax_C537882(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, utf_constants,
                                        request, sl_collections, ssl_server):
    """WLAN_Alone_2.4G_SSL Rx_ Tput with synchronous socket_11ax"""
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(
        wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
        testcase=testcase, wifi_client=wifi_client, sl_collections=sl_collections,
        ping_count=ping_count, data_transfer=True, traffic_type="RX",
        iteration_count=iter_count, ssl_server=ssl_server
    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.htm"})
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORDBIT,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wlan_ssl_rx_with_100_mb_sync_soc_11ax_C537886(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                               utf_constants, request, sl_collections, ssl_server, index_path,
                                               http_server):
    """WLAN_Alone_2.4G_SSL Rx_16K Record file(100MB) download with sync socket_11ax"""
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(
        wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
        testcase=testcase, wifi_client=wifi_client, sl_collections=sl_collections,
        ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=100001,
        iteration_count=iter_count, ssl_server=ssl_server
    )
    http_down = http_download(wifi_dut=wifi_dut, http_server=http_server, index_path=index_path,
                              https=0, sl_collections=sl_collections)
    try:
        wlan_obj.start()
        http_down.start()
        wlan_obj.wait_for_exit()
        http_down.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"10MB.htm"})
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORDBIT,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wlan_ssl_rx_with_10_mb_sync_soc_11ax_C537887(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                                      utf_constants, request, sl_collections, ssl_server, index_path,
                                                      http_server):
    """WLAN_Alone_2.4G_SSL Rx_16K Record file(10MB) download with sync socket_11ax"""
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(
        wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
        testcase=testcase, wifi_client=wifi_client, sl_collections=sl_collections,
        ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=100002,
        iteration_count=iter_count, ssl_server=ssl_server
    )
    http_down = http_download(wifi_dut=wifi_dut, http_server=http_server, index_path=index_path,
                              https=0, sl_collections=sl_collections)
    try:
        wlan_obj.start()
        http_down.start()
        wlan_obj.wait_for_exit()
        http_down.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
