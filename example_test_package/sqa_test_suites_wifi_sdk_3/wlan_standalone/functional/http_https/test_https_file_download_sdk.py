from utf.utils.logger import get_logger
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xPowerSaveModes,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
    Si91xOperatingMode,
    Si91xExtCustomFeatureBitMap,
    Si91xJoinFeatureBitMap
)
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.iperf.iperf_utils import ping
from utf.utils.thread_base import ThreadBase
import re

def logger():
    return get_logger(__name__)


"""
    Setup requirement:
        1. SoC Board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

     Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http file download
        
    Author: Ayush Agarwal
"""


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, http_client=None, wifi_client=None,
                 test_name=None, sl_collections=None, http_server=None, index_paths=None, sniffer_filter=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.http_server = http_server
        self.test_name = test_name
        self.index_paths = index_paths
        self.http_client = http_client
        self.sniffer_filter = sniffer_filter
        self.wifi_client = wifi_client
        self.power_save_filter = None
        self.dut_addr = None
        self.ap_mac_address = None
        self.http_client_initialized = False

    def run(self):
        try:
            self.http_server.interfaces.http.start_server()
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     retry_count=3)
            remote_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"http_server_ip: {remote_ip}")
            status = ping(remote_ip, 10)
            assert status, "Server not responding for ping request"

            for index_path in self.index_paths:
                tcp_socket_id = self.wifi_dut.interfaces.wifi.socket(domain="AF_INET")
                self.wifi_dut.interfaces.wifi.bind(socket_fd=tcp_socket_id,
                                                   device_ip=self.dut_addr['device_ip'],
                                                   server_port=self.http_server.interfaces.http.port,
                                                   asynch=0,
                                                   timeout=5)
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=tcp_socket_id, option_level='SOL_TCP',
                                                              option_name='TCP_ULP', option_val="tls")
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=tcp_socket_id, server_ip=remote_ip,
                                                               ip_len=4,
                                                               server_port=self.http_server.interfaces.http.port)
                with TimeMeasurer() as t:
                    result = self.wifi_dut.interfaces.wifi.http_client_download(socket_id=tcp_socket_id,
                                                                                file_name=index_path,
                                                                                ip_address=remote_ip,
                                                                                mode=1, timeout=2000, async_timeout=2000)
                logger().info(f"time taken for file downloading the {index_path} file is {t.duration}")
                bytes_recv = int(re.findall(r"((?<=total received bytes:\s)\d+)", str(result))[0])
                logger().info(f"Total bytes received: {bytes_recv}")
                total_bytes = int(re.findall(r"(\d+)", index_path)[0])
                if "MB" in index_path:
                    total_bytes *= 1024 * 1024
                else:
                    total_bytes *= 1024
                logger().info(f"Total bytes to be received: {total_bytes}")
                assert int(bytes_recv) >= int(total_bytes), f"Data received is not {index_path.replace('.htm', '')}ytes"
                self.wifi_dut.interfaces.wifi.close_sockets()
            self.http_server.interfaces.http.stop_server()
            self.wifi_sniffer.interfaces.capture.stop_capture()

        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 4096, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config("http_server", auto_start=False)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C42042')
def test_wifi_sdk_https_file_download_c42042(wifi_dut, wifi_access_point, sl_collections, http_server,
                                             wifi_client, wifi_sniffer):

    """Verify whether DUT is able to download data from HTTPS server using host based application with different sizes
    (6kb, 1MB, 10MB, 100MB) with power save enabled Use : Host based & synchronous socket"""
    try:
        test_name = "42042"
        index_paths = ["1MB.htm", "10MB.htm", "100MB.htm"]

        download = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              sl_collections=sl_collections, http_server=http_server, wifi_client=wifi_client,
                              index_paths=index_paths, test_name=test_name)

        download.start()
        download.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



