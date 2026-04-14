from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xOperatingMode, Si91xCertificateType, Si91xCertIdentifier
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect_3.tests.sl_status import SLStatus
from random import randint
from utf.utils import get_tls_certificate_dir


def logger():
    return get_logger(__name__)


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None, wifi_client=None,
                 test_case=None, url=None, aws_s3=None, azure_blob=None, rps_path=None, http_server=None,
                 tcp_server=None, abort=False, power_save=False, utf_constants=None):
        super().__init__()
        self.host_ip = None
        self.wifi_dut = wifi_dut
        self.time_duration = None
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.fw_version_before_upgrade = None
        self.fw_version_after_upgrade = None
        self.url = url
        self.aws_s3 = aws_s3
        self.azure_blob = azure_blob
        self.aws_host_name = "httpotaf.s3.us-east-2.amazonaws.com"
        self.azure_host_name = "httpotaf.blob.core.windows.net"
        self.rps_path = rps_path
        self.wifi_client = wifi_client
        self.http_server = http_server
        self.twelve_hour = 43200
        self.tcp_server = tcp_server
        self.dut_addr = None
        self.abort = abort
        self.utf_constants = utf_constants
        self.power_save = power_save

    def run(self):
        logger().info(" **** Configuring the sniffer with access point channel **** ")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== Start capturing with Sniffer by giving the test case name as filename ====== ")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_case)

        if self.tcp_server:
            time_duration = self.utf_constants.get("long_duration")
            t_end = time.time() + time_duration
            while time.time() < t_end:
                fw_version_before_upgrade = self.wifi_dut.interfaces.wifi.version()
                logger().info(f"*** DUT firmware version after upgrade = {fw_version_before_upgrade} ***")
                self.wifi_dut.interfaces.wifi.is_external_stack_enabled = False
                self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         power_save=self.power_save, retry_count=3,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated)
                logger().info("Starting TCP server...")
                self.http_server.interfaces.server.start_server()
                remote_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                local_port = 5001
                client_socket = self.wifi_dut.interfaces.wifi.socket(protocol="IPPROTO_TCP")
                self.wifi_dut.interfaces.wifi.bind(socket_fd=client_socket, device_ip=self.dut_addr['device_ip'], ip_len=4,
                                                   server_port=local_port, asynch=1)
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=client_socket, server_ip=remote_ip, ip_len=4,
                                                               server_port="5001")

                self.wifi_dut.interfaces.wifi.update_firmware_over_tcp(timeout=150)
                self.wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")
                self.wifi_dut.interfaces.wifi.is_external_stack_enabled = True
                self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                self.wifi_dut.interfaces.wifi.init(mode="client", config_required=False, load_certificate=False)
                fw_version_after_upgrade = self.wifi_dut.interfaces.wifi.version()
                logger().info(f"*** DUT firmware version after upgrade = {fw_version_after_upgrade} ***")
        logger().info("Stopping Sniffer capture...")
        self.wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'OPEN'})
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3072}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.Aggregation |
                    Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.HTTPClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORD |
                              Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
)
@pytest.mark.test_src_map_id('C510706')
def test_wifi_sdk_tcp_fw_upgrade_full_security_overnight_c510706(firmware_loader, wifi_client, sdk_server,
                                                                 wifi_access_point, wifi_dut, wifi_sniffer,
                                                                 sl_collections, utf_constants):
    """Verify the TA firmware upgradation functionality using the TCP server (firmware update example) with
    Full Security enabled overnight run"""

    try:
        test_case = '510706'
        logger().info(f"***** Firmware file name: {sdk_server.interfaces.server.firmware_file_name} *****")
        wlan_obj = WifiJoin(http_server=sdk_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, rps_path=sdk_server.interfaces.server.firmware_file_name,
                            tcp_server=True, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut,
                            test_case=test_case, power_save=False, utf_constants=utf_constants)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        sdk_server.interfaces.server.stop_server()


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'OPEN'})
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3072}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.Aggregation |
                    Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.HTTPClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORD |
                              Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
)
@pytest.mark.test_src_map_id('C510728')
def test_wifi_sdk_tcp_fw_upgrade_combine_image_overnight_c510728(firmware_loader, wifi_client, sdk_server,
                                                                 wifi_access_point, wifi_dut, wifi_sniffer,
                                                                 sl_collections, utf_constants):
    """	Verify DUT functionality with combined image(TA full security + M4 Full security) using TCP server
    (firmware update example) with Full Security enabled overnight"""

    try:
        test_case = '510728'
        sdk_server.interfaces.server.firmware_file_name = utf_constants.get("combine_rps_filename")
        logger().info(f"***** Firmware file name: {sdk_server.interfaces.server.firmware_file_name} *****")
        wlan_obj = WifiJoin(http_server=sdk_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, rps_path=sdk_server.interfaces.server.firmware_file_name,
                            tcp_server=True, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut,
                            test_case=test_case, power_save=False, utf_constants=utf_constants)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        sdk_server.interfaces.server.stop_server()
