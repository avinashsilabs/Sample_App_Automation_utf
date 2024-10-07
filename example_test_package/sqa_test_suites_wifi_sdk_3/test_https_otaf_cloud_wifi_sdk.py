from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xOperatingMode, Si91xCertificateType, Si91xCertIdentifier
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils import get_tls_certificate_dir


"""This Test plan is validating Firmware version upgrade through AWS/Azure HTTP OTAF

        1. Configuration of DUT in 2G : BGN
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Stop the sniffer
        6. Compare firmware version

    setup requirement:
        1. soc board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)
        5. AWS server
        6. Azure server

    Author: SHOBHA RANI JOGU

"""


def logger():
    return get_logger(__name__)


def wifi_dut_marker(ca_cert=None):
    """
        Common method to generate wifi_dut marker for pytest.mark.config decorator.
        """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3072}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
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
        "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    return pytest.mark.config("wifi_dut", wifi=config)


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None,
                 test_case=None, url=None, url1=None, aws_s3=None, azure_blob=None, rps_path=None):
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
        self.url1 = url1
        self.aws_s3 = aws_s3
        self.azure_blob = azure_blob
        self.aws_host_name = "httpotaf.s3.us-east-2.amazonaws.com"
        self.azure_host_name = "httpotaf.blob.core.windows.net"
        self.rps_path = rps_path

    def fw_download_from_aws_server(self, aws_s3, rps_path):

        rps_path_final = "/app/manifest/" + rps_path
        status = aws_s3.interfaces.s3.upload_file(rps_path_final, "httpotaf", "rps_path")
        assert status is True, f"unable to upload"
        logger().info(f"upload successful")
        url = aws_s3.interfaces.s3.get_file_url("httpotaf", "us-east-2", "rps_path")
        logger().info(f"aws url is :{url}")
        return url

    def fw_download_from_azure_server(self, azure_blob, rps_path):

        rps_path_final = "/app/manifest/" + rps_path
        url1 = azure_blob.interfaces.blob.upload_file(rps_path_final, "rps_path")

        logger().info(f"azure url1 is {url1}")
        return url1

    def run(self):
        try:

            if self.test_case == '652416':
                logger().info("Downloading firmware from Azure server...")
                self.url1 = self.fw_download_from_azure_server(azure_blob=self.azure_blob, rps_path=self.rps_path)
                logger().info(f"Firmware URL obtained: {self.url1}")

            else:
                # Use fw_download_from_aws_server to upload the firmware to aws s3 bucket
                logger().info("Downloading firmware from AWS server...")
                self.url = self.fw_download_from_aws_server(aws_s3=self.aws_s3, rps_path=self.rps_path)
                logger().info(f"Firmware URL obtained: {self.url}")

            logger().info(" **** Configuring the sniffer with access point channel **** ")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            logger().info(" ====== Start capturing with Sniffer by giving the test case name as filename ====== ")
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_case)
            self.sl_collections.join_to_wifi_network(self.wifi_dut,
                                                     wifi_access_point=self.wifi_access_point,
                                                     power_save=False,
                                                     retry_count=3,
                                                     associated=self.wifi_dut.interfaces.wifi.associated)
            if self.test_case == '652416':
                result = self.wifi_dut.interfaces.wifi.dns_get(domain_name=self.azure_host_name, query_timeout=20000,
                                                               timeout=100)
            else:
                result = self.wifi_dut.interfaces.wifi.dns_get(domain_name=self.aws_host_name, query_timeout=20000,
                                                               timeout=100)
            logger().info(f'**** Host IP: {result}')
            self.host_ip = (result.decode()).strip()

            logger().info("Pinging to server IP....")
            status = ping(self.host_ip, 10)
            logger().info(f'Ping status = {status}')

            logger().info("DUT firmware version before upgrade...")
            self.fw_version_before_upgrade = self.wifi_dut.interfaces.wifi.version()
            logger().info(f"*** DUT firmware version before upgrade = {self.fw_version_before_upgrade} ***")

            if self.test_case == '19769':
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=1,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.aws_host_name,
                    extended_header='""',
                    username='""',
                    password='""',
                    post_data='""',
                    http_url='rps_path',
                    async_timeout=500)
            if self.test_case == '652581':
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=1,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.aws_host_name,
                    extended_header='HTTPS_SUPPORT',
                    username='""',
                    password='""',
                    post_data='""',
                    http_url='rps_path',
                    async_timeout=500)
            if self.test_case == '652416':
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=1,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.azure_host_name,
                    extended_header='""',
                    username='""',
                    password='""',
                    post_data='""',
                    http_url='firmware/rps_path',
                    async_timeout=500)

            logger().info("Stopping Sniffer capture...")
            self.wifi_sniffer.interfaces.capture.stop_capture()

            self.wifi_dut.interfaces.wifi.reset()
            time.sleep(15)
            self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            self.wifi_dut.interfaces.wifi.init(load_certificate=False)
            self.wifi_dut.interfaces.wifi.initialize_thread()
            self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True

            logger().info("DUT firmware version after upgrade...")
            self.fw_version_after_upgrade = self.wifi_dut.interfaces.wifi.version()
            logger().info(f"*** DUT firmware version after upgrade = {self.fw_version_after_upgrade} ***")

            if self.fw_version_before_upgrade == self.fw_version_after_upgrade:
                logger().info("Firmware after upgrade matched with the previous firmware")
            else:
                logger().info("Firmware upgrade successful. Versions are different.")

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_fw_upgrade_using_aws_server_c19769(aws_s3, wifi_sniffer, wifi_access_point,
                                                           wifi_dut, sl_collections, utf_constants):
    """This Test case is validating Firmware upgrade using aws server"""
    rps_path = utf_constants.get("rps_filename")
    try:
        test_case = '19769'

        wlan_obj = WifiJoin(aws_s3=aws_s3, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            rps_path=rps_path)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_fw_upgrade_using_aws_server_c652581(aws_s3, wifi_sniffer, wifi_access_point,
                                                            wifi_dut, sl_collections, utf_constants):
    """This Test case is validating Firmware upgrade using aws server with extender header enable"""
    rps_path = utf_constants.get("rps_filename")
    try:
        test_case = '652581'
        wlan_obj = WifiJoin(aws_s3=aws_s3, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            rps_path=rps_path)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_azure")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_fw_upgrade_using_azure_server_c652416(firmware_loader, azure_blob, wifi_sniffer,
                                                              wifi_access_point, wifi_dut, sl_collections,
                                                              utf_constants):
    """This Test case is validating Firmware upgrade using aws server with extender header enable"""
    rps_path = utf_constants.get("rps_filename")
    try:
        test_case = '652416'
        wlan_obj = WifiJoin(azure_blob=azure_blob, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            rps_path=rps_path)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
