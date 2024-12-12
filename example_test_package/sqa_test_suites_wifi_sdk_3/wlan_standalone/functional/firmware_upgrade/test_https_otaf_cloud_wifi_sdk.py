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


def wifi_dut_marker_http_longer_url(ca_cert=None):
    """
        Common method to generate wifi_dut marker for pytest.mark.config decorator.
        """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3072}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.Aggregation |
                    Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.HTTPLongerURL,
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
                 test_case=None, url=None, url1=None, aws_s3=None, azure_blob=None, rps_path=None, url_len=None):
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
        self.long_url = None
        self.url_len = url_len
        self.new_url = None

    def fw_download_from_aws_server(self, aws_s3, rps_path):

        logger().info(f"******firmware file name uploading to aws server {rps_path}*********")
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

    def fw_download_presigned_url(self, aws_s3, rps_path):
        long_file = "longerurltesting"
        long_url_name = []
        if self.test_case == '500499':
            for i in range(1, 77):
                long_url_name.append(long_file + str(i))
        if self.test_case == '500498':
            for i in range(1, 80):
                long_url_name.append(long_file + str(i))
        if self.test_case == '510789':
            for i in range(1, 49):
                long_url_name.append(long_file+str(i))
        elif self.test_case == '510788' or self.test_case == '500497':
            for i in range(1, 25):
                long_url_name.append(long_file+str(i))

        logger().info(f"long url name {long_url_name}")
        final_long_url_name = "".join(long_url_name)
        logger().info(f"final url name {final_long_url_name}")

        presigned_rps_path_aws = "PRESIGNED_URL/"+final_long_url_name+"/"+rps_path
        logger().info(f"PRESIGNED_RPS_PATH PATH {presigned_rps_path_aws}")

        if self.test_case != '500499' and self.test_case != '500498':
            rps_path_final = "/app/manifest/" + rps_path
            status = aws_s3.interfaces.s3.upload_file(rps_path_final, "httpotaf", presigned_rps_path_aws)
            assert status is True, f"unable to upload"
            logger().info(f"upload successful")

            logger().info(f"upload successful")
            url = aws_s3.interfaces.s3.get_file_url("httpotaf", "us-east-2", presigned_rps_path_aws)
            logger().info(f"****** aws url is :{url}")

            logger().info("Removing https://httpotaf.s3.us-east-2.amazonaws.com/ as it is not required for long url")
            self.new_url = url.replace("https://httpotaf.s3.us-east-2.amazonaws.com/", "")
            logger().info(f"Final url to upload {self.new_url}")

        if self.test_case == '500499' or self.test_case == '500498':
            self.new_url = presigned_rps_path_aws
            logger().info(f"Since 2048 legth not allowed to upload, simulated url of length more than 2048 to download {self.new_url}")

        p_s_url = aws_s3.interfaces.s3.create_presigned_url("httpotaf", self.new_url, 6000)
        logger().info(f" PRESIGNED URL IS {p_s_url}")
        logger().info(f" length pre-signed url is {len(p_s_url)}")
        return p_s_url


    def fw_download_from_aws_server_for_longer_url_length(self, aws_s3, rps_path, url_len):
        logger().info(f"**** rps_path: ***{rps_path}")
        long_rps_path_800 = "LONGER_URL/HTTPS_OTAF/item1item2item3item4item5item6item7item8item9item10item11item12item13item14item15item16item17item18item19item20item21item22item23item24item25item26item27item28item29item30item31item32item33item34item35item36item37item38item39item40item41item42item43item44item45item46item47item48item49item50item51item52item53item54item55item56item57item58item59item60item61item62item63item64item65item66item67item68item69item70item71item72item73item74item75item76item77item78item79item80item81item82item83item84item85item86item87item88item89item90item91item92item93item94item95item96item97item98item99item100item101item102item103item104item105item106item107item108item109item110item111item112item113item114item115/HTTP_OTAF_LONGER_URL_800/"+rps_path
        long_rps_path_1024 = "LONGER_URL/HTTPS_OTAF/item1item2item3item4item5item6item7item8item9item10item11item12item13item14item15item16item17item18item19item20item21item22item23item24item25item26item27item28item29item30item31item32item33item34item35item36item37item38item39item40item41item42item43item44item45item46item47item48item49item50item51item52item53item54item55item56item57item58item59item60item61item62item63item64item65item66item67item68item69item70item71item72item73item74item75item76item77item78item79item80item81item82item83item84item85item86item87item88item89item90item91item92item93item94item95item96item97item98item99item100item101item102item103item104item105item106item107item108item109item110item111item112item113item114item115116item117item118item119item120item121item122item123item124item125item126item127item128item129item130item131item132item133item134item135item136item137item138item139item140item141item142item143item144item145/HTTP_OTAF_LONGER_URL_1024/" + rps_path
        if self.url_len == 800:
            rps_path_final = "/app/manifest/" + rps_path
            status = aws_s3.interfaces.s3.upload_file(rps_path_final, "httpotaf", long_rps_path_800)
            assert status is True, f"unable to upload"
            logger().info(f"upload successful")
            url = aws_s3.interfaces.s3.get_file_url("httpotaf", "us-east-2", long_rps_path_800)
            logger().info(f"aws url is :{url}")
            return url
        elif self.url_len == 1024:
            rps_path_final = "/app/manifest/" + rps_path
            status = aws_s3.interfaces.s3.upload_file(rps_path_final, "httpotaf", long_rps_path_1024)
            assert status is True, f"unable to upload"
            logger().info(f"upload successful")
            url = aws_s3.interfaces.s3.get_file_url("httpotaf", "us-east-2", long_rps_path_1024)
            logger().info(f"aws url is :{url}")
            return url

    def run(self):
        try:

            if self.test_case == '652416' or self.test_case == '498663':
                logger().info("Downloading firmware from Azure server...")
                self.url1 = self.fw_download_from_azure_server(azure_blob=self.azure_blob, rps_path=self.rps_path)
                logger().info(f"Firmware URL obtained: {self.url1}")

            elif self.test_case == '500496' or self.test_case == '500495':
                self.url = self.fw_download_from_aws_server_for_longer_url_length(aws_s3=self.aws_s3, rps_path=self.rps_path, url_len=self.url_len)

            elif self.test_case == '500497' or self.test_case == '510788' or self.test_case == '510789' or self.test_case == '500499' or self.test_case == '500498':
                self.url = self.fw_download_presigned_url(aws_s3=self.aws_s3, rps_path=self.rps_path)

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
            if self.test_case == '652416' or self.test_case == '498663':
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

            if self.test_case == '19769' or self.test_case == '498662' or self.test_case == '687579' or self.test_case == '687580':
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
            if self.test_case == '500496' or self.test_case == '500495':
                logger().info(f"Test case 500496: URL received is {self.url}")
                logger().info("Removing https://httpotaf.s3.us-east-2.amazonaws.com/ as it is not required for long url")
                self.new_url = self.url.replace("https://httpotaf.s3.us-east-2.amazonaws.com/", "")
                logger().info(f"Final url to upload {self.new_url}")
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=1,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.aws_host_name,
                    extended_header='""',
                    username='""',
                    password='""',
                    post_data='""',
                    http_url=self.new_url,
                    async_timeout=500)
            if self.test_case == '500497' or self.test_case == '510789' or self.test_case == '500499':
                logger().info("Removing https://httpotaf.s3.amazonaws.com/ as it is not required for long url")
                self.new_url = self.url.replace("https://httpotaf.s3.amazonaws.com/", "")
                logger().info(f"Final url to upload {self.new_url}")
                logger().info(f"**** length of url is {len(self.new_url)}")
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=1,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.aws_host_name,
                    extended_header='""',
                    username='""',
                    password='""',
                    post_data='""',
                    http_url=self.new_url,
                    async_timeout=500,
                    expected_status=SLStatus.SL_STATUS_SI91X_ERROR_IN_LEN_OF_THE_COMMAND)
            if self.test_case == '510788':
                logger().info("Removing https://httpotaf.s3.amazonaws.com/ as it is not required for long url")
                self.new_url = self.url.replace("https://httpotaf.s3.amazonaws.com/", "")
                logger().info(f"Final url to upload {self.new_url}")
                logger().info(f"**** length of url is {len(self.new_url)}")
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=1,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.aws_host_name,
                    extended_header='""',
                    username='""',
                    password='""',
                    post_data='""',
                    http_url=self.new_url,
                    async_timeout=500)
            if self.test_case == '500498':
                logger().info("Removing https://httpotaf.s3.amazonaws.com/ as it is not required for long url")
                self.new_url = self.url.replace("https://httpotaf.s3.amazonaws.com/", "")
                logger().info(f"Final url to upload {self.new_url}")
                logger().info(f"**** length of url is {len(self.new_url)}")
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=1,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.aws_host_name,
                    extended_header='""',
                    username='""',
                    password='""',
                    post_data='""',
                    http_url=self.new_url,
                    async_timeout=500,
                    expected_status=SLStatus.SL_STATUS_HAS_OVERFLOWED)
            if self.test_case == '652416' or self.test_case == '498663':
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

            if self.test_case == '498662' or self.test_case == '498663':
                self.wifi_dut.interfaces.wifi.reset()
                time.sleep(15)

            if self.test_case != '498662' and self.test_case != '498663':
                # self.wifi_dut.interfaces.wifi.deinit()
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
def test_wifi_sdk_https_fw_upgrade_using_aws_server_ext_header_c652581(aws_s3, wifi_sniffer, wifi_access_point,
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


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_fw_upgrade_using_azure_server_c652416(azure_blob, wifi_sniffer,
                                                              wifi_access_point, wifi_dut, sl_collections,
                                                              utf_constants):
    """This Test case is validating Firmware upgrade using azure server """
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


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_fw_upgrade_using_aws_server_c498662(aws_s3, wifi_sniffer, wifi_access_point,
                                                            wifi_dut, sl_collections, utf_constants):
    """TVerify M4 firmware update functionlaity using HTTPS otaf (port 443)with aws server"""
    rps_path = utf_constants.get("m4_rps_plain")
    try:
        test_case = '498662'

        wlan_obj = WifiJoin(aws_s3=aws_s3, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            rps_path=rps_path)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_fw_upgrade_using_azure_server_498663(azure_blob, wifi_sniffer,
                                                             wifi_access_point, wifi_dut, sl_collections,
                                                             utf_constants):
    """Wi-Fi - M4 Firmware Update functionality using azure server """
    rps_path = utf_constants.get("m4_rps_plain")
    try:
        test_case = '498663'
        wlan_obj = WifiJoin(azure_blob=azure_blob, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            rps_path=rps_path)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker_http_longer_url()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_fw_url_length_1024_c500495(aws_s3, wifi_sniffer, wifi_access_point,
                                                           wifi_dut, sl_collections, utf_constants):
    """This Test case is validating Firmware upgrade using aws server"""
    rps_path = utf_constants.get("rps_filename")
    try:
        test_case = '500495'

        wlan_obj = WifiJoin(aws_s3=aws_s3, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            rps_path=rps_path,url_len=1024)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@wifi_dut_marker_http_longer_url()
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_fw_url_length_800_c500496(aws_s3, wifi_sniffer, wifi_access_point,
                                                           wifi_dut, sl_collections, utf_constants):
    """This Test case is validating Firmware upgrade using aws server"""
    rps_path = utf_constants.get("rps_filename")
    try:
        test_case = '500496'

        wlan_obj = WifiJoin(aws_s3=aws_s3, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            rps_path=rps_path, url_len=800)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_fw_url_length_1080_c500497(aws_s3, wifi_sniffer, wifi_access_point,
                                                           wifi_dut, sl_collections, utf_constants):
    """This Test case is validating Firmware upgrade using aws server"""
    rps_path = utf_constants.get("rps_filename")
    try:
        test_case = '500497'

        wlan_obj = WifiJoin(aws_s3=aws_s3, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            rps_path=rps_path, url_len=1080)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_M4_fw_url_length_1500_disable_http_url_c510789(aws_s3, wifi_sniffer, wifi_access_point,
                                                           wifi_dut, sl_collections, utf_constants):
    """HTTP(S) OTAFÂ M4 update functionality with URL length is more than 1024 (i-e ~1500) and disable long http bit"""
    rps_path = utf_constants.get("m4_rps_plain")
    try:
        test_case = '510789'

        wlan_obj = WifiJoin(aws_s3=aws_s3, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            rps_path=rps_path)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



@pytest.mark.start_state("wifi_dut", wifi=['init'])
@wifi_dut_marker_http_longer_url()
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
def test_wifi_sdk_https_fw_url_length_2048_enable_http_url_c500498(aws_s3, wifi_sniffer, wifi_access_point,
                                                           wifi_dut, sl_collections, utf_constants):
    """HTTP(S) OTAFÂ update functionality with URL length is more than 2048 (i-e ~2048) and enable long http bit"""
    rps_path = utf_constants.get("rps_filename")
    try:
        test_case = '500498'

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
def test_wifi_sdk_https_fw_url_length_2048_disable_http_url_c500499(aws_s3, wifi_sniffer, wifi_access_point,
                                                           wifi_dut, sl_collections, utf_constants):
    """HTTP(S) OTAFÂ update functionality with URL length is more than 2048 (i-e ~2048) and disable long http bit"""
    rps_path = utf_constants.get("rps_filename")
    try:
        test_case = '500499'

        wlan_obj = WifiJoin(aws_s3=aws_s3, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            rps_path=rps_path)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3072}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.Aggregation |
                    Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.HTTPLongerURL,
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
        "ca_cert": ["combined_cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw", "clear_certs"])
def test_wifi_sdk_https_fw_upgrade_using_aws_server_combined_root_ca_c687580(aws_s3, wifi_sniffer, wifi_access_point,
                                                           wifi_dut, sl_collections, utf_constants):
    """This Test case is validating Firmware upgrade using aws server"""
    rps_path = utf_constants.get("rps_filename")
    try:
        test_case = '687580'

        wlan_obj = WifiJoin(aws_s3=aws_s3, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            rps_path=rps_path)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3072}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.Aggregation |
                    Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.HTTPLongerURL,
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
        "ca_cert": ["intermediate-root-ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw","clear_certs"])
def test_wifi_sdk_https_fw_upgrade_using_aws_server_intermediate_root_ca_c687579(aws_s3, wifi_sniffer, wifi_access_point,
                                                           wifi_dut, sl_collections, utf_constants):
    """This Test case is validating Firmware upgrade using aws server"""
    rps_path = utf_constants.get("rps_filename")
    try:
        test_case = '687579'

        wlan_obj = WifiJoin(aws_s3=aws_s3, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            rps_path=rps_path)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)














