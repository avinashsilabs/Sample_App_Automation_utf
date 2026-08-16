from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xOperatingMode, Si91xCertificateType, Si91xCertIdentifier
import time
import re
import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from utf.utils.time_measurer import TimeMeasurer
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.sl_status import SLStatus


def _normalize_ota_http_url(path):
    """Ensure OTA path is a server-relative URL (leading '/')."""
    if path is None:
        return None
    path = str(path).strip()
    if not path:
        return path
    return path if path.startswith("/") else f"/{path}"


def _harness_wifi_http_url():
    """Old/alternate RPS from harness defaults.wifi.http_url."""
    defaults = UtfConfig.instance().defaults or {}
    wifi_defaults = defaults.get("wifi") or {}
    return _normalize_ota_http_url(wifi_defaults.get("http_url"))

"""This Test plan is validating Firmware version upgrade through  HTTP OTAF with encryption

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
        7. lighthttpd server

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
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    return pytest.mark.config("wifi_dut", wifi=config)


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None, wifi_client=None,
                 test_case=None, url=None, aws_s3=None, azure_blob=None, rps_path=None, http_server=None,
                 tcp_server=None, abort=False, power_save=False):
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
        self.power_save = power_save

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
        url = azure_blob.interfaces.blob.upload_file(rps_path_final, "rps_path")

        logger().info(f"azure url1 is {url}")
        return url

    def get_firmware_status(self):
        # Prefer net.deinit over hard reset so wifi.set_config / opermode is not
        # reapplied every overnight OTA iteration (config_required=False).
        self.wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")
        time.sleep(30)
        logger().info("Initialising DUT after deinit....")
        self.wifi_dut.interfaces.wifi.is_external_stack_enabled = True
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        self.wifi_dut.interfaces.wifi.init(
            mode="client", config_required=False, load_certificate=False
        )
        self.wifi_dut.interfaces.wifi.initialize_thread()
        self.wifi_dut.interfaces.wifi.is_external_stack_enabled = False
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        fw_after_upgrade = self.wifi_dut.interfaces.wifi.version()
        self.wifi_dut.interfaces.wifi.inited = False
        time.sleep(5)
        return fw_after_upgrade

    def run(self):
        try:

            if self.test_case == '510699':
                logger().info("Downloading firmware from Azure server...")
                self.url = self.fw_download_from_azure_server(azure_blob=self.azure_blob, rps_path=self.rps_path)
                logger().info(f"Firmware URL obtained: {self.url}")

            if self.test_case == '510698' or self.test_case == '510702':
                # Use fw_download_from_aws_server to upload the firmware to aws s3 bucket
                logger().info("Downloading firmware from AWS server...")
                self.url = self.fw_download_from_aws_server(aws_s3=self.aws_s3, rps_path=self.rps_path)
                logger().info(f"Firmware URL obtained: {self.url}")

            logger().info(" **** Configuring the sniffer with access point channel **** ")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            logger().info(" ====== Start capturing with Sniffer by giving the test case name as filename ====== ")
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_case)

            if self.tcp_server:
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
                if self.test_case == "540496" or self.test_case == "510727":
                    update_data = self.wifi_dut.interfaces.wifi.update_firmware_over_tcp(timeout=60, expected_status=SLStatus.SL_STATUS_FAIL)
                    pattern = r'Firmware update failed\s*:\s*([a-fA-F0-9]+)'
                    match = re.search(pattern, update_data)
                    error_code = match.group(1) if match else None
                    logger().info(f"Printing the error code {error_code}")
                    if error_code == "1dd04":
                        logger().info(f"\n UPDATE FIRMWARE OVER TCP Returned error code {error_code}\n ")
                    else:
                        raise ValueError("\n No Error Code Encountered while Upgrading Firmware \n")
                    return

                if self.test_case == "510714":
                    self.wifi_dut.interfaces.wifi.update_firmware_over_tcp(timeout=60,
                                                                           expected_status=SLStatus.SL_STATUS_TIMEOUT)
                    return

                self.wifi_dut.interfaces.wifi.update_firmware_over_tcp(timeout=150)
                if self.test_case == "559884":
                    self.wifi_dut.interfaces.wifi.sl_si91x_fwup_abort()
                    self.http_server.interfaces.server.stop_server()
                    time.sleep(10)
                    self.http_server.interfaces.server.start_server()
                    client_socket = self.wifi_dut.interfaces.wifi.socket(protocol="IPPROTO_TCP")
                    self.wifi_dut.interfaces.wifi.bind(socket_fd=client_socket, device_ip=self.dut_addr['device_ip'],
                                                       ip_len=4, server_port=local_port, asynch=1)
                    self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=client_socket, server_ip=remote_ip,
                                                                   ip_len=4,
                                                                   server_port="5001")
                    self.wifi_dut.interfaces.wifi.update_firmware_over_tcp(timeout=150)
                if self.abort:
                    self.wifi_dut.interfaces.wifi.sl_si91x_fwup_abort()
                    fw_version_after_upgrade = self.wifi_dut.interfaces.wifi.version()
                    logger().info(f"*** DUT firmware version after upgrade = {fw_version_after_upgrade} ***")

                    assert fw_version_after_upgrade == fw_version_before_upgrade, "Firmware version mismatch after upgrade"
                    return
                self.wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")
                self.wifi_dut.interfaces.wifi.is_external_stack_enabled = True
                self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                self.wifi_dut.interfaces.wifi.init(mode="client", config_required=False, load_certificate=False)
                fw_version_after_upgrade = self.wifi_dut.interfaces.wifi.version()
                logger().info(f"*** DUT firmware version after upgrade = {fw_version_after_upgrade} ***")
                logger().info("Stopping Sniffer capture...")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                return

            if self.test_case not in ['510698', '510699', '510702']:
                """ ******* SERVER CHECKS ******* """
                logger().info("checking server stats....")
                server_stat = self.http_server.interfaces.http.started
                assert server_stat == True, "server is inactive"
                logger().info(f'http server state is {server_stat}')
                logger().info("fetching server ip....")
                self.host_ip = self.http_server.interfaces.http.hostname_or_ip_address
                logger().info(f"server ip is {self.host_ip}")

            if self.test_case == '510707':
                current_rps = _normalize_ota_http_url(self.rps_path)
                old_rps = _harness_wifi_http_url()
                assert current_rps and old_rps and current_rps != old_rps, (
                    "C510707 needs two different RPS files on HTTPS docroot: "
                    f"utf_constants.rps_filename={current_rps!r} and "
                    f"defaults.wifi.http_url={old_rps!r}"
                )
                logger().info(f"C510707 current rps_filename={current_rps}")
                logger().info(f"C510707 harness wifi.http_url={old_rps}")

                t_end = time.time() + self.twelve_hour
                iteration = 0
                while time.time() < t_end:
                    iteration += 1
                    wifi = self.wifi_dut.interfaces.wifi
                    # Keep test-agent threads on so scan uses "t 0 A wifi.scan" (avoids 0x7).
                    # For join+DHCP use join_ap + net.configure_ip: with
                    # is_external_stack_enabled=True, start_ip() sends net.up while already
                    # associated and fails with 0x10002 SCAN_ISSUED_IN_ASSOCIATED_STATE.
                    wifi.test_agent_thread_enabled = True
                    wifi.is_external_stack_enabled = False
                    wifi.inited = True

                    logger().info(f"*** Overnight OTA iteration {iteration} ***")
                    if wifi.associated:
                        try:
                            wifi.leave()
                        except Exception as leave_err:
                            logger().warning(f"leave before overnight scan: {leave_err}")
                        wifi.associated = False

                    self.fw_version_before_upgrade = wifi.version()
                    logger().info(f"*** dut fw version before upgrade = {self.fw_version_before_upgrade} ***")

                    # Retried scan/join/DHCP (channel=0). Single channel-scoped scan often
                    # returns 0x10003 NO_AP_FOUND when the beacon is missed in ~100ms.
                    self.sl_collections.join_to_wifi_network(
                        self.wifi_dut,
                        wifi_access_point=self.wifi_access_point,
                        power_save=False,
                        retry_count=3,
                        associated=False,
                        ping_before_power_save=False,
                        channel=0,
                    )

                    # Odd iters: old image (http_url). Even iters: current (rps_filename).
                    ota_http_url = old_rps if iteration % 2 else current_rps
                    logger().info(
                        f"Overnight iter {iteration}: OTA with "
                        f"{'http_url (old)' if iteration % 2 else 'rps_filename (current)'} "
                        f"= {ota_http_url!r}"
                    )

                    with TimeMeasurer() as t:
                        wifi.firmware_upgrade(
                            flags=1,
                            ip_address=self.host_ip,
                            port=443,
                            host_name=self.host_ip,
                            http_url=ota_http_url,
                            timeout=150
                        )

                    if t.duration > 40:
                        logger().info('*** Firmware upgrade time is more ***')
                    else:
                        logger().info(f'*** Firmware upgrade time = {t.duration} ***')
                    logger().info(f'*** Firmware upgrade time: {t.duration} ***')

                    # net.deinit + re-init (no opermode); restores threads for next iter.
                    self.fw_version_after_upgrade = self.get_firmware_status()
                    logger().info(f"*** dut fw version after upgrade = {self.fw_version_after_upgrade} ***")
                    wifi.inited = True
                    wifi.associated = False

                    if self.fw_version_before_upgrade == self.fw_version_after_upgrade:
                        logger().info("Firmware after upgrade matched with the previous firmware")
                    else:
                        logger().info("Firmware upgrade successful. Versions are different.")

                return
            self.wifi_dut.interfaces.wifi.is_external_stack_enabled = False
            self.sl_collections.join_to_wifi_network(self.wifi_dut,
                                                     wifi_access_point=self.wifi_access_point,
                                                     power_save=False,
                                                     retry_count=3,
                                                     associated=self.wifi_dut.interfaces.wifi.associated)

            if self.test_case == '510699':
                result = self.wifi_dut.interfaces.wifi.dns_get(domain_name=self.azure_host_name, query_timeout=20000,
                                                               timeout=100)
                logger().info(f'**** Host IP: {result}')
                self.host_ip = (result.decode()).strip()
            if self.test_case == '510698' or self.test_case == '510702':
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

            if self.test_case == '510696':
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    ip_address=self.host_ip,
                    host_name=self.host_ip,
                    http_url=self.rps_path,
                    timeout=150)
            if self.test_case == '510704':
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    ip_address=self.host_ip,
                    host_name=self.host_ip,
                    http_url=self.rps_path,
                    timeout=150)
                self.fw_version_after_upgrade = self.get_firmware_status()
                logger().info(f"*** DUT firmware version after upgrade = {self.fw_version_after_upgrade} ***")

                if self.fw_version_before_upgrade == self.fw_version_after_upgrade:
                    logger().info("Firmware after upgrade matched with the previous firmware")
                else:
                    logger().info("Firmware upgrade successful. Versions are different.")
                return

            if self.test_case == '510697':
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=1,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.host_ip,
                    http_url=self.rps_path,
                    timeout=150)

            if self.test_case == '510698' or self.test_case == '510702':
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=2049,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.aws_host_name,
                    extended_header='""',
                    username='""',
                    password='""',
                    http_url='rps_path',
                    async_timeout=500)

            if self.test_case == '510699':
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=2049,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.azure_host_name,
                    extended_header='""',
                    username='""',
                    password='""',
                    http_url='firmware/rps_path',
                    async_timeout=500)

            if self.test_case == '510701':
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=1,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.host_ip,
                    http_url=self.rps_path,
                    timeout=150)
                logger().info("The M4 application will load after a reset...")
                self.wifi_dut.interfaces.wifi.reset()
                time.sleep(30)

            if self.test_case == '510702':
                logger().info("The M4 application will load after a reset...")
                self.wifi_dut.interfaces.wifi.reset()
                time.sleep(30)

            if self.test_case == '510708':
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=1,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.host_ip,
                    http_url="/SiWG917-B.2.13.4.1.0.2.rps",
                    expected_status=SLStatus.SL_STATUS_SI91X_FW_UPDATE_FAILED,
                    timeout=150)
                logger().info("stop Sniffer capture...")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                time.sleep(2)
                logger().info("*******The error code 0x1DD04 occurs when updating a plain image "
                              "on a DUT that is encrypted or secured ********")
                return

            if self.test_case == '510709':
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=1,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.host_ip,
                    http_url="/secure_SiWG917-B.2.13.2.0.0.4_corrupt.rps",
                    expected_status=SLStatus.SL_STATUS_SI91X_INVALID_LENGTH,
                    timeout=150)
                logger().info("stop Sniffer capture...")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                time.sleep(2)
                logger().info("*******The error code 0x1DD41 occurs when updating a corrupted image-added lines at end "
                              "on a DUT that is encrypted or secured ********")
                return

            if self.test_case == '510710':
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=1,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.host_ip,
                    http_url="/TA.rps",
                    expected_status=SLStatus.SL_STATUS_SI91X_HTTP_FAILED,
                    timeout=150)
                logger().info("stop Sniffer capture...")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                time.sleep(2)
                logger().info("*******The error code 0xBBE2 occurs when image is not present in server"
                              "on a DUT that is encrypted or secured ********")
                return

            if self.test_case == '510711':
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=1,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.host_ip,
                    http_url="/wifi_station_ping_soc.rps",
                    expected_status=SLStatus.SL_STATUS_SI91X_FW_UPDATE_FAILED,
                    timeout=150)
                logger().info("stop Sniffer capture...")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                time.sleep(2)
                logger().info("*******The error code 0x1DD04 occurs when updating a plain image "
                              "on a DUT that is encrypted or secured ********")
                return

            if self.test_case == '510712':
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=1,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.host_ip,
                    http_url="/secured_wifi_station_ping_soc_corrupt.rps",
                    expected_status=SLStatus.SL_STATUS_SI91X_INVALID_LENGTH,
                    timeout=150)
                logger().info("stop Sniffer capture...")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                logger().info("*******The error code 0x1DD41 occurs when updating a corrupted image-added lines at end "
                              "on a DUT that is encrypted or secured ********")
                return

            if self.test_case == '510713':
                self.wifi_dut.interfaces.wifi.firmware_upgrade(
                    flags=1,
                    ip_address=self.host_ip,
                    port=443,
                    host_name=self.host_ip,
                    http_url="/M4.rps",
                    expected_status=SLStatus.SL_STATUS_SI91X_HTTP_FAILED,
                    timeout=150)
                logger().info("stop Sniffer capture...")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                time.sleep(2)
                logger().info("*******The error code 0xBBE2 occurs when image is not present in server"
                              "on a DUT that is encrypted or secured ********")
                return

            logger().info("Stopping Sniffer capture...")
            self.wifi_sniffer.interfaces.capture.stop_capture()

            if self.test_case != '510701' and self.test_case != '510702':
                self.wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")
                time.sleep(25)
                self.wifi_dut.interfaces.wifi.is_external_stack_enabled = True
                self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                self.wifi_dut.interfaces.wifi.init(mode="client", config_required=False, load_certificate=False)
                self.fw_version_after_upgrade = self.wifi_dut.interfaces.wifi.version()
                logger().info(f"*** DUT firmware version after upgrade = {self.fw_version_after_upgrade} ***")

                if self.fw_version_before_upgrade == self.fw_version_after_upgrade:
                    logger().info("Firmware after upgrade matched with the previous firmware")
                else:
                    logger().info("Firmware upgrade successful. Versions are different.")

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@wifi_dut_marker()
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C510696')
def test_wifi_sdk_https_fw_upgrade_in_sta_alone_mode_and_measure_time_c510696(firmware_loader, wifi_client, http_server,
                                                                              wifi_sniffer, wifi_access_point, wifi_dut,
                                                                              sl_collections, utf_constants):
    """Verify the TA firmware upgrade functionality using HTTP OTAF (Local Apache)with
     Full Security(security level_3 enabled"""

    try:
        test_case = '510696'
        rps_path = utf_constants.get("rps_filename")
        wlan_obj = WifiJoin(http_server=http_server, wifi_sniffer=wifi_sniffer, wifi_client=wifi_client,
                            sl_collections=sl_collections, rps_path=rps_path,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@wifi_dut_marker()
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C510697')
def test_wifi_sdk_https_fw_upgrade_in_sta_alone_mode_and_measure_time_c510697(firmware_loader, wifi_client,
                                                                              http_server, wifi_sniffer,
                                                                              wifi_access_point, wifi_dut,
                                                                              sl_collections,utf_constants):
    """Verify the TA firmware upgrade functionality using HTTP OTAF (Local Apache)with
     Full Security(security level_3 enabled"""
    try:
        test_case = '510697'
        rps_path = utf_constants.get("rps_filename")
        wlan_obj = WifiJoin(http_server=http_server, wifi_sniffer=wifi_sniffer, wifi_client=wifi_client,
                            sl_collections=sl_collections, rps_path=rps_path,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("firmware_security_encrypted_1")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@wifi_dut_marker(ca_cert=["combined_cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C510698')
def test_wifi_sdk_https_fw_upgrade_using_aws_server_c510698(firmware_loader, aws_s3, wifi_sniffer, wifi_access_point,
                                                            wifi_dut, sl_collections, utf_constants):
    """This Test case is validating Firmware upgrade using aws server"""
    rps_path = utf_constants.get("rps_filename")
    try:
        test_case = '510698'

        wlan_obj = WifiJoin(aws_s3=aws_s3, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            rps_path=rps_path)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("firmware_security_encrypted_1")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@wifi_dut_marker(ca_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C510699')
def test_wifi_sdk_https_fw_upgrade_using_azure_server_c510699(firmware_loader, azure_blob, wifi_sniffer,
                                                              wifi_access_point, wifi_dut, sl_collections,
                                                              utf_constants):
    """This Test case is validating Firmware upgrade using aws server with extender header enable"""
    rps_path = utf_constants.get("rps_filename")
    try:
        test_case = '510699'
        wlan_obj = WifiJoin(azure_blob=azure_blob, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            rps_path=rps_path)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.http_server("raspi_lighttpd_tls")
@wifi_dut_marker()
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C510701')
def test_wifi_sdk_m4_fw_upgrade_in_sta_alone_mode_and_measure_time_c510701(firmware_loader, wifi_client, http_server,
                                                                           wifi_sniffer, wifi_access_point, wifi_dut,
                                                                           sl_collections, utf_constants):
    """Verify the M4 firmware upgrade functionality using HTTPS OTAF (Local Apache)with
     Full Security(security level_3) enabled"""

    try:
        test_case = '510701'
        rps_path = utf_constants.get("m4_rps_filename")
        wlan_obj = WifiJoin(http_server=http_server, wifi_sniffer=wifi_sniffer, wifi_client=wifi_client,
                            sl_collections=sl_collections, rps_path=rps_path,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("firmware_security_encrypted_1")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@wifi_dut_marker(ca_cert=["combined_cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C510702')
def test_wifi_sdk_m4_fw_upgrade_using_aws_server_c510702(firmware_loader, aws_s3, wifi_sniffer, wifi_access_point,
                                                         wifi_dut, sl_collections, utf_constants):
    """This Test case is validating m4 Firmware upgrade using aws server"""
    rps_path = utf_constants.get("m4_rps_filename")
    try:
        test_case = '510702'
        wlan_obj = WifiJoin(aws_s3=aws_s3, wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            rps_path=rps_path)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.http_server("raspi_lighttpd_tls")
@wifi_dut_marker()
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C510708')
def test_wifi_sdk_plain_fw_upgrade_negative_c510708(firmware_loader, wifi_client, http_server,
                                                    wifi_sniffer, wifi_access_point, wifi_dut,
                                                    sl_collections):
    """Verify the TA firmware degradation (HTTP OTAF) functionality Plain firmware update application """
    try:
        test_case = '510708'
        wlan_obj = WifiJoin(http_server=http_server, wifi_sniffer=wifi_sniffer, wifi_client=wifi_client,
                            sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.http_server("raspi_lighttpd_tls")
@wifi_dut_marker()
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C510709')
def test_wifi_sdk_corrupted_fw_upgrade_negative_c510709(firmware_loader, wifi_client, http_server,
                                                        wifi_sniffer, wifi_access_point, wifi_dut,
                                                        sl_collections):
    """Verify the M4 firmware upgradation(HTTP OTAF) functionality Plain FW update application"""
    try:
        test_case = '510709'
        wlan_obj = WifiJoin(http_server=http_server, wifi_sniffer=wifi_sniffer, wifi_client=wifi_client,
                            sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.http_server("raspi_lighttpd_tls")
@wifi_dut_marker()
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C510710')
def test_wifi_sdk_fw_upgrade_negative_with_no_file_c510710(firmware_loader, wifi_client, http_server,
                                                           wifi_sniffer, wifi_access_point, wifi_dut,
                                                           sl_collections):
    """Verify the TA firmware update(HTTP OTAF) functionality with the File missing server"""
    try:
        test_case = '510710'
        wlan_obj = WifiJoin(http_server=http_server, wifi_sniffer=wifi_sniffer, wifi_client=wifi_client,
                            sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.http_server("raspi_lighttpd_tls")
@wifi_dut_marker()
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C510711')
def test_wifi_sdk_m4_plain_fw_upgrade_negative_c510711(firmware_loader, wifi_client,http_server,
                                                       wifi_sniffer, wifi_access_point, wifi_dut, sl_collections):
    """Verify the M4 firmware upgradation(HTTP OTAF) functionality Plain FW update application"""
    try:
        test_case = '510711'
        wlan_obj = WifiJoin(http_server=http_server, wifi_sniffer=wifi_sniffer, wifi_client=wifi_client,
                            sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.http_server("raspi_lighttpd_tls")
@wifi_dut_marker()
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C510712')
def test_wifi_sdk_m4_corrupted_fw_upgrade_negative_c510712(firmware_loader, wifi_client, http_server,
                                                           wifi_sniffer, wifi_access_point, wifi_dut,
                                                           sl_collections):
    """Verify the M4 firmware upgradation(HTTP OTAF) functionality Plain FW update application"""
    try:
        test_case = '510712'
        wlan_obj = WifiJoin(http_server=http_server, wifi_sniffer=wifi_sniffer, wifi_client=wifi_client,
                            sl_collections=sl_collections,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.http_server("raspi_lighttpd_tls")
@wifi_dut_marker()
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C510713')
def test_wifi_sdk_m4_fw_upgrade_negative_with_no_file_c510713(firmware_loader, wifi_client, http_server,
                                                              wifi_sniffer, wifi_access_point, wifi_dut,
                                                              sl_collections):
    """Verify the M4 firmware update(HTTP OTAF) functionality with the File missing server"""
    try:
        test_case = '510713'
        wlan_obj = WifiJoin(http_server=http_server, wifi_sniffer=wifi_sniffer, wifi_client=wifi_client,
                            sl_collections=sl_collections, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut,
                            test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C510707')
def test_wifi_sdk_https_fw_upgrade_downgrade_overnight_c510707(firmware_loader, http_server, wifi_sniffer, wifi_client, utf_constants,
                                                               wifi_access_point, wifi_dut, sl_collections):
    """This Test case is validating Firmware update overnight"""

    try:
        test_case = '510707'
        # current image (utf_constants.rps_filename); old/alt image is harness wifi.http_url
        rps_path = utf_constants.get("rps_filename")
        current_rps = _normalize_ota_http_url(rps_path)
        old_rps = _harness_wifi_http_url()
        logger().info(f"C510707 current rps_filename={current_rps}")
        logger().info(f"C510707 harness wifi.http_url={old_rps}")
        if not current_rps or not old_rps or current_rps == old_rps:
            logger().warning(
                "C510707 requires two different RPS files on the HTTPS lighttpd docroot: "
                f"utf_constants.rps_filename={current_rps!r} and "
                f"defaults.wifi.http_url={old_rps!r}")
        wlan_obj = WifiJoin(http_server=http_server, wifi_sniffer=wifi_sniffer,sl_collections=sl_collections,wifi_client=wifi_client,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case, rps_path=rps_path)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'OPEN'})
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@wifi_dut_marker()
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C510700')
def test_wifi_sdk_tcp_fw_upgrade_with_full_security_mode_c510700(firmware_loader, wifi_client, sdk_server,
                                                                 wifi_access_point, wifi_dut, wifi_sniffer,
                                                                 sl_collections):
    """Verify the TA firmware upgradation functionality using the TCP server (firmware update example) with
    Full Security enabled"""

    try:
        test_case = '510700'
        logger().info(f"***** Firmware file name: {sdk_server.interfaces.server.firmware_file_name} *****")
        wlan_obj = WifiJoin(http_server=sdk_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, rps_path=sdk_server.interfaces.server.firmware_file_name,
                            tcp_server=True, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        sdk_server.interfaces.server.stop_server()

@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'OPEN'})
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C510703')
def test_wifi_sdk_tcp_fw_upgrade_with_full_security_mode_c510703(firmware_loader, wifi_client, sdk_server,
                                                                 wifi_access_point, wifi_dut, wifi_sniffer,
                                                                 sl_collections):
    """	Verify DUT functionality with combined image using TCP server (firmware update example) with Full Security
    and Sign enabled"""

    try:
        test_case = '510703'
        logger().info(f"***** Firmware file name: {sdk_server.interfaces.server.firmware_file_name} *****")
        wlan_obj = WifiJoin(http_server=sdk_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, rps_path=sdk_server.interfaces.server.firmware_file_name,
                            tcp_server=True, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        sdk_server.interfaces.server.stop_server()


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C510704')
def test_wifi_sdk_http_combine_image_download_c510704(firmware_loader, wifi_client, http_server, wifi_sniffer,
                                                      wifi_access_point, wifi_dut, sl_collections, utf_constants):
    """Verify DUT functionality with combined image using OTA (HTTP OTAF example) with Full Security and sign enabled"""

    try:
        test_case = '510704'
        rps_path = utf_constants.get("combine_rps_filename")
        wlan_obj = WifiJoin(http_server=http_server, wifi_sniffer=wifi_sniffer, wifi_client=wifi_client,
                            sl_collections=sl_collections, rps_path=rps_path,
                            wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'OPEN'})
@pytest.mark.config("sdk_server", server={"firmware_file_name": "combined_ta_secure_m4_plain.rps"})
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@wifi_dut_marker()
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C510727')
def test_wifi_sdk_tcp_combine_image_ta_secure_m4_plain_c510727(firmware_loader, wifi_client, sdk_server,
                                                               wifi_access_point, wifi_dut, wifi_sniffer,
                                                               sl_collections):
    """Verify DUT functionality with combined image(TA full security + M4 Plain) using TCP server
    (firmware update example) with Full Security enabled"""

    try:
        test_case = '510727'
        logger().info(f"***** Firmware file name: {sdk_server.interfaces.server.firmware_file_name} *****")
        wlan_obj = WifiJoin(http_server=sdk_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, rps_path=sdk_server.interfaces.server.firmware_file_name,
                            tcp_server=True, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        sdk_server.interfaces.server.stop_server()


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'OPEN'})
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C540475')
def test_wifi_sdk_tcp_fw_abort_with_full_security_mode_c540475(firmware_loader, wifi_client, sdk_server,
                                                               wifi_access_point, wifi_dut, wifi_sniffer,
                                                               sl_collections):
    """Verify fwup_abort after the TA rps download using firmware update via TCP with Full Security enabled"""

    try:
        test_case = '540475'
        logger().info(f"***** Firmware file name: {sdk_server.interfaces.server.firmware_file_name} *****")
        wlan_obj = WifiJoin(http_server=sdk_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, rps_path=sdk_server.interfaces.server.firmware_file_name,
                            tcp_server=True, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            abort=True)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        sdk_server.interfaces.server.stop_server()


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'OPEN'})
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@wifi_dut_marker()
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C540476')
def test_wifi_sdk_tcp_fw_abort_m4_with_full_security_mode_c540476(firmware_loader, wifi_client, sdk_server,
                                                                  wifi_access_point, wifi_dut, wifi_sniffer,
                                                                  sl_collections, utf_constants):
    """Verify fwup_abort after the TA rps download using firmware update via TCP with Full Security enabled"""

    try:
        test_case = '540476'
        sdk_server.interfaces.server.firmware_file_name = utf_constants.get("m4_rps_filename")
        logger().info(f"***** Firmware file name: {sdk_server.interfaces.server.firmware_file_name} *****")
        wlan_obj = WifiJoin(http_server=sdk_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, rps_path=sdk_server.interfaces.server.firmware_file_name,
                            tcp_server=True, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            abort=True)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        sdk_server.interfaces.server.stop_server()


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'OPEN'})
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C540477')
def test_wifi_sdk_tcp_fw_abort_with_combine_image_c540477(firmware_loader, wifi_client, sdk_server,
                                                          wifi_access_point, wifi_dut, wifi_sniffer,
                                                          sl_collections, utf_constants):
    """Verify fwup_abort after the TA rps download using firmware update via TCP with Full Security enabled"""

    try:
        test_case = '540475'
        sdk_server.interfaces.server.firmware_file_name = utf_constants.get("combine_rps_filename")
        logger().info(f"***** Firmware file name: {sdk_server.interfaces.server.firmware_file_name} *****")
        wlan_obj = WifiJoin(http_server=sdk_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, rps_path=sdk_server.interfaces.server.firmware_file_name,
                            tcp_server=True, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                            abort=True)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        sdk_server.interfaces.server.stop_server()


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'OPEN'})
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C540495')
def test_wifi_sdk_tcp_fw_upgrade_with_mic_encryption_sign_security_c540495(firmware_loader, wifi_client, sdk_server,
                                                                           wifi_access_point, wifi_dut, wifi_sniffer,
                                                                           sl_collections):
    """Verify the TA firmware upgradation functionality using the TCP server (firmware update example) with
    MIC + Encryption + Sign enabled"""

    try:
        test_case = '540495'
        logger().info(f"***** Firmware file name: {sdk_server.interfaces.server.firmware_file_name} *****")
        wlan_obj = WifiJoin(http_server=sdk_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, rps_path=sdk_server.interfaces.server.firmware_file_name,
                            tcp_server=True, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        sdk_server.interfaces.server.stop_server()


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'OPEN'})
@pytest.mark.config("sdk_server", server={"firmware_file_name": "mic_only_SiWG917-B.2.14.5.0.0.2.rps"})
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@wifi_dut_marker()
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C540496')
def test_wifi_sdk_tcp_fw_upgrade_with_mic_only_security_mode_c540496(firmware_loader, wifi_client, sdk_server,
                                                                     wifi_access_point, wifi_dut, wifi_sniffer,
                                                                     sl_collections):
    """Verify the TA firmware upgradation functionality using the TCP server (firmware update example) with
    MIC + Encryption + Sign enabled"""

    try:
        test_case = '540496'
        logger().info(f"***** Firmware file name: {sdk_server.interfaces.server.firmware_file_name} *****")
        wlan_obj = WifiJoin(http_server=sdk_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, rps_path="mic_only_SiWG917-B.2.14.5.0.0.2.rps",
                            tcp_server=True, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        sdk_server.interfaces.server.stop_server()


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'OPEN'})
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C559884')
def test_wifi_sdk_tcp_first_abort_then_upgrade_full_security_c559884(firmware_loader, wifi_client, sdk_server,
                                                                     wifi_access_point, wifi_dut, wifi_sniffer,
                                                                     sl_collections):
    """	Verify DUT Functionality with fw abort in 1st iteration and without abort do firmware update in 2nd iteration"""

    try:
        test_case = '559884'
        logger().info(f"***** Firmware file name: {sdk_server.interfaces.server.firmware_file_name} *****")
        wlan_obj = WifiJoin(http_server=sdk_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, rps_path=sdk_server.interfaces.server.firmware_file_name,
                            tcp_server=True, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        sdk_server.interfaces.server.stop_server()


@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'OPEN'})
@pytest.mark.config("sdk_server", server={"firmware_file_name": "combined_SiWG917-B.2.14.5.0.0.2_wrong_header.rps"})
@pytest.mark.firmware_app("firmware_security_encrypted_1")
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C510714')
def test_wifi_sdk_tcp_combine_image_wrong_header_c510714(firmware_loader, wifi_client, sdk_server,
                                                         wifi_access_point, wifi_dut, wifi_sniffer,
                                                         sl_collections):
    """Verify DUT functionality with combined(TA+M4) image wrong header format"""

    try:
        test_case = '510714'
        logger().info(f"***** Firmware file name: {sdk_server.interfaces.server.firmware_file_name} *****")
        wlan_obj = WifiJoin(http_server=sdk_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, rps_path=sdk_server.interfaces.server.firmware_file_name,
                            tcp_server=True, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        sdk_server.interfaces.server.stop_server()
