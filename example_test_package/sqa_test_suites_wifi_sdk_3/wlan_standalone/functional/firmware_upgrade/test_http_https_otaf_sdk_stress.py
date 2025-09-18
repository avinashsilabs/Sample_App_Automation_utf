from utf.utils import print_dict
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xBTFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xOperatingMode
import time
import pytest
import datetime
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.wifi import WlanError
from utf_wiseconnect_3.tests.sl_status import SLStatus

"""This function runs below test steps for DUT-Si91x
        1. Configuration of DUT in 2G : BGN
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        7. Stop the sniffer
 

    setup requirement:
        1. soc board
        2. Raspberry PI4 and (lighttpd server)
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)
        

    Author: Shobha Rani Jogu
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
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    return pytest.mark.config("wifi_dut", wifi=config)


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, wifi_client=None,
                 capture_filename=None, sl_collections=None, http_server=None, test_case_no=None,
                 rps_path=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.wifi_client = wifi_client
        self.capture_filename = capture_filename
        self.sl_collections = sl_collections
        self.dut_addr = None
        self.http_server = http_server
        self.test_case_no = test_case_no
        self.rps_path = rps_path
        self.fw_before_upgrade = None
        self.fw_after_upgrade = None

    def get_firmware_status(self):
        self.wifi_dut.interfaces.wifi.reset()
        time.sleep(30)
        logger().info("Initialising DUT after the reset....")
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        self.wifi_dut.interfaces.wifi.init(load_certificate=False)
        self.wifi_dut.interfaces.wifi.initialize_thread()
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        fw_after_upgrade = self.wifi_dut.interfaces.wifi.version()
        self.wifi_dut.interfaces.wifi.inited = False
        time.sleep(5)
        return fw_after_upgrade

    def run(self):
        try:
            """ ******* SERVER CHECKS ******* """
            logger().info("checking server stats....")
            server_stat = self.http_server.interfaces.http.started
            assert server_stat == True, "server is inactive"
            logger().info(f'http server state is {server_stat}')
            logger().info("fetching server ip....")
            host_ip = self.http_server.interfaces.http.hostname_or_ip_address
            logger().info(f"server ip is {host_ip}")
            logger().info("pinging to server ip....")
            status = ping(host_ip, 10)
            assert status == 1, "failed to ping to server"

            logger().info(f"******** AP MAC address *******")
            ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap mac is {ap_mac_address}")
            logger().info(f"***** STA get IP address ******")
            dut_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"host ip is {dut_ip}")

            logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
            logger().info("dut fw version before upgrade...")
            fw_before_upgrade = self.wifi_dut.interfaces.wifi.version()
            logger().info(f" ***** FW before upgrade: {fw_before_upgrade} *****")

            logger().info("join WIFI network...")
            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                     retry_count=3,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     power_save=False)
            time.sleep(2)
            start_time = time.time()
            logger().info(f" start firmware upgrade: {start_time}")

            if self.test_case_no == 19793:
                logger().info("performing fw upgrade on dut ....")
                self.wifi_dut.interfaces.wifi.firmware_upgrade(ip_address=host_ip,
                                                               host_name=host_ip)
                time.sleep(5)

                self.get_firmware_status()
                logger().info("performing fw downgrade on dut...")
                logger().info("join WIFI network...")
                self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                         retry_count=3,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         power_save=False)
                self.wifi_dut.interfaces.wifi.firmware_upgrade(ip_address=host_ip, http_url=self.rps_path,
                                                               host_name=host_ip)

            if self.test_case_no == 19794:
                logger().info("performing fw upgrade on dut non rps....")
                self.wifi_dut.interfaces.wifi.firmware_upgrade(ip_address=host_ip,
                                                               host_name=host_ip, http_url='/ReleaseNotes.pdf',
                                                               expected_status=SLStatus.SL_STATUS_SI91X_CORRUPTED_RPS_HEADER)

            if self.test_case_no == 19795:
                logger().info("performing fw upgrade on dut non rps....")
                self.wifi_dut.interfaces.wifi.firmware_upgrade(ip_address=host_ip,
                                                               host_name=host_ip,
                                                               http_url='/SiWG917-B.2.13.3.0.0.5_corrupt_add.rps',
                                                               expected_status=SLStatus.SL_STATUS_SI91X_INVALID_LENGTH)

            if self.test_case_no == 19771:
                logger().info("performing fw upgrade on dut ....")
                self.wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=host_ip, port=443,
                                                               host_name=host_ip)
                time.sleep(5)

                self.get_firmware_status()
                logger().info("performing fw downgrade on dut...")
                logger().info("join WIFI network...")
                self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                         retry_count=3,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         power_save=False)
                self.wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=host_ip, port=443, http_url=self.rps_path,
                                                               host_name=host_ip)
            if self.test_case_no == 19772:
                logger().info("performing fw upgrade on dut non rps....")
                self.wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=host_ip, port=443, host_name=host_ip,
                                                               http_url='/SiWG917-B.2.13.3.0.0.5_corrupt_remove.rps',
                                                               expected_status=SLStatus.SL_STATUS_SI91X_HTTP_OTAF_INVALID_PACKET)

            if self.test_case_no == 19773:
                logger().info("performing fw upgrade on dut non rps....")
                self.wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=host_ip, port=443,
                                                               host_name=host_ip, http_url='/text_file.txt',
                                                               expected_status=SLStatus.SL_STATUS_SI91X_CORRUPTED_RPS_HEADER)

            finish_time = time.time()
            logger().info(f"firmware upgraded : {finish_time}")
            time_duration = (finish_time - start_time)
            logger().info(f"Time taken to upgrade firmware is: {time_duration}")
            logger().info("Stop Sniffer finally")
            self.wifi_sniffer.interfaces.capture.stop_capture()
            fw_after_upgrade = self.get_firmware_status()
            time.sleep(2)
            logger().info(f"\n\n ***firmware versions before otaf:{fw_before_upgrade}"
                          f" firmware version after loading through otaf :{fw_after_upgrade}")
            if self.fw_before_upgrade == self.fw_after_upgrade:
                logger().info("Firmware after upgrade matched with the previous firmware")
            else:
                logger().info("Firmware upgrade successful. Versions are different.")

        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
            raise e


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@wifi_dut_marker()
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.legacy_deployed
def test_http_fw_upgrade_downgrade_overnight_c19793(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                    request, wifi_client, sl_collections, utf_constants):
    try:
        rps_path = utf_constants.get("rps_filename")
        long_duration = utf_constants.get("long_duration")
        sw = Stopwatch()
        logger().info(f"Time duration is {long_duration} secs")
        capture_filename = request.node.name
        while sw.elapsed_sec < long_duration:
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                wifi_client=wifi_client, capture_filename=capture_filename,
                                sl_collections=sl_collections,
                                http_server=http_server, test_case_no=19793, rps_path=rps_path)
            wifi_obj.start()
            wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@wifi_dut_marker()
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.legacy_deployed
def test_http_fw_upgrade_overnight_corrupted_file_c19794(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                         request, wifi_client, sl_collections, utf_constants):
    try:
        long_duration = utf_constants.get("long_duration")
        sw = Stopwatch()
        logger().info(f"Time duration is {long_duration} secs")
        capture_filename = request.node.name
        while sw.elapsed_sec < long_duration:
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                wifi_client=wifi_client, capture_filename=capture_filename,
                                sl_collections=sl_collections,
                                http_server=http_server, test_case_no=19794)
            wifi_obj.start()
            wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@wifi_dut_marker()
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.legacy_deployed
def test_http_fw_upgrade_overnight_corrupted_file_c19795(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                         request, wifi_client, sl_collections, utf_constants):
    try:
        long_duration = utf_constants.get("long_duration")
        sw = Stopwatch()
        logger().info(f"Time duration is {long_duration} secs")
        capture_filename = request.node.name
        while sw.elapsed_sec < long_duration:
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                wifi_client=wifi_client, capture_filename=capture_filename,
                                sl_collections=sl_collections,
                                http_server=http_server, test_case_no=19795)
            wifi_obj.start()
            wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@wifi_dut_marker(ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.legacy_deployed
def test_https_fw_upgrade_downgrade_overnight_file_c19771(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                          request, wifi_client, sl_collections, utf_constants):
    try:
        rps_path = utf_constants.get("rps_filename")
        long_duration = utf_constants.get("long_duration")
        sw = Stopwatch()
        logger().info(f"Time duration is {long_duration} secs")
        capture_filename = request.node.name
        while sw.elapsed_sec < long_duration:
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                wifi_client=wifi_client, capture_filename=capture_filename,
                                sl_collections=sl_collections, rps_path=rps_path,
                                http_server=http_server, test_case_no=19771)
            wifi_obj.start()
            wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@wifi_dut_marker(ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.legacy_deployed
def test_https_fw_upgrade_overnight_corrupted_rps_file_c19772(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                              request, wifi_client, sl_collections, utf_constants):
    try:
        rps_path = utf_constants.get("rps_filename")
        long_duration = utf_constants.get("long_duration")
        sw = Stopwatch()
        logger().info(f"Time duration is {long_duration} secs")
        capture_filename = request.node.name
        while sw.elapsed_sec < long_duration:
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                wifi_client=wifi_client, capture_filename=capture_filename,
                                sl_collections=sl_collections, rps_path=rps_path,
                                http_server=http_server, test_case_no=19772)
            wifi_obj.start()
            wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@wifi_dut_marker(ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.legacy_deployed
def test_https_fw_upgrade_overnight_corrupted_text_file_c19773(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                               request, wifi_client, sl_collections, utf_constants):
    try:
        rps_path = utf_constants.get("rps_filename")
        long_duration = utf_constants.get("long_duration")
        sw = Stopwatch()
        logger().info(f"Time duration is {long_duration} secs")
        capture_filename = request.node.name
        while sw.elapsed_sec < long_duration:
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                wifi_client=wifi_client, capture_filename=capture_filename,
                                sl_collections=sl_collections, rps_path=rps_path,
                                http_server=http_server, test_case_no=19773)
            wifi_obj.start()
            wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
