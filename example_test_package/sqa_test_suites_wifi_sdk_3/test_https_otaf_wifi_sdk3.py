from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils.iperf.iperf_utils import print_dict
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.wifi import WlanError

"""This function runs below test steps for DUT-Si91x
        1. Configuration of DUT in 2G : BGN
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        6. Enable the power save mode in DUT
        7. Stop the sniffer
        8. Validating Add-ba request from AP/DUT
        9. Validating Add-ba response from AP/DUT 

    setup requirement:
        1. soc board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

"""


def logger():
    return get_logger(__name__)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, net_perf_client=None, wifi_client=None,
                 protocol=None, capture_filename=None, sl_collections=None, http_server=None, test_case_no=None, switch = None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.switch = switch
        self.protocol = protocol
        self.capture_filename = capture_filename
        self.sl_collections = sl_collections
        self.dut_addr = None
        self.http_server = http_server
        self.test_case_no = test_case_no
    def get_firmware_status(self):

        self.wifi_dut.interfaces.wifi.wireless_deinit(timeout=60)
        time.sleep(10)

        logger().info("Initialising DUT after the reset....")
        self.wifi_dut.interfaces.wifi.inited = False
        self.wifi_dut.interfaces.wifi.init(reset_type="rs911x")

        self.wifi_dut.interfaces.wifi.associated = False

        fw_after_upgrade = self.wifi_dut.interfaces.wifi.version()
        time.sleep(2)
        return fw_after_upgrade


    def run(self):
        try:
            """ ******* SERVER CHECKS ******* """
            logger().info("checking server stats....")
            server_stat = self.http_server.interfaces.http.started
            assert server_stat == True, "server is inactive"
            logger().info(f'http server state is {server_stat}')
            logger().info("fetching server ip....")
            host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"server ip is {host_ip}")

            logger().info("pinging to server ip....")
            status = ping(host_ip, 10)
            assert status == 1, "failed to ping to server"
            if self.test_case_no == 19757:
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Performing firmware upgrade....")
                    self.wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)
                    time.sleep(20)
                assert exc_info.value.error_code == 0x0021, "observed wrong error code expected is 0x0021"
                return()
            logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
            logger().info("dut fw version before upgrade...")
            fw_before_upgrade = self.wifi_dut.interfaces.wifi.version()
            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated)
            start_time = time.perf_counter_ns()
            async_timestamp = 0
            time.sleep(2)


            if self.test_case_no == 19774:
                with pytest.raises(WlanError) as exc_info:
                    logger().info("performing fw upgrade on dut....")
                    self.wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4.rps")
                assert exc_info.value.error_code == 0x21, "observed wrong error code expected is 0x21"
                self.get_firmware_status()
            if self.test_case_no == 19773:
                logger().info("performing fw upgrade on dut non rps ...")
                self.wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/cgi-bin/cgi_example.py")
                time.sleep(100)
                with pytest.raises(WlanError) as exc_info:
                    self.wifi_dut.interfaces.wifi.get_http_otaf_status()
                assert exc_info.value.error_code == 0xFFFD, "observed wrong error code expected is 0xfffd"
                self.get_firmware_status()

            if self.test_case_no == 19778:
                logger().info("performing fw upgrade on dut with empty rps file....")
                self.wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4_empty.rps")
                time.sleep(30)
                with pytest.raises(WlanError) as exc_info:
                    logger().info("fetching otaf status...")
                    self.wifi_dut.interfaces.wifi.get_http_otaf_status()
                assert exc_info.value.error_code == 0xFFF9, "observed wrong error code expected is 0xFFF9"
                self.get_firmware_status()
            if self.test_case_no == 19772:
                self.wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4_corrupted_remove.rps")
                time.sleep(100)
                with pytest.raises(WlanError) as exc_info:
                    self.wifi_dut.interfaces.wifi.get_http_otaf_status()
                assert exc_info.value.error_code == 0xFFFD, "observed wrong error code expected is 0xFFFD"

                logger().info("performing fw upgrade on dut by adding some content to  rps....")
                self.wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4_corrupted_add.rps")
                time.sleep(100)
                with pytest.raises(WlanError) as exc_info:
                    self.wifi_dut.interfaces.wifi.get_http_otaf_status()
                assert exc_info.value.error_code == 0xBB41, "observed wrong error code expected is 0xBB41"
                self.get_firmware_status()

            if self.test_case_no == 19776 or 19775:
                logger().info("performing fw upgrade on dut by removing data in .xls file....")
                self.wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "RS9116.2.5.0.4_remove.xls")

                time.sleep(120)
                with pytest.raises(WlanError) as exc_info:
                    self.wifi_dut.interfaces.wifi.get_http_otaf_status()
                assert exc_info.value.error_code == 0xFFFD, "observed wrong error code expected is 0xFFFD"

                logger().info("performing fw upgrade on dut by adding data in .xls file....")
                self.wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "RS9116.2.5.0.4_add.xls")
                time.sleep(120)
                with pytest.raises(WlanError) as exc_info:
                    self.wifi_dut.interfaces.wifi.get_http_otaf_status()
                assert exc_info.value.error_code == 0xBB41, "observed wrong error code expected is 0xBB41"
                self.get_firmware_status()

            if self.test_case_no == 19777:
                logger().info("performing fw upgrade on dut....")
                self.wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4.rps")
                with pytest.raises(WlanError) as exc_info:
                    self.wifi_dut.interfaces.wifi.get_http_otaf_status()
                assert exc_info.value.error_code == 0xFF74, "observed wrong error code expected is 0xff74"
                time.sleep(3)
                self.get_firmware_status()
            if self.test_case_no == 19766:
                logger().info("performing fw upgrade on dut....")
                self.wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)
                logger().info("turning off Access point")
                self.switch.interfaces.pdu_switch.turn_off()
                time.sleep(5)
                logger().info("turning on Access point")
                self.switch.interfaces.pdu_switch.turn_on()
                self.get_firmware_status()

            else:
                logger().info("performing firmware upgrade....")
                self.wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)
                time.sleep(120)
                logger().info("fetching otaf status....")
                self.wifi_dut.interfaces.wifi.get_http_otaf_status()
                time.sleep(5)

                logger().info("fetching otaf async events after upgrade....")
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                if len(events):
                    for event in events:
                        if event.event_type == self.RS9116AsyncEventType.HTTP_OTAF_STATUS:
                            async_timestamp = event.timestamp

                if not async_timestamp:
                    logger().info(f"asynchronous message is not received after otaf over http")
                else:
                    time_duration = (async_timestamp - start_time) / 1000000000

                if time_duration > 40:
                    logger().warning(f"TOOK TOO LONG TIME TO DOWNLOAD FW {time_duration}")
                else:
                    logger().info(f"time taken to upgrade firmware using http otaf {time_duration} seconds")
                fw_after_upgrade=self.get_firmware_status()
                time.sleep(2)
                logger().info(f"\n\n ***firmware versions before otaf:{fw_before_upgrade}"
                              f" firmware version after loading through otaf :{fw_after_upgrade}")
                assert fw_before_upgrade != fw_after_upgrade, f"firmware versions should not match after loading" \
                                                              f" firmware through otaf"
                logger().info(f"\n ***firmware versions not matched after loading" \
                              f" firmware through otaf\n")
                logger().info("Stop Sniffer finally")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                time.sleep(10)
        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_sdk_https_fw_upgrade_in_STA_alone_mode_and_measure_time_C19758(http_server, wifi_sniffer, wifi_access_point,
                                                                wifi_dut,request,wifi_client, sl_collections, sniffer_filter):
    '''https firmware upgrade in sta mode'''
    capture_filename = request.node.name
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** Start get IP address ******")
        logger().info(f"ap mac is {ap_mac_address}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_dut.interfaces.wifi.load_certs(cert_type=5, cert_file="ca-cert.pem", cert_index=0, use_secure_element=0,
                                            net_interface="client", application_protocol="ssl")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename,
                            sl_collections=sl_collections, http_server=http_server)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)



@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_sdk_https_fw_upgrade_in_STA_alone_mode_and_measure_time_C19760(http_server, wifi_sniffer, wifi_access_point, wifi_dut, request,
                                               wifi_client, sl_collections, sniffer_filter):
    '''https firmware upgrade over the air when wlan + ble is enabled'''
    capture_filename = request.node.name
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap mac is {ap_mac_address}")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_dut.interfaces.wifi.load_certs(cert_type=5, cert_file="ca-cert.pem", cert_index=0, use_secure_element=0,
                                            net_interface="client", application_protocol="ssl")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client,capture_filename=capture_filename, sl_collections=sl_collections, http_server=http_server)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_sdk_https_fw_upgrade_failure_with_empty_rps_C19778(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                       request,wifi_client, sl_collections, sniffer_filter):
    '''https firmware upgrade whe nrps file is 0bytes'''
    capture_filename = request.node.name
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap mac is {ap_mac_address}")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_dut.interfaces.wifi.load_certs(cert_type=5, cert_file="ca-cert.pem", cert_index=0, use_secure_element=0,
                                            net_interface="client", application_protocol="ssl")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client,capture_filename=capture_filename, sl_collections=sl_collections,
                            http_server=http_server, test_case_no=19778)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,

    },
)
def test_sdk_https_fw_upgrade_failure_without_enabling_http_C19777(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                              request,wifi_client, sl_collections, sniffer_filter):
    capture_filename = request.node.name
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap mac is {ap_mac_address}")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_dut.interfaces.wifi.load_certs(cert_type=5, cert_file="ca-cert.pem", cert_index=0, use_secure_element=0,
                                            net_interface="client", application_protocol="ssl")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client,capture_filename=capture_filename, sl_collections=sl_collections,
                            http_server=http_server,test_case_no=19777)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_sdk_https_fw_upgrade_failure_when_STA_is_not_connected_C19757(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                              request,wifi_client, sl_collections, sniffer_filter):
    capture_filename = request.node.name
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap mac is {ap_mac_address}")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_dut.interfaces.wifi.load_certs(cert_type=5, cert_file="ca-cert.pem", cert_index=0, use_secure_element=0,
                                            net_interface="client", application_protocol="ssl")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                            http_server=http_server, test_case_no=19757)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_https_fw_upgrade_in_UART_mode_and_measure_time_C19767(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                              request,wifi_client, sl_collections, sniffer_filter):
    capture_filename = request.node.name
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap mac is {ap_mac_address}")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_dut.interfaces.wifi.load_certs(cert_type=5, cert_file="ca-cert.pem", cert_index=0, use_secure_element=0,
                                            net_interface="client", application_protocol="ssl")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                            http_server=http_server, test_case_no=19789)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_sdk_https_fw_upgrade_failure_with_non_rps_C19776(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                              request,wifi_client, sl_collections, sniffer_filter):
    capture_filename = request.node.name
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap mac is {ap_mac_address}")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_dut.interfaces.wifi.load_certs(cert_type=5, cert_file="ca-cert.pem", cert_index=0, use_secure_element=0,
                                            net_interface="client", application_protocol="ssl")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                            http_server=http_server, test_case_no=19776)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_https_fw_upgrade_failure_with_junk_rps_C19775(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                              request,wifi_client, sl_collections, sniffer_filter):
    capture_filename = request.node.name
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap mac is {ap_mac_address}")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_dut.interfaces.wifi.load_certs(cert_type=5, cert_file="ca-cert.pem", cert_index=0, use_secure_element=0,
                                            net_interface="client", application_protocol="ssl")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                            http_server=http_server, test_case_no=19775)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_sdk_https_fw_upgrade_failure_when_enabled_only_ble_C19774(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                              request,wifi_client, sl_collections, sniffer_filter):
    capture_filename = request.node.name
    try:
        logger().info(f"******** AP MAC ADD *******")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap mac is {ap_mac_address}")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip is {host_ip}")
        wifi_dut.interfaces.wifi.load_certs(cert_type=5, cert_file="ca-cert.pem", cert_index=0, use_secure_element=0,
                                            net_interface="client", application_protocol="ssl")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                            http_server=http_server, test_case_no=19774)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_https_fw_upgrade_over_night_C19771(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                           request,wifi_client, sl_collections, sniffer_filter,utf_constants):
    try:
        time_duration = utf_constants.get("time_duration")
        sw = Stopwatch()
        logger().info(f"Time duration is {time_duration} Mins")
        capture_filename = request.node.name
        while sw.elapsed_sec < time_duration:
            logger().info(f"******** AP MAC ADD *******")
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap mac is {ap_mac_address}")
            logger().info(f"***** Start get IP address ******")
            host_ip = wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"host ip is {host_ip}")
            wifi_dut.interfaces.wifi.load_certs(cert_type=5, cert_file="ca-cert.pem", cert_index=0,
                                                use_secure_element=0,
                                                net_interface="client", application_protocol="ssl")
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                                http_server=http_server, test_case_no=19793)
            wifi_obj.start()
            wifi_obj.wait_for_exit()

    except Exception as Ex:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_sdk_https_fw_upgrade_over_night_corrupted_file_C19772(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                           request,wifi_client, sl_collections, sniffer_filter, utf_constants):
    try:
        time_duration = utf_constants.get("time_duration")
        sw = Stopwatch()
        logger().info(f"Time duration is {time_duration} Mins")
        capture_filename = request.node.name
        while sw.elapsed_sec < time_duration:
            logger().info(f"******** AP MAC ADD *******")
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap mac is {ap_mac_address}")
            logger().info(f"***** Start get IP address ******")
            host_ip = wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"host ip is {host_ip}")
            wifi_dut.interfaces.wifi.load_certs(cert_type=5, cert_file="ca-cert.pem", cert_index=0,
                                                use_secure_element=0,
                                                net_interface="client", application_protocol="ssl")
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                                http_server=http_server, test_case_no=19772)
            wifi_obj.start()
            wifi_obj.wait_for_exit()

    except Exception as Ex:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_sdk_https_fw_upgrade_over_night_corrupted_file_C19773(http_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                           request,wifi_client, sl_collections, sniffer_filter, utf_constants):
    try:
        time_duration = utf_constants.get("time_duration")
        sw = Stopwatch()
        logger().info(f"Time duration is {time_duration} Mins")
        capture_filename = request.node.name
        while sw.elapsed_sec < time_duration:
            logger().info(f"******** AP MAC ADD *******")
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap mac is {ap_mac_address}")
            logger().info(f"***** Start get IP address ******")
            host_ip = wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"host ip is {host_ip}")
            wifi_dut.interfaces.wifi.load_certs(cert_type=5, cert_file="ca-cert.pem", cert_index=0,
                                                use_secure_element=0,
                                                net_interface="client", application_protocol="ssl")
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                                http_server=http_server, test_case_no=19773)
            wifi_obj.start()
            wifi_obj.wait_for_exit()

    except Exception as Ex:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)

#########Rejoin###

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "load_default_fw"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | Si91xTCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF | Si91xExtTCPIPFeatureBitMap.Default

    },
)
def test_sdk_https_fw_upgrade_rejoin_process_C19766(http_server, switch, wifi_sniffer, wifi_access_point, wifi_dut,
                                           request,wifi_client, sl_collections, sniffer_filter, utf_constants):
    try:
        time_duration = utf_constants.get("time_duration")
        sw = Stopwatch()
        logger().info(f"Time duration is {time_duration} Mins")
        capture_filename = request.node.name
        while sw.elapsed_sec < time_duration:
            logger().info(f"******** AP MAC ADD *******")
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap mac is {ap_mac_address}")
            logger().info(f"***** Start get IP address ******")
            host_ip = wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"host ip is {host_ip}")
            wifi_dut.interfaces.wifi.load_certs(cert_type=5, cert_file="ca-cert.pem", cert_index=0,
                                                use_secure_element=0,
                                                net_interface="client", application_protocol="ssl")
            wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                          beacon_missed_count=40,
                                                                          first_time_retry_enable=0)
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                wifi_client=wifi_client, capture_filename=capture_filename, sl_collections=sl_collections,
                                http_server=http_server, test_case_no=19766, switch=switch)
            wifi_obj.start()
            wifi_obj.wait_for_exit()

    except Exception as Ex:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=Ex)
    finally:
        logger().info("****** Access point is going to turn on  ******")
        switch.interfaces.pdu_switch.turn_on(delay=20)






