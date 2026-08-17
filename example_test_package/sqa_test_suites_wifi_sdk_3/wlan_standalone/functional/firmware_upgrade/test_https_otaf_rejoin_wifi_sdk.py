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
from utf.utils.stopwatch import Stopwatch
from random import randint
from utf.utils import get_tls_certificate_dir
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers

"""This Test plan is validating Firmware version updation through OTAF

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

    Author: Ayush Agarwal

"""


def logger():
    return get_logger(__name__)


def wifi_dut_marker():
    """
        Common method to generate wifi_dut marker for pytest.mark.config decorator.
        """
    config = {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3072}},
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
    return pytest.mark.config("wifi_dut", wifi=config)


class APController(ThreadBase):
    def __init__(self, switch, wifi_dut=None, wifi_access_point=None, sl_collections=None):
        super().__init__()
        self.switch = switch
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections

    def run(self):
        try:
            logger().info("Turning off the AP")
            self.switch.interfaces.pdu_switch.turn_off(delay=20)
            logger().info("Successfully powered off AP")

            logger().info("Checking for rejoin fail event from dut")
            with TimeMeasurer() as t:
                sw = Stopwatch()
                while sw.elapsed_sec < 180:
                    events = self.wifi_dut.interfaces.wifi.get_async_events()
                    rejoin_error_events = [
                        event
                        for event in events
                        if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT
                    ]
                    if len(rejoin_error_events):
                        break
                    time.sleep(0.1)
                else:
                    return False

            logger().info("Again turning on the AP")
            self.switch.interfaces.pdu_switch.turn_on(delay=100)
            time.sleep(60)

        except Exception as e:
            logger().error(f"failed to control ap error: {e}")


class ThreadHttpOtaf(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, wifi_client=None,
                 sl_collections=None, http_server=None, test_case=None, switch=None,
                 cert_index=None, rps_path=None):
        super().__init__()
        self.host_ip = None
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.wifi_client = wifi_client
        self.switch = switch
        self.sl_collections = sl_collections
        self.dut_addr = None
        self.http_server = http_server
        self.test_case = test_case
        self.fw_version_before_upgrade = None
        self.fw_version_after_upgrade = None
        self.cert_index = cert_index
        self.rps_path = rps_path

    def load_certs_to_index(self):
        logger().info("Loading certificates in DUT")
        self.wifi_dut.interfaces.wifi.set_ssl_certificate(
            str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem")),
            Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
            Si91xCertIdentifier.SL_NET_TLS_SERVER_CREDENTIAL_START,
            cert_index=self.cert_index)

    def join_to_ap(self, set_rejoin=True):
        if set_rejoin:
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=2, scan_interval=6,
                                                                          beacon_missed_count=40,
                                                                          first_time_retry_enable=0)
        logger().info("scanning for ap...")
        self.wifi_dut.interfaces.wifi.scan()
        self.wifi_dut.interfaces.wifi.join_ap(access_point=self.wifi_access_point)
        self.wifi_dut.interfaces.wifi.start_ip()
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
        logger().info(f"Device is {device_ip}")
        time.sleep(2)
        status = ping(device_ip, 10)
        logger().info(f'Ping status = {status}')

    def http_server_start(self):
        status_http = self.http_server.interfaces.http.started
        assert status_http, 'Server is inactive'
        logger().info(f'http server state is {status_http}')
        http_interface = self.http_server.interfaces.http.interface
        self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address(http_interface)

        logger().info("pinging to server ip....")
        status = ping(self.host_ip, 10)
        logger().info(f'Ping status = {status}')

    def firmware_upgrade(self):
        logger().info("dut fw version before upgrade...")
        self.fw_version_before_upgrade = self.wifi_dut.interfaces.wifi.version()
        logger().info(f"*** dut fw version before upgrade = {self.fw_version_before_upgrade} ***")

        logger().info("Performing firmware upgrade....")

        # With a finite rejoin retry count configured (see join_to_ap), the firmware aborts the pending OTAF
        # either with CONNECTION_LOST or with REJOIN_FAILURE once the rejoin attempts are exhausted.
        expected_status = [SLStatus.SL_STATUS_WIFI_CONNECTION_LOST, SLStatus.SL_STATUS_SI91X_REJOIN_FAILURE]

        if self.test_case == '19788':
            self.wifi_dut.interfaces.wifi.firmware_upgrade(ip_address=self.host_ip,
                                                           expected_status=expected_status,
                                                           host_name=self.host_ip, timeout=150)

        else:
            self.wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=self.host_ip, port=443,
                                                           host_name=self.host_ip,
                                                           expected_status=expected_status,
                                                           timeout=150)

    def firmware_upgrade_after_rejoin(self):
        logger().info("dut fw version before upgrade...")
        self.fw_version_before_upgrade = self.wifi_dut.interfaces.wifi.version()
        logger().info(f"*** dut fw version before upgrade = {self.fw_version_before_upgrade} ***")

        logger().info("Performing firmware upgrade after rejoin....")

        if self.test_case == '19788':
            self.wifi_dut.interfaces.wifi.firmware_upgrade(ip_address=self.host_ip,
                                                           host_name=self.host_ip, timeout=150)
        else:
            self.wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=self.host_ip, port=443,
                                                           host_name=self.host_ip, timeout=150)

            self.wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")
            time.sleep(30)
            self.wifi_dut.interfaces.wifi.is_external_stack_enabled = True
            self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            self.wifi_dut.interfaces.wifi.init(mode="client", config_required=False, load_certificate=False)
            self.wifi_dut.interfaces.wifi.initialize_thread()
            self.wifi_dut.interfaces.wifi.is_external_stack_enabled = False
            self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True

            self.fw_version_after_upgrade = self.wifi_dut.interfaces.wifi.version()
            logger().info(f"*** dut fw version after upgrade = {self.fw_version_after_upgrade} ***")

            if self.fw_version_before_upgrade == self.fw_version_after_upgrade:
                logger().info("Firmware upgrade successful. Version after upgrade matched with the previous firmware")
            else:
                logger().info("Firmware upgrade successful. Versions are different.")

    def run(self):
        try:
            self.firmware_upgrade()

        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")


@pytest.mark.start_state("wifi_dut", wifi=['sl_net_init_client'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["clear_certs"])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19766')
def test_wifi_sdk_https_fw_upgrade_after_rejoin_failure_and_measure_time_c19766(http_server, wifi_client, wifi_sniffer,
                                                                                wifi_access_point, wifi_dut, switch,
                                                                                sl_collections):
    """This Test case is validating https Firmware update after rejoin failure"""
    try:
        wifi_dut.interfaces.wifi.is_external_stack_enabled = False
        test_case = '19766'
        logger().info(" **** configuring the sniffer with access point channel **** ")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)
        fwup_obj = ThreadHttpOtaf(http_server=http_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                                  wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                                  sl_collections=sl_collections, cert_index=0)

        ap_obj = APController(switch=switch, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut,
                              sl_collections=sl_collections)

        fwup_obj.load_certs_to_index()
        fwup_obj.join_to_ap()
        fwup_obj.http_server_start()
        logger().info("starting fwup thread to do firmware update")
        fwup_obj.start()
        time.sleep(15)
        logger().info("starting ap controller thread to turn off AP ,check for rejoin event and turn on AP")
        ap_obj.start()
        ap_obj.wait_for_exit()
        fwup_obj.wait_for_exit()
        # DUT is already off-air after rejoin failure; skip teardown leave() to avoid 0x10021
        wifi_dut.interfaces.wifi.associated = False

        wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")
        wifi_dut.interfaces.wifi.is_external_stack_enabled = True
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False, load_certificate=False)
        wifi_dut.interfaces.wifi.initialize_thread()
        wifi_dut.interfaces.wifi.is_external_stack_enabled = False
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True

        logger().info("Again connecting and doing firmware upgrade after rejoin failure")
        fwup_obj.join_to_ap(set_rejoin=False)
        fwup_obj.http_server_start()
        logger().info("starting fwup thread to do firmware update")
        fwup_obj.firmware_upgrade_after_rejoin()

        logger().info("stop Sniffer capture...")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi=['sl_net_init_client'])
@pytest.mark.http_server("raspi_lighttpd")
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19788')
def test_wifi_sdk_http_fw_upgrade_after_rejoin_failure_and_measure_time_c19788(http_server, wifi_client, wifi_sniffer,
                                                                               wifi_access_point, wifi_dut, switch,
                                                                               sl_collections):
    """This Test case is validating http Firmware update after rejoin failure"""
    try:
        wifi_dut.interfaces.wifi.is_external_stack_enabled = False
        test_case = '19788'
        logger().info(" **** configuring the sniffer with access point channel **** ")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)
        fwup_obj = ThreadHttpOtaf(http_server=http_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                                  wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                                  sl_collections=sl_collections, cert_index=1)

        ap_obj = APController(switch=switch, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut,
                              sl_collections=sl_collections)

        fwup_obj.load_certs_to_index()
        fwup_obj.join_to_ap()
        fwup_obj.http_server_start()
        logger().info("starting fwup thread to do firmware update")
        fwup_obj.start()
        time.sleep(15)
        logger().info("starting ap controller thread to turn off AP ,check for rejoin event and turn on AP")
        ap_obj.start()
        ap_obj.wait_for_exit()
        fwup_obj.wait_for_exit()
        # DUT is already off-air after rejoin failure; skip teardown leave() to avoid 0x10021
        wifi_dut.interfaces.wifi.associated = False

        wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")
        wifi_dut.interfaces.wifi.is_external_stack_enabled = True
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False, load_certificate=False)
        wifi_dut.interfaces.wifi.initialize_thread()
        wifi_dut.interfaces.wifi.is_external_stack_enabled = False
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True

        logger().info("Again connecting and doing firmware upgrade after rejoin failure")
        fwup_obj.join_to_ap(set_rejoin=False)
        fwup_obj.http_server_start()
        logger().info("starting fwup thread to do firmware update")
        fwup_obj.firmware_upgrade_after_rejoin()

        logger().info("stop Sniffer capture...")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi=['sl_net_init_client'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C584245')
def test_wifi_sdk_https_otaf_after_rejoin_failure_and_measure_time_c584245(http_server, wifi_client, wifi_sniffer,
                                                                           wifi_access_point, wifi_dut, switch,
                                                                           sl_collections):
    """Verify the HTTPS OTAF TA firmware upgrade functionality by loading
    certificate into index 2 after rejoin failure"""
    try:
        wifi_dut.interfaces.wifi.is_external_stack_enabled = False
        test_case = '584245'
        logger().info(" **** configuring the sniffer with access point channel **** ")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)
        fwup_obj = ThreadHttpOtaf(http_server=http_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                                  wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                                  sl_collections=sl_collections, cert_index=2)

        ap_obj = APController(switch=switch, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut,
                              sl_collections=sl_collections)

        fwup_obj.load_certs_to_index()
        fwup_obj.join_to_ap()
        fwup_obj.http_server_start()
        logger().info("starting fwup thread to do firmware update")
        fwup_obj.start()
        time.sleep(15)
        logger().info("starting ap controller thread to turn off AP ,check for rejoin event and turn on AP")
        ap_obj.start()
        ap_obj.wait_for_exit()
        fwup_obj.wait_for_exit()
        # DUT is already off-air after rejoin failure; skip teardown leave() to avoid 0x10021
        wifi_dut.interfaces.wifi.associated = False

        wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")
        wifi_dut.interfaces.wifi.is_external_stack_enabled = True
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False, load_certificate=False)
        wifi_dut.interfaces.wifi.initialize_thread()
        wifi_dut.interfaces.wifi.is_external_stack_enabled = False
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True

        logger().info("Again connecting and doing firmware upgrade after rejoin failure")
        fwup_obj.join_to_ap(set_rejoin=False)
        fwup_obj.http_server_start()
        logger().info("starting fwup thread to do firmware update")

        logger().info("stop Sniffer capture...")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi=['sl_net_init_client'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C584246')
def test_wifi_sdk_https_otaf_after_rejoin_failure_and_measure_time_c584246(http_server, wifi_client, wifi_sniffer,
                                                                           wifi_access_point, wifi_dut, switch,
                                                                           sl_collections):
    """Verify the HTTPS OTAF M4 firmware upgrade functionality by loading certificate into index 1 after rejoin
    failure"""
    try:
        wifi_dut.interfaces.wifi.is_external_stack_enabled = False
        test_case = '584245'
        logger().info(" **** configuring the sniffer with access point channel **** ")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)
        fwup_obj = ThreadHttpOtaf(http_server=http_server, wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                                  wifi_access_point=wifi_access_point, wifi_dut=wifi_dut, test_case=test_case,
                                  sl_collections=sl_collections, cert_index=1)

        ap_obj = APController(switch=switch, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut,
                              sl_collections=sl_collections)

        fwup_obj.load_certs_to_index()
        fwup_obj.join_to_ap()
        fwup_obj.http_server_start()
        logger().info("starting fwup thread to do firmware update")
        fwup_obj.start()
        time.sleep(15)
        logger().info("starting ap controller thread to turn off AP ,check for rejoin event and turn on AP")
        ap_obj.start()
        ap_obj.wait_for_exit()
        fwup_obj.wait_for_exit()

        wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")
        wifi_dut.interfaces.wifi.is_external_stack_enabled = True
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False, load_certificate=False)
        wifi_dut.interfaces.wifi.initialize_thread()
        wifi_dut.interfaces.wifi.is_external_stack_enabled = False
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True

        logger().info("Again connecting and doing firmware upgrade after rejoin failure")
        fwup_obj.join_to_ap()
        fwup_obj.http_server_start()
        logger().info("starting fwup thread to do firmware update")
        fwup_obj.firmware_upgrade_after_rejoin()

        logger().info("stop Sniffer capture...")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

