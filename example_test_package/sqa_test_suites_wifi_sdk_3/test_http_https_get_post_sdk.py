import time
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
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers


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
        4. Initiate http get for http content
"""


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, http_client=None,
                 test_name=None, sl_collections=None, http_server=None, index_path=None, sniffer_filter=None, switch=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.http_server = http_server
        self.test_name = test_name
        self.index_path = index_path
        self.http_client = http_client
        self.sniffer_filter = sniffer_filter
        self.power_save_filter = None
        self.dut_addr = None
        self.ap_mac_address = None
        self.switch = switch

    def run(self):
        try:
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            if self.test_name == '476930' or self.test_name == '476938' or self.test_name == '476939':
                for i in range(0, 5):
                    logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel)
                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    time.sleep(3)

                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             channel=self.wifi_access_point.interfaces.wifi.channel)

                    self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                    self.wifi_dut.interfaces.wifi.http_client_init(https_enable=False)
                    logger().info("\n\n***Fetching the data on https using get method***\n\n")
                    if self.test_name == '476938':
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(
                            self.http_server.interfaces.http,
                            self.index_path,
                            server_port=80,
                            expected_status=SLStatus.SL_STATUS_HAS_OVERFLOWED)

                    elif self.test_name == '476939':
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(
                            self.http_server.interfaces.http,
                            self.index_path,
                            server_port=80,
                            expected_status=SLStatus.SL_STATUS_SI91X_ERROR_IN_LEN_OF_THE_COMMAND)

                    else:
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(
                            self.http_server.interfaces.http,
                            self.index_path,
                            server_port=80)
                        status_client, content_client = self.http_client.interfaces.http.http_get(
                            self.http_server.interfaces.http, self.index_path)

                        assert not status_dut, "failed to fetch the https data"
                        assert status_client, "failed to load the https data"

                        logger().info(status_dut)
                        logger().info(content_dut)
                        assert content_dut == content_client, "fetched data is not same as expected data"
                        self.wifi_dut.interfaces.wifi.http_client_deinit()

                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    time.sleep(5)
                    self.wifi_dut.interfaces.wifi.leave()

                    self.power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                        packet_filter1=self.power_save_filter)['packet_count'] > 0, \
                        "Unable to find NULL-Data frame packets with power save bit = 1"
                return

            if self.test_name == '476932':
                try:
                    for i in range(0, 5):
                        logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
                        self.wifi_sniffer.interfaces.capture.configure_interface(
                            channel=self.wifi_access_point.interfaces.wifi.channel)
                        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                        time.sleep(3)

                        self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                                wifi_access_point=self.wifi_access_point,
                                                                                eap_type="tls",
                                                                                ping_after_power_save=False,
                                                                                channel=self.wifi_access_point.interfaces.wifi.channel)
                        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                        self.wifi_dut.interfaces.wifi.http_client_init(https_enable=False)
                        logger().info("\n\n***Fetching the data on https using get method***\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(
                            self.http_server.interfaces.http,
                            self.index_path,
                            server_port=80)
                        status_client, content_client = self.http_client.interfaces.http.http_get(
                            self.http_server.interfaces.http, self.index_path)

                        assert not status_dut, "failed to fetch the https data"
                        assert status_client, "failed to load the https data"

                        logger().info(status_dut)
                        logger().info(content_dut)
                        assert content_dut == content_client, "fetched data is not same as expected data"

                        logger().info("Stopping sniffer capture")
                        self.wifi_sniffer.interfaces.capture.stop_capture()
                        self.wifi_dut.interfaces.wifi.http_client_deinit()
                        time.sleep(5)
                        self.wifi_dut.interfaces.wifi.leave()

                        self.power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                            sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                            filter_name="power_mgmt_bit")
                        assert \
                            self.wifi_sniffer.interfaces.capture.sniffer_validation(
                                packet_filter1=self.power_save_filter)[
                                'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"
                    return
                except Exception as e:
                    logger().info(f"\n\n **** Got exception in test case {self.test_name} thread: {str(e)} ****\n\n")
                    raise e

            if self.test_name == '476966':
                try:
                    logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel)
                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    time.sleep(3)

                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             channel=self.wifi_access_point.interfaces.wifi.channel)
                    power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")

                    time.sleep(5)
                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

                    for i in range(0, 5):
                        logger().info(f"\n\n***Fetching the data on https using get method iteration = {i} ***\n\n")
                        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                        self.wifi_dut.interfaces.wifi.http_client_init(https_enable=True)

                        for url in self.index_path:
                            logger().info("\n\n***Fetching the data on https using get method***\n\n")
                            status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http,
                                                                                             url,
                                                                                             server_port=443)
                            status_client, content_client = self.http_client.interfaces.http.http_get(
                                self.http_server.interfaces.http, url)

                            assert not status_dut, "failed to fetch the https data"
                            assert status_client, "failed to load the https data"

                            logger().info(status_dut)
                            logger().info(content_dut)
                            assert content_dut == content_client, "fetched data is not same as expected data"
                        self.wifi_dut.interfaces.wifi.http_client_deinit()
                        time.sleep(5)
                    time.sleep(5)
                    self.wifi_dut.interfaces.wifi.leave()
                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                except Exception as e:
                    logger().info(f"\n\n **** Got exception in test case {self.test_name} thread: {str(e)} ****\n\n")
                    raise e
                return

            if self.test_name == '537883':
                try:
                    logger().info('\n*** Configuring Sniffer channel ***\n')
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel)
                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    time.sleep(3)

                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, power_save=True,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             channel=self.wifi_access_point.interfaces.wifi.channel,
                                                                             )
                    power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")

                    time.sleep(5)
                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    for i in range(0, 5):
                        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                        self.wifi_dut.interfaces.wifi.http_client_init(https_enable=True)

                        logger().info(f"\n\n***Posting data using http post request for iteration = {i} ***\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_post(
                            self.http_server.interfaces.http,
                            self.index_path,
                            post_data='hellotestingfrohttppostcontent',
                            server_port=443)

                        assert status_dut == SLStatus.SL_STATUS_OK, "failed to post data using http post request"
                        logger().info(status_dut)
                        time.sleep(5)

                        logger().info(f"\n\n***Fetching the data on https using get method iteration = {i} ***\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(
                            self.http_server.interfaces.http,
                            self.index_path,
                            server_port=443)
                        status_client, content_client = self.http_client.interfaces.http.http_get(
                            self.http_server.interfaces.http, self.index_path)

                        assert not status_dut, "failed to fetch the https data"
                        assert status_client, "failed to load the https data"

                        logger().info(status_dut)
                        logger().info(content_dut)
                        assert content_dut == content_client, "fetched data is not same as expected data"

                        logger().info(f"\n\n************* Put data using HTTP PUT request {i}*************\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_put(
                            self.http_server.interfaces.http,
                            server_port=443)

                        logger().info(f"HTTP Put Status:{status_dut}")

                        time.sleep(5)
                        self.wifi_dut.interfaces.wifi.http_client_deinit()

                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()

                    time.sleep(5)
                    self.wifi_dut.interfaces.wifi.leave()
                    return
                except Exception as e:
                    logger().info(f"\n\n **** Got exception in test case {self.test_name} thread: {str(e)} ****\n\n")
                    raise e

            if self.test_name == '537902':
                try:
                    logger().info('\n*** Configuring Sniffer channel ***\n')
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel)
                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    time.sleep(3)

                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, power_save=True,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             channel=self.wifi_access_point.interfaces.wifi.channel,
                                                                             )
                    power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")

                    time.sleep(5)
                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    for i in range(0, 5):
                        """ Verify DUT functionality with sequence HTTPS GET,PUT,POST"""

                        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                        self.wifi_dut.interfaces.wifi.http_client_init(https_enable=True)

                        logger().info(f"\n\n***Fetching the data on https using get method iteration = {i} ***\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(
                            self.http_server.interfaces.http,
                            self.index_path,
                            server_port=443)
                        status_client, content_client = self.http_client.interfaces.http.http_get(
                            self.http_server.interfaces.http, self.index_path)

                        assert not status_dut, "failed to fetch the https data"
                        assert status_client, "failed to load the https data"

                        logger().info(status_dut)
                        logger().info(content_dut)
                        assert content_dut == content_client, "fetched data is not same as expected data"

                        logger().info(f"\n\n************* Put data using HTTP PUT request {i}*************\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_put(
                            self.http_server.interfaces.http,
                            server_port=443)
                        logger().info(status_dut)
                        logger().info(content_dut)

                        logger().info(f"\n\n***Posting data using http post request for iteration = {i} ***\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_post(
                            self.http_server.interfaces.http,
                            self.index_path,
                            post_data='hellotestingfrohttppostcontent',
                            server_port=443)

                        assert status_dut == SLStatus.SL_STATUS_OK, "failed to post data using http post request"
                        logger().info(status_dut)
                        time.sleep(5)

                        logger().info(f"HTTP Put Status:{status_dut}")

                        time.sleep(5)
                        self.wifi_dut.interfaces.wifi.http_client_deinit()

                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()

                    time.sleep(5)
                    self.wifi_dut.interfaces.wifi.leave()
                    return
                except Exception as e:
                    logger().info(f"\n\n **** Got exception in test case {self.test_name} thread: {str(e)} ****\n\n")
                    raise e

            if self.test_name == '537903':
                try:
                    logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel)
                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    time.sleep(3)

                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, power_save=True,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             channel=self.wifi_access_point.interfaces.wifi.channel,
                                                                             )
                    power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")

                    time.sleep(5)
                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    for i in range(0, 1):
                        """ Verify DUT functionality with sequence HTTPS GET,PUT,POST"""

                        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                        self.wifi_dut.interfaces.wifi.http_client_init(https_enable=True)

                        logger().info(f"\n\n***Fetching the data on https using get method iteration = {i} ***\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(
                            self.http_server.interfaces.http,
                            self.index_path,
                            server_port=443)
                        status_client, content_client = self.http_client.interfaces.http.http_get(
                            self.http_server.interfaces.http, self.index_path)

                        assert not status_dut, "failed to fetch the https data"
                        assert status_client, "failed to load the https data"

                        logger().info(status_dut)
                        logger().info(content_dut)
                        assert content_dut == content_client, "fetched data is not same as expected data"

                        logger().info(f"\n\n***Posting data using http post request for iteration = {i} ***\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_post(
                            self.http_server.interfaces.http,
                            self.index_path,
                            post_data='hellotestingfrohttppostcontent',
                            server_port=443)

                        assert status_dut == SLStatus.SL_STATUS_OK, "failed to post data using http post request"
                        logger().info(status_dut)

                        logger().info(f"\n\n************* Put data using HTTP PUT request {i}*************\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_put(
                            self.http_server.interfaces.http,
                            server_port=443)
                        logger().info(status_dut)
                        logger().info(content_dut)

                        time.sleep(5)

                        logger().info(f"HTTP Put Status:{status_dut}")

                        time.sleep(5)
                        self.wifi_dut.interfaces.wifi.http_client_deinit()

                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()

                    time.sleep(5)
                    self.wifi_dut.interfaces.wifi.leave()
                    return
                except Exception as e:
                    logger().info(f"\n\n **** Got exception in test case {self.test_name} thread: {str(e)} ****\n\n")
                    raise e

            if self.test_name == '537904':
                try:
                    logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel)
                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    time.sleep(3)

                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, power_save=True,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             channel=self.wifi_access_point.interfaces.wifi.channel,
                                                                             )
                    power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")

                    time.sleep(5)
                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    for i in range(0, 1):
                        """ Verify DUT functionality with sequence HTTPS PUT,POST,GET """

                        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                        self.wifi_dut.interfaces.wifi.http_client_init(https_enable=True)

                        logger().info(f"\n\n************* Put data using HTTP PUT request {i}*************\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_put(
                            self.http_server.interfaces.http,
                            server_port=443)
                        logger().info(status_dut)
                        logger().info(content_dut)

                        logger().info(f"\n\n***Posting data using http post request for iteration = {i} ***\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_post(
                            self.http_server.interfaces.http,
                            self.index_path,
                            post_data='hellotestingfrohttppostcontent',
                            server_port=443)

                        assert status_dut == SLStatus.SL_STATUS_OK, "failed to post data using http post request"
                        logger().info(status_dut)

                        logger().info(f"\n\n***Fetching the data on https using get method iteration = {i} ***\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(
                            self.http_server.interfaces.http,
                            self.index_path,
                            server_port=443)
                        status_client, content_client = self.http_client.interfaces.http.http_get(
                            self.http_server.interfaces.http, self.index_path)

                        assert not status_dut, "failed to fetch the https data"
                        assert status_client, "failed to load the https data"

                        logger().info(status_dut)
                        logger().info(content_dut)
                        assert content_dut == content_client, "fetched data is not same as expected data"

                        logger().info(f"\n\n***Posting data using http post request for iteration = {i} ***\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_post(
                            self.http_server.interfaces.http,
                            self.index_path,
                            post_data='hellotestingfrohttppostcontent',
                            server_port=443)

                        assert status_dut == SLStatus.SL_STATUS_OK, "failed to post data using http post request"
                        logger().info(status_dut)
                        logger().info(f"HTTP Put Status:{status_dut}")

                        time.sleep(5)
                        self.wifi_dut.interfaces.wifi.http_client_deinit()

                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()

                    time.sleep(5)
                    self.wifi_dut.interfaces.wifi.leave()
                    return
                except Exception as e:
                    logger().info(f"\n\n **** Got exception in test case {self.test_name} thread: {str(e)} ****\n\n")
                    raise e

            if self.test_name == '537905':
                try:
                    logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel)
                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    time.sleep(3)

                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, power_save=True,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             channel=self.wifi_access_point.interfaces.wifi.channel,
                                                                             )
                    power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")

                    time.sleep(5)
                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    for i in range(0, 1):
                        """ Verify DUT functionality with sequence HTTPS POST, PUT, GET """

                        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                        self.wifi_dut.interfaces.wifi.http_client_init(https_enable=True)

                        # time.sleep(20)
                        # logger().info(f"\n\n***Posting data using http post request for iteration = {i} ***\n\n")
                        # status_dut, content_dut = self.wifi_dut.interfaces.http.http_post(
                        #     self.http_server.interfaces.http,
                        #     self.index_path,
                        #     post_data='hellotestingfrohttppostcontent',
                        #     server_port=443)
                        #
                        # assert status_dut == SLStatus.SL_STATUS_OK, "failed to post data using http post request"
                        # logger().info(status_dut)

                        time.sleep(20)
                        logger().info(f"\n\n************* Put data using HTTP PUT request {i}*************\n\n")
                        post_data = 'hellotestingfrohttppostcontent'
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_put(
                            self.http_server.interfaces.http, self.index_path)
                        logger().info(status_dut)
                        logger().info(content_dut)

                        #
                        # time.sleep(25)
                        # logger().info(f"\n\n***Fetching the data on https using get method iteration = {i} ***\n\n")
                        # status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(
                        #     self.http_server.interfaces.http,
                        #     self.index_path,
                        #     server_port=443)
                        # status_client, content_client = self.http_client.interfaces.http.http_get(
                        #     self.http_server.interfaces.http, self.index_path)
                        #
                        # assert not status_dut, "failed to fetch the https data"
                        # assert status_client, "failed to load the https data"
                        #
                        # logger().info(status_dut)
                        # logger().info(content_dut)
                        # assert content_dut == content_client, "fetched data is not same as expected data"

                        time.sleep(5)
                        self.wifi_dut.interfaces.wifi.http_client_deinit()

                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()

                    time.sleep(5)
                    self.wifi_dut.interfaces.wifi.leave()
                    return
                except Exception as e:
                    logger().info(f"\n\n **** Got exception in test case {self.test_name} thread: {str(e)} ****\n\n")
                    raise e

            if self.test_name == '37540':
                try:
                    logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel)
                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    time.sleep(3)

                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, power_save=True,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             channel=self.wifi_access_point.interfaces.wifi.channel,
                                                                             )
                    power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")

                    time.sleep(10)
                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    for i in range(0, 3):
                        """ Verify DUT functionality with sequence HTTPS POST """

                        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                        self.wifi_dut.interfaces.wifi.http_client_init(https_enable=True)

                        logger().info(f"\n\n***Posting data using http post request for iteration = {i} ***\n\n")

                        self.wifi_dut.interfaces.http.http_post(
                            self.http_server.interfaces.http,
                            self.index_path,
                            post_data='hellotestingfrohttppostcontent',
                            server_port=443, expected_status=SLStatus.SL_STATUS_SI91X_ERROR_IN_LEN_OF_THE_COMMAND)

                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()

                    time.sleep(5)
                    self.wifi_dut.interfaces.wifi.leave()
                    return
                except Exception as e:
                    logger().info(f"\n\n **** Got exception in test case {self.test_name} thread: {str(e)} ****\n\n")
                    raise e

            if self.test_name == '535794':
                try:
                    logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel)
                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    time.sleep(3)

                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, power_save=True,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             channel=self.wifi_access_point.interfaces.wifi.channel,
                                                                             )
                    power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")

                    time.sleep(10)
                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    for i in range(0, 1):
                        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                        self.wifi_dut.interfaces.wifi.http_client_init(https_enable=True)

                        logger().info(f"\n\n***Fetching the data on https using get method iteration = {i} ***\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(
                            self.http_server.interfaces.http,
                            self.index_path,
                            server_port=443)
                        status_client, content_client = self.http_client.interfaces.http.http_get(
                            self.http_server.interfaces.http, self.index_path)

                        assert not status_dut, "failed to fetch the https data"
                        assert status_client, "failed to load the https data"

                        logger().info(status_dut)
                        logger().info(content_dut)
                        assert content_dut == content_client, "fetched data is not same as expected data"

                        time.sleep(5)
                        self.wifi_dut.interfaces.wifi.http_client_deinit()

                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()

                    time.sleep(5)
                    self.wifi_dut.interfaces.wifi.leave()
                    return
                except Exception as e:
                    logger().info(f"\n\n **** Got exception in test case {self.test_name} thread: {str(e)} ****\n\n")
                    raise e

            if self.test_name == '535793':
                try:
                    logger().info('\n*** Configuring Sniffer channel ***\n')
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel)
                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    time.sleep(3)

                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, power_save=True,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             channel=self.wifi_access_point.interfaces.wifi.channel,
                                                                             )
                    power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")

                    time.sleep(10)
                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    for i in range(0, 5):
                        """ Verify DUT functionality with sequence HTTPS POST """

                        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                        self.wifi_dut.interfaces.wifi.http_client_init(https_enable=False)

                        logger().info(f"\n\n***Posting data using http post request for iteration = {i} ***\n\n")

                        self.wifi_dut.interfaces.http.http_post(
                            self.http_server.interfaces.http,
                            self.index_path,
                            post_data='hellotestingfrohttppostcontent',
                            server_port=443, expected_status=SLStatus.SL_STATUS_SI91X_ERROR_IN_LEN_OF_THE_COMMAND)

                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()

                    time.sleep(5)
                    self.wifi_dut.interfaces.wifi.leave()
                    return
                except Exception as e:
                    logger().info(f"\n\n **** Got exception in test case {self.test_name} thread: {str(e)} ****\n\n")
                    raise e

            if self.test_name == '537878':
                try:
                    """ Enabling Rejoin """
                    self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=4, scan_interval=6,
                                                                                  beacon_missed_count=40,
                                                                                  first_time_retry_enable=0)
                    logger().info('\n*** Configuring Sniffer channel ***\n')
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel)
                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    time.sleep(3)

                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, power_save=True,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             channel=self.wifi_access_point.interfaces.wifi.channel,
                                                                             )
                    power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")

                    time.sleep(10)
                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    for i in range(0, 1):
                        """ Verify DUT functionality with sequence HTTPS POST """

                        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                        self.wifi_dut.interfaces.wifi.http_client_init(https_enable=True)

                        logger().info(f"\n\n***Fetching the data on https using get method iteration = {i} ***\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(
                            self.http_server.interfaces.http,
                            self.index_path,
                            server_port=443)
                        status_client, content_client = self.http_client.interfaces.http.http_get(
                            self.http_server.interfaces.http, self.index_path)

                        assert not status_dut, "failed to fetch the https data"
                        assert status_client, "failed to load the https data"

                        logger().info(status_dut)
                        logger().info(content_dut)
                        assert content_dut == content_client, "fetched data is not same as expected data"

                        https_thread = Thread_https_post(self.wifi_dut, self.http_server, self.index_path)
                        ap_thread = Thread_ap(self.switch, self.wifi_dut)

                        # https_thread.start()
                        # https_thread.wait_for_exit()
                        ap_thread.start()
                        ap_thread.wait_for_exit()
                        https_thread.start()
                        https_thread.wait_for_exit()

                        # logger().info(f"\n\n***Posting data using http post request for iteration = {i} ***\n\n")
                        #
                        # self.wifi_dut.interfaces.http.http_post(
                        #     self.http_server.interfaces.http,
                        #     self.index_path,
                        #     post_data='hellotestingfrohttppostcontent',
                        #     server_port=443)

                    # logger().info("Stopping sniffer capture")
                    # self.wifi_sniffer.interfaces.capture.stop_capture()
                    #
                    # time.sleep(5)
                    # self.wifi_dut.interfaces.wifi.leave()
                    return
                except Exception as e:
                    logger().info(f"\n\n **** Got exception in test case {self.test_name} thread: {str(e)} ****\n\n")
                    raise e

            if self.test_name == '537879':
                try:
                    logger().info('\n*** Configuring Sniffer channel ***\n')
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel)
                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    time.sleep(3)

                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, power_save=True,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             channel=self.wifi_access_point.interfaces.wifi.channel,
                                                                             )
                    power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")

                    time.sleep(10)
                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    for i in range(0, 5):
                        """ Verify DUT functionality with sequence HTTPS POST """

                        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                        self.wifi_dut.interfaces.wifi.http_client_init(https_enable=True)

                        logger().info(f"\n\n***Fetching the data on https using get method iteration = {i} ***\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(
                            self.http_server.interfaces.http,
                            self.index_path,
                            server_port=443)
                        status_client, content_client = self.http_client.interfaces.http.http_get(
                            self.http_server.interfaces.http, self.index_path)

                        assert not status_dut, "failed to fetch the https data"
                        assert status_client, "failed to load the https data"

                        logger().info(status_dut)
                        logger().info(content_dut)
                        assert content_dut == content_client, "fetched data is not same as expected data"

                        logger().info(f"\n\n***Posting data using http post request for iteration = {i} ***\n\n")

                        self.wifi_dut.interfaces.http.http_post(
                            self.http_server.interfaces.http,
                            self.index_path,
                            post_data='hellotestingforhttppostcontent',
                            server_port=443)

                        time.sleep(2)
                        logger().info("\n\n *** Initiating HTTP client deinit *** \n\n")
                        self.wifi_dut.interfaces.wifi.http_client_deinit()

                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    return
                except Exception as e:
                    logger().info(f"\n\n **** Got exception in test case {self.test_name} thread: {str(e)} ****\n\n")
                    raise e

            logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
            time.sleep(3)

            self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                     channel=self.wifi_access_point.interfaces.wifi.channel)

            self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
            self.wifi_dut.interfaces.wifi.http_client_init()

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e
class Thread_https_post(WLanThread):
    def __init__(self, wifi_dut, http_server, index_path):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.http_server = http_server
        self.index_path = index_path

    def run(self):
        logger().info(f"\n\n***Posting data using http post request ***\n\n")
        self.wifi_dut.interfaces.http.http_post(
            self.http_server.interfaces.http,
            self.index_path,
            post_data='hellotestingfrohttppostcontent',
            server_port=443)
        time.sleep(20)
        self.wifi_dut.interfaces.http.http_post(
            self.http_server.interfaces.http,
            self.index_path,
            post_data='hellotestingfrohttppostcontent',
            server_port=443)
        time.sleep(20)
        self.wifi_dut.interfaces.http.http_post(
            self.http_server.interfaces.http,
            self.index_path,
            post_data='hellotestingfrohttppostcontent',
            server_port=443)
        time.sleep(20)
        self.wifi_dut.interfaces.http.http_post(
            self.http_server.interfaces.http,
            self.index_path,
            post_data='hellotestingfrohttppostcontent',
            server_port=443)
        self.wifi_dut.interfaces.http.http_post(
            self.http_server.interfaces.http,
            self.index_path,
            post_data='hellotestingfrohttppostcontent',
            server_port=443)
        time.sleep(20)
        self.wifi_dut.interfaces.http.http_post(
            self.http_server.interfaces.http,
            self.index_path,
            post_data='hellotestingfrohttppostcontent',
            server_port=443)


class Thread_ap(WLanThread):
    def __init__(self, switch, wifi_dut):
        super().__init__()
        self.switch = switch
        self.wifi_dut = wifi_dut

    def run(self):
        logger().info('******* Turn off AP0 outlet  **********')
        self.switch.interfaces.pdu_switch.turn_off()
        # assert self.rejoin_async_event(), "Did not receive an expected rejoin error event"
        logger().info("Checking for rejoin fail event from dut, this may take some time....")
        with TimeMeasurer() as t:
            logger().info("Waiting up to 180 seconds for rejoin error event...")
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
        logger().info(f"Received rejoin error event after {t.duration:.2f}s")
        # return True
        self.switch.interfaces.pdu_switch.turn_on(70)
        time.sleep(20)
        # time.sleep(20)




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_http_get_functionality_feature_not_enabled_dut_c19204(http_server, wifi_dut, http_client,
                                                                        wifi_access_point, index_path, utf_constants,
                                                                        wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify error code SL_STATUS_SI91X_FEATURE_NOT_ENABLED
    """
    try:
        test_name = '19204'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetching https data using get method")
        wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,
                                          expected_status=SLStatus.SL_STATUS_SI91X_FEATURE_NOT_ENABLED)
        logger().info('We are getting 0x1FF74(SL_STATUS_SI91X_FEATURE_NOT_ENABLED) status which is expected')

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_http_get_functionality_comparison_c19215(http_server, wifi_dut, http_client, wifi_access_point,
                                                           index_path, utf_constants, wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the http get response
    """
    try:
        test_name = '19215'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("\n\n***Fetching the data on https using get method***\n\n")
        status_dut, content_dut = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,
                                                                    server_port=80)
        status_client, content_client = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

        assert not status_dut, "failed to fetch the https data"
        assert status_client, "failed to load the https data"

        logger().info(status_dut)
        logger().info(content_dut)
        assert content_dut == content_client, "fetched data is not same as expected data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.http_client_deinit()
        time.sleep(5)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_http_get_functionality_c19209(http_server, wifi_dut, http_client, wifi_access_point, index_path,
                                                utf_constants, wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the http get response
    """
    try:
        test_name = '19209'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("\n\n***Fetching the data on https using get method***\n\n")
        status_dut, content_dut = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,
                                                                    server_port=80)
        status_client, content_client = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

        assert not status_dut, "failed to fetch the https data"
        assert status_client, "failed to load the https data"

        logger().info(status_dut)
        logger().info(content_dut)
        assert content_dut == content_client, "fetched data is not same as expected data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.http_client_deinit()
        time.sleep(5)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_access_point", wifi={"security": 'OPEN'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_http_get_with_url_length_1140_with_open_security_c476930(http_server, wifi_dut, http_client,
                                                                           wifi_access_point, wifi_sniffer,
                                                                           sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the http get response
    """
    try:
        test_name = '476930'
        index_path = "url_greater_than_1024_and_less_than_2048/" * 27 + "LONG_PATH.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_http_get_with_url_length_1140_with_wpa3_security_c476931(http_server, wifi_dut, http_client,
                                                                           wifi_access_point, wifi_sniffer,
                                                                           sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection`
        4. Initiate http get for http content
        5. Verify the http get response
    """
    try:
        test_name = '476930'
        index_path = "url_greater_than_1024_and_less_than_2048/" * 27 + "LONG_PATH.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2Enterprise'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL | Si91xFeatureBitMap.PSKSecurity,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_http_get_multiple_times_with_long_http_url_bit_enable_eap_security_c476932(http_server, wifi_dut,
                                                                                             http_client, index_path,
                                                                                             wifi_access_point,
                                                                                             wifi_sniffer,
                                                                                             sl_collections,
                                                                                             sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the http get response
    """
    try:
        test_name = '476932'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_http_get_with_url_length_approx_800_bytes_c476934(http_server, wifi_dut, http_client,
                                                                    wifi_access_point, wifi_sniffer, sl_collections,
                                                                    sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the http get response
    """
    try:
        test_name = '476930'
        index_path = "url_approx_800bytes/" * 40 + "LONG_PATH.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_http_get_with_url_length_1024_c476935(http_server, wifi_dut, http_client, wifi_access_point,
                                                        wifi_sniffer, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the http get response
    """
    try:
        test_name = '476930'
        index_path = "url_exact_1024_bytes/" * 48 + "url_len_1024.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_http_get_with_url_length_1140_c476936(http_server, wifi_dut, http_client, wifi_access_point,
                                                        wifi_sniffer, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection`
        4. Initiate http get for http content
        5. Verify the http get response
    """
    try:
        test_name = '476930'
        index_path = "url_greater_than_1024_and_less_than_2048/" * 27 + "LONG_PATH.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_http_get_with_url_length_2048_c476937(http_server, wifi_dut, http_client, wifi_access_point,
                                                        wifi_sniffer, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the http get response
    """
    try:
        test_name = '476930'
        index_path = "url_exact_2048_bytes/" * 97 + "2048url.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_http_get_with_url_length_greater_than_2048_c476938(http_server, wifi_dut, http_client,
                                                                     wifi_access_point, wifi_sniffer,
                                                                     sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the http get response
    """
    try:
        test_name = '476938'
        index_path = "url_greater_than_2048_bytes/" * 75 + "LONG_PATH.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_http_get_with_url_length_2048_with_longer_url_bit_disable_c476939(http_server, wifi_dut, http_client,
                                                                                    wifi_access_point, wifi_sniffer,
                                                                                    sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the http get response
    """
    try:
        test_name = '476939'
        index_path = "url_exact_2048_bytes/" * 97 + "2048url.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_http_get_with_url_length_greater_than_2048_with_longer_url_bit_disable_c476940(http_server, wifi_dut,
                                                                                                 http_client,
                                                                                                 wifi_access_point,
                                                                                                 wifi_sniffer,
                                                                                                 sl_collections,
                                                                                                 sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the http get response
    """
    try:
        test_name = '476938'
        index_path = "url_greater_than_2048_bytes/" * 75 + "LONG_PATH.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.http_server("python_http_server")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wifi_sdk_https_post_get_put_c537883(http_server, wifi_dut, http_client, wifi_access_point, index_path,
                                             wifi_sniffer, sl_collections, sniffer_filter):
    """Verify DUT functionality with sequence HTTPS POST,GET,PUT"""
    try:
        test_name = '537883'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.http_server("python_http_server")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wifi_sdk_https_post_get_put_c537902(http_server, wifi_dut, http_client, wifi_access_point, index_path,
                                             wifi_sniffer, sl_collections, sniffer_filter):
    """Verify DUT functionality with sequence HTTPS GET,PUT,POST"""
    try:
        test_name = '537902'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.http_server("python_http_server")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wifi_sdk_https_post_get_put_c537903(http_server, wifi_dut, http_client, wifi_access_point, index_path,
                                             wifi_sniffer, sl_collections, sniffer_filter):
    """Verify DUT functionality with sequence HTTPS GET, POST, PUT"""
    try:
        test_name = '537903'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.http_server("python_http_server")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wifi_sdk_https_post_get_put_c537904(http_server, wifi_dut, http_client, wifi_access_point, index_path,
                                             wifi_sniffer, sl_collections, sniffer_filter):
    """ Verify DUT functionality with sequence HTTPS PUT,POST,GET"""
    try:
        test_name = '537904'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.http_server("python_http_server")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wifi_sdk_https_post_c537905(http_server, wifi_dut, http_client, wifi_access_point, index_path,
                                     wifi_sniffer, sl_collections, sniffer_filter):
    """ Verify DUT functionality with sequence HTTPS POST,PUT,GET """
    try:
        test_name = '537905'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wifi_sdk_https_get_c476966(http_server, wifi_dut, http_client, wifi_access_point,
                                             wifi_sniffer, sl_collections, sniffer_filter):
    """ Verify HTTPs GET continuously with different URL lengths in a loop with HTTP longer URL support BIT
    enable in opermode """
    try:
        test_name = '476966'
        index_path1 = "url_approx_800bytes/" * 40 + "LONG_PATH.htm"
        index_path2 = "url_exact_1024_bytes/" * 48 + "url_len_1024.htm"
        index_path3 = "url_exact_2048_bytes/" * 97 + "2048url.htm"
        urls_list = [index_path1, index_path2, index_path3]

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=urls_list,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wifi_sdk_https_post_negative_c37540(http_server, wifi_dut, http_client, wifi_access_point,
                                             wifi_sniffer, sl_collections, sniffer_filter):
    """ Verify HTTPS POST with HTTP_LONGER URL path ,HTTP POST should fail 0x1BB3E error """
    try:
        test_name = '37540'
        index_path = "url_exact_2048_bytes/" * 97 + "2048url.htm"

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "clear_certs"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V2,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wifi_sdk_https_get_c535794(http_server, wifi_dut, http_client, wifi_access_point,
                                    wifi_sniffer, sl_collections, sniffer_filter, index_path):
    """ Verify HTTPS GET with TLS v 1.2 """
    try:
        test_name = '535794'

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wifi_sdk_https_post_negative_c535793(http_server, wifi_dut, http_client, wifi_access_point,
                                              wifi_sniffer, sl_collections, sniffer_filter):
    """ Verify HTTP POST with HTTP longer URL Path , DUT should throw an error BB3E (~1900)"""
    try:
        test_name = '535793'
        index_path = "url_exact_1900_byte_same/" * 76 + "1900_url.htm"

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wifi_sdk_https_post_rejoin_c537878(http_server, wifi_dut, http_client, wifi_access_point,
                                            wifi_sniffer, sl_collections, sniffer_filter, index_path, switch):
    """ Verify HTTPS POST functionality after rejoin failure indication """
    try:
        test_name = '537878'

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client, test_name=test_name, sl_collections=sl_collections,
                              http_server=http_server, index_path=index_path, sniffer_filter=sniffer_filter, switch=switch)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        # https_thread = Thread_https_post(wifi_dut, http_server,index_path)
        # ap_thread = Thread_ap(switch, wifi_dut)
        #
        # # https_thread.start()
        # # https_thread.wait_for_exit()
        # ap_thread.start()
        # ap_thread.wait_for_exit()
        # https_thread.start()
        # https_thread.wait_for_exit()



        wifi_sniffer.interfaces.capture.stop_capture()

        time.sleep(5)
        # wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wifi_sdk_https_get_post_c537879(http_server, wifi_dut, http_client, wifi_access_point,
                                            wifi_sniffer, sl_collections, sniffer_filter, index_path):
    """ Verify HTTPS POST functionality in loop without WLAN Disconnect """
    try:
        test_name = '537879'

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client, test_name=test_name, sl_collections=sl_collections,
                              http_server=http_server, index_path=index_path, sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)