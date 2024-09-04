import time
from utf.utils.logger import get_logger
import pytest
import random
import string
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xPowerSaveModes,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
    Si91xOperatingMode,
    Si91xExtCustomFeatureBitMap
)
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus


def logger():
    return get_logger(__name__)


"""setup requirement:
        1. SoC Board

     Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http post for http content
        
     Author: Achal Raghav 
"""


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None,
                 test_name=None, sl_collections=None, https_enable=False, http_client=None, http_server=None,
                 index_path=None, sniffer_filter=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.dut_addr = None
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.https_enable = https_enable
        self.http_client = http_client
        self.http_server = http_server
        self.index_path = index_path
        self.sniffer_filter = sniffer_filter



    def run(self):
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
        time.sleep(3)

        self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                                 associated=self.wifi_dut.interfaces.wifi.associated)

        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
        self.wifi_dut.interfaces.wifi.http_client_init(https_enable=self.https_enable)

        if self.test_name == '19222':
            try:
                for i in range(0, 5):
                    logger().info(f"\n\n*** Start DUT connect/post/disconnect request for iteration = {i} ***\n\n")
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel)
                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    time.sleep(3)

                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             channel=self.wifi_access_point.interfaces.wifi.channel)
                    time.sleep(1)
                    power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")

                    time.sleep(5)
                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                    self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                    self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                    self.wifi_dut.interfaces.wifi.http_client_init(https_enable=False)

                    for url in self.index_path:
                        logger().info(f"\n\n***Posting data using http post request for iteration = {i} ***\n\n")
                        status_dut, content_dut = self.wifi_dut.interfaces.http.http_post(
                            self.http_server.interfaces.http, url, post_data='hellotestingfrohttppostcontent')

                        assert status_dut == SLStatus.SL_STATUS_OK, "failed to post data using http post request"
                        logger().info(status_dut)
                        time.sleep(2)
                    self.wifi_dut.interfaces.wifi.http_client_deinit()
                    time.sleep(2)
                    self.wifi_dut.interfaces.wifi.leave()
                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()
            except Exception as e:
                logger().info(f"\n\n **** Got exception in test case {self.test_name} thread: {str(e)} ****\n\n")
                raise e
            return


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
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_http_post_functionality_invalid_ip_c19220(http_server, wifi_dut, wifi_access_point,
                                                            index_path
                                                            , wifi_sniffer, sl_collections, utf_constants):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http post request using invalid server ip
        5. Module should throw 1BB38 error code response
    """
    try:
        test_name = 'test_19220'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, https_enable=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("\n\n***Posting data using http post request***\n\n")
        status_dut, content_dut = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, index_path,
                                                                     post_data=''.join(random.choices(
                                                                         string.ascii_uppercase + string.digits,
                                                                         k=utf_constants.get('generate_bytes'))),
                                                                     server_ip='192.168.9.99',
                                                                     expected_status=SLStatus.SL_STATUS_SI91X_CONNECT_TO_NON_EXISTING_TCP_SERVER_SOCKET)

        logger().info(status_dut)
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

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
@pytest.mark.start_state("wifi_dut", wifi=["reset", "init"])
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_http_post_functionality_multiple_iterations_C19221(http_server, wifi_dut, wifi_access_point,
                                                                     index_path
                                                                     , wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http post request for multiple iterations using a single url.
        5. Verify the http post response
    """
    try:
        test_name = 'test_19221'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        iteration_count = 5
        for index in range(0, iteration_count):
            logger().info(f"\n\n***Posting data using http post request for {index + 1} iteration***\n\n")
            status_dut, content_dut = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, index_path,
                                                                         post_data='hellotestingfrohttppostcontent')

            assert status_dut == SLStatus.SL_STATUS_OK, "failed to post data using http post request"
            logger().info(status_dut)
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.http_client_deinit()

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
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_http_post_functionality_different_urls_C19224(http_server, wifi_dut, wifi_access_point
                                                                , wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http post using different url lengths
        5. Verify the http post response
    """
    try:
        test_name = 'test_19224'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("\n\n***Posting data using http post request***\n\n")

        urls_list = ["cgi-bin/cgi_example.py", "index_long_crlf.html", "6KB.html"]
        for url in urls_list:
            logger().info(f"Initiating http post request for url {url}")
            status_dut, content_dut = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, resource_path=url,
                                                                         post_data="hellothisisfordifferenturlsusedtopostthed"
                                                                                   "atoverthehttppostprotocol")
            assert not status_dut, "failed to post http data"
            logger().info(status_dut)

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.http_client_deinit()

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
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "clear_certs"])
def test_wifi_sdk_https_post_functionality_multiple_iterations_C19225(http_server, wifi_dut, wifi_access_point,
                                                                      index_path
                                                                      , wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate https post request for multiple iterations using a single url.
        5. Verify the https post response
    """
    try:
        test_name = 'test_19225'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, https_enable=True)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        iteration_count = 5
        for index in range(0, iteration_count):
            logger().info(f"\n\n***Posting data using http post request for {index + 1} iteration***\n\n")
            status_dut, content_dut = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, index_path,
                                                                         post_data="hellothisisfordifferenturlsusedtopostthed"
                                                                                   "atoverthehttppostprotocol",
                                                                         server_port=443)

            assert status_dut == SLStatus.SL_STATUS_OK, "failed to post data using http post request"
            logger().info(status_dut)
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.http_client_deinit()

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
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "clear_certs"])
def test_wifi_sdk_https_post_functionality_different_urls_C19226(http_server, wifi_dut, wifi_access_point
                                                                 , wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate https post using different url lengths
        5. Verify the https post response
    """
    try:
        test_name = 'test_19226'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, https_enable=True)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("\n\n***Posting data using http post request***\n\n")
        urls_list = ["cgi-bin/cgi_example.py", "index_long_crlf.html", "6KB.html"]
        for url in urls_list:
            logger().info(f"Initiating http post request for url {url}")
            status_dut, content_dut = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, resource_path=url,
                                                                         post_data=''.join(random.choices(
                                                                             string.ascii_uppercase + string.digits,
                                                                             k=30)), server_port=443)
            assert not status_dut, "failed to post http data"
            logger().info(status_dut)

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.http_client_deinit()

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
@pytest.mark.config("http_server", auto_start=False)
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_https_post_functionality_on_different_ports_c19227(http_server, wifi_dut, wifi_access_point,
                                                            index_path
                                                            , wifi_sniffer, sl_collections, utf_constants):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http post request on multiple ports
        5. Verfify the HTTP response
    """
    try:
        test_name = 'test_19220'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, https_enable=True)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        ports = (0, 10, 200, 2000, 20000, 443)

        for port in ports:
            http_server.interfaces.http.start_server(port=port)
            logger().info(f"\n\n***Posting data using http post request on port number {port}***\n\n")
            status_dut, content_dut = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, index_path,
                                                                     post_data=''.join(random.choices(
                                                                         string.ascii_uppercase + string.digits,
                                                                         k=utf_constants.get('generate_bytes'))),
                                                                         server_port=port,
                                                                         expected_status=SLStatus.SL_STATUS_OK
                                                                     )
            logger().info(status_dut)
            http_server.interfaces.http.stop_server()
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

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
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_http_post_diff_urls_diff_data_C19222(http_server, wifi_dut, wifi_access_point
                                                                , wifi_sniffer, sl_collections):
    """ HTTP POST functionality by providing data with different data URL lengths """
    try:
        test_name = 'test_19222'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)

        for _ in range(0, 5):
            wlan_obj.start()
            wlan_obj.wait_for_exit()

            index_path = "url_approx_800bytes/" * 5 + "LONG_PATH.htm"
            logger().info("\n\n***Posting data using http post request***\n\n")

            url_dict = {"cgi-bin/cgi_example.py": "hellothisisford",
                        "index_long_crlf.html": "hellothisisfordifferenthellothisisfordifferenthellothisisfordifferent",
                        "6KB.html": "hellothisisfordifferentur"}

            for url, data in url_dict.items():
                logger().info(f"Initiating http post request for url {url}")
                status_dut, content_dut = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, resource_path=url,
                                                                             post_data=data, timeout=100)
                assert not status_dut, "failed to post http data"
                logger().info(status_dut)
                logger().info("\n\n***Time sleep for 5 second ....***\n\n")
                time.sleep(15)

            logger().info("Stopping sniffer capture")
            wifi_sniffer.interfaces.capture.stop_capture()
            wifi_dut.interfaces.wifi.http_client_deinit()
            wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)