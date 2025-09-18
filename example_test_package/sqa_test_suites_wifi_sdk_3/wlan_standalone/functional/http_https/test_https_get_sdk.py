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
    Si91xExtCustomFeatureBitMap
)
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
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
        4. Initiate http get for http content
"""


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, http_client=None,
                 test_name=None, sl_collections=None, http_server=None, index_path=None, sniffer_filter=None,
                 wifi_client=None):
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
        self.wifi_client = wifi_client
        self.dut_addr = None
        self.ap_mac_address = None
        self.http_client_initialized = False

    def run(self):
        try:
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            if self.test_name == '476965' or self.test_name == '476951' or self.test_name == '476952' or \
                    self.test_name == '476967' or self.test_name == '476945':
                server_port = 443
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
                    if self.test_name == '476945':
                        status = self.wifi_dut.interfaces.wifi.http_client_init(https_enable=False)
                        if status == SLStatus.SL_STATUS_OK:
                            self.http_client_initialized = True
                        server_port = 80
                    else:
                        status = self.wifi_dut.interfaces.wifi.http_client_init(https_enable=True)
                        if status == SLStatus.SL_STATUS_OK:
                            self.http_client_initialized = True
                    logger().info("\n\n***Fetching the data on https using get method***\n\n")
                    if self.test_name == '476951':
                        self.wifi_dut.interfaces.wifi.http_get(
                            self.http_server.interfaces.http,
                            self.index_path,
                            server_port=443,
                            expected_status=SLStatus.SL_STATUS_HAS_OVERFLOWED)

                    elif self.test_name == '476952':
                        self.wifi_dut.interfaces.wifi.http_get(
                            self.http_server.interfaces.http,
                            self.index_path,
                            server_port=443,
                            expected_status=SLStatus.SL_STATUS_SI91X_ERROR_IN_LEN_OF_THE_COMMAND)

                    elif self.test_name == '476967':
                        status_dut, content_dut = self.wifi_dut.interfaces.wifi.http_get(self.http_server.interfaces.http,
                                                                                         self.index_path, timeout=24000,
                                                                                         server_port=443,
                                                                                         skip_http_data_print=1)

                        assert not status_dut, "failed to fetch the https data"

                        data = re.findall(r'((?<=http_get_response_length:)\d+)', str(content_dut))[0]

                        assert int(data) >= 104857600, 'Fetched data is not 100MB'

                        status = self.wifi_dut.interfaces.wifi.http_client_deinit()
                        if status == SLStatus.SL_STATUS_OK:
                            self.http_client_initialized = False

                    else:
                        status_dut, content_dut = self.wifi_dut.interfaces.wifi.http_get(
                            self.http_server.interfaces.http,
                            self.index_path,
                            server_port=server_port)
                        status_client, content_client = self.http_client.interfaces.http.http_get(
                            self.http_server.interfaces.http, self.index_path)

                        assert not status_dut, "failed to fetch the https data"
                        assert status_client, "failed to load the https data"

                        logger().info(status_dut)
                        logger().info(content_dut)
                        assert content_dut == content_client, "fetched data is not same as expected data"
                        status = self.wifi_dut.interfaces.wifi.http_client_deinit()
                        if status == SLStatus.SL_STATUS_OK:
                            self.http_client_initialized = False

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

            if self.test_name == '476944':
                logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel)
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                time.sleep(3)

                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         channel=self.wifi_access_point.interfaces.wifi.channel)
                for i in range(0, 5):
                    self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                    status = self.wifi_dut.interfaces.wifi.http_client_init(https_enable=True)
                    if status == SLStatus.SL_STATUS_OK:
                        self.http_client_initialized = True
                    logger().info("\n\n***Fetching the data on https using get method***\n\n")
                    status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http,
                                                                                     self.index_path,
                                                                                     server_port=443)
                    status_client, content_client = self.http_client.interfaces.http.http_get(
                        self.http_server.interfaces.http, self.index_path)

                    assert not status_dut, "failed to fetch the https data"
                    assert status_client, "failed to load the https data"

                    logger().info(status_dut)
                    logger().info(content_dut)
                    assert content_dut == content_client, "fetched data is not same as expected data"
                    status = self.wifi_dut.interfaces.wifi.http_client_deinit()
                    if status == SLStatus.SL_STATUS_OK:
                        self.http_client_initialized = False

                logger().info("Stopping sniffer capture")
                self.wifi_sniffer.interfaces.capture.stop_capture()

                power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address, filter_name="power_mgmt_bit")
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                time.sleep(5)
                self.wifi_dut.interfaces.wifi.leave()
                return

            logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
            time.sleep(3)

            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     channel=self.wifi_access_point.interfaces.wifi.channel)

            if self.test_name == '537610':
                url = 'https://www.google.com/'
                for _ in range(5):
                    self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                    status = self.wifi_dut.interfaces.wifi.http_client_init(https_enable=True, sni_enable=True,
                                                                   url=url)
                    if status == SLStatus.SL_STATUS_OK:
                        self.http_client_initialized = True
                    logger().info("\n\n***Fetching the data on https using get method***\n\n")
                    status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http,
                                                                                     self.index_path, server_port=443,
                                                                                     timeout=60)
                    status_client, content_client = self.http_client.interfaces.http.http_get(self.http_server.interfaces.http,
                                                                                              self.index_path)

                    assert not status_dut, "failed to fetch the https data"
                    assert status_client, "failed to load the https data"

                    logger().info(status_dut)
                    logger().info(content_dut)
                    assert content_dut == content_client, "fetched data is not same as expected data"

                    status = self.wifi_dut.interfaces.wifi.http_client_deinit()
                    if status == SLStatus.SL_STATUS_OK:
                        self.http_client_initialized = False

                logger().info("Stopping sniffer capture")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                time.sleep(5)
                remote_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f'**** Remote IP: {remote_ip} ****')
                sni_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.dut_addr['device_ip'], da_addr=remote_ip, filter_name="http_sni")
                logger().info(sni_filter)
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=sni_filter)[
                    'packet_count'], "Client Hello packet with SNI not found"
            elif self.test_name == '19228':
                self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                status = self.wifi_dut.interfaces.wifi.http_client_init()
                if status == SLStatus.SL_STATUS_OK:
                    self.http_client_initialized = True
            else:
                self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                status = self.wifi_dut.interfaces.wifi.http_client_init(https_enable=True)
                if status == SLStatus.SL_STATUS_OK:
                    self.http_client_initialized = True

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e


class HttpGet(ThreadBase):
    def __init__(self, wifi_dut=None, http_server=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.http_server = http_server

    def run(self):
        self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http, 'index.html', server_port=80)
        time.sleep(1)


class HttpDeInit(ThreadBase):
    def __init__(self, wifi_dut=None):
        super().__init__()
        self.wifi_dut = wifi_dut

    def run(self):
        time.sleep(1)
        self.wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_functionality_c19209(http_server, wifi_dut, http_client, wifi_access_point, index_path,
                                                 utf_constants, wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the http get response
    """
    http_client_initialized = False
    try:
        test_name = '19209'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("\n\n***Fetching the data on https using get method***\n\n")
        status_dut, content_dut = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,
                                                                    server_port=443)
        status_client, content_client = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

        assert not status_dut, "failed to fetch the https data"
        assert status_client, "failed to load the https data"

        logger().info(status_dut)
        logger().info(content_dut)
        assert content_dut == content_client, "fetched data is not same as expected data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        status = wifi_dut.interfaces.wifi.http_client_deinit()
        if status == SLStatus.SL_STATUS_OK:
            http_client_initialized = False
        time.sleep(5)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_functionality_feature_not_enabled_dut_c19204(http_server, wifi_dut, http_client,
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

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_functionality_not_loading_cert_c19203(http_server, wifi_dut, http_client, wifi_access_point,
                                                                  index_path, utf_constants, wifi_sniffer,
                                                                  sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify error code SL_STATUS_SI91X_SSL_TLS_HANDSHAKE_FAILED
    """
    try:
        test_name = '19203'

        wifi_dut.interfaces.wifi.clear_certificate()
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetching https data using get method")
        wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path, server_port=443,
                                          expected_status=SLStatus.SL_STATUS_SI91X_SSL_TLS_HANDSHAKE_FAILED)

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca_ecdsa.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_with_wrong_certificate_c19211(http_server, wifi_dut, http_client, wifi_access_point,
                                                          index_path, utf_constants, wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify error code SL_STATUS_SI91X_SSL_TLS_HANDSHAKE_FAILED
    """
    try:
        test_name = '19211'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("\n\n***Fetching the data on https using get method***\n\n")
        wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path, server_port=443,
                                          expected_status=SLStatus.SL_STATUS_SI91X_SSL_TLS_HANDSHAKE_FAILED)

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.config("http_server", port=10)
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_functionality_port10_c19207_case1(http_server, wifi_dut, http_client, wifi_access_point,
                                                              index_path, utf_constants, wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the response from http get when different port number is passed
    """
    try:
        test_name = '19207_case1'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetches https data using get method")
        status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path, server_port=10)
        logger().info(status)
        logger().info(content)
        assert not status, "failed to fetch the http data"
        assert content, "failed to load the http data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        status = wifi_dut.interfaces.wifi.http_client_deinit()
        if status == SLStatus.SL_STATUS_OK:
            wlan_obj.http_client_initialized = False
        time.sleep(5)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if wlan_obj.http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.config("http_server", port=200)
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_functionality_port200_c19207_case2(http_server, wifi_dut, http_client, wifi_access_point,
                                                               index_path, utf_constants, wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the response from http get when different port number is passed
    """
    try:
        test_name = '19207_case2'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetches https data using get method")
        status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path, server_port=200)
        logger().info(status)
        logger().info(content)
        assert not status, "failed to fetch the http data"
        assert content, "failed to load the http data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        status = wifi_dut.interfaces.wifi.http_client_deinit()
        if status == SLStatus.SL_STATUS_OK:
            wlan_obj.http_client_initialized = False
        time.sleep(5)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if wlan_obj.http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.config("http_server", port=2000)
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_functionality_port2000_c19207_case3(http_server, wifi_dut, http_client, wifi_access_point,
                                                                index_path, utf_constants, wifi_sniffer,
                                                                sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the response from http get when different port number is passed
    """
    try:
        test_name = '19207_case3'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetches https data using get method")
        status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path, server_port=2000)
        logger().info(status)
        logger().info(content)
        assert not status, "failed to fetch the http data"
        assert content, "failed to load the http data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        status = wifi_dut.interfaces.wifi.http_client_deinit()
        if status == SLStatus.SL_STATUS_OK:
            wlan_obj.http_client_initialized = False
        time.sleep(5)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if wlan_obj.http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.config("http_server", port=20000)
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_functionality_port20000_c19207_case4(http_server, wifi_dut, http_client, wifi_access_point,
                                                                 index_path, utf_constants, wifi_sniffer,
                                                                 sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the response from http get when different port number is passed
    """
    try:
        test_name = '19207_case4'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetches https data using get method")
        status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,
                                                            server_port=20000)
        logger().info(status)
        logger().info(content)
        assert not status, "failed to fetch the http data"
        assert content, "failed to load the http data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        status = wifi_dut.interfaces.wifi.http_client_deinit()
        if status == SLStatus.SL_STATUS_OK:
            wlan_obj.http_client_initialized = False
        time.sleep(5)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if wlan_obj.http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"100MB.htm"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_functionality_send_100mb_file_from_peer_c19206(http_server, wifi_dut, http_client,
                                                                           wifi_access_point, index_path, utf_constants,
                                                                           wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the response from http get when peer sends 100mb data
    """
    try:
        test_name = '19206'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetching  https data using get method")
        status_dut, content_dut = wifi_dut.interfaces.http.http_get(http_server.interfaces.http,
                                                                    index_path, timeout=24000, server_port=443,
                                                                    skip_http_data_print=1)

        assert not status_dut, "failed to fetch the https data"

        data = re.findall(r'((?<=http_get_response_length:)\d+)', str(content_dut))[0]

        assert int(data) >= 104857600, 'Fetched data is not 100MB'

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        status = wifi_dut.interfaces.wifi.http_client_deinit()
        if status == SLStatus.SL_STATUS_OK:
            wlan_obj.http_client_initialized = False
        time.sleep(5)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if wlan_obj.http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_http_get_when_httpserver_does_not_ssl_handshake_c19210(wifi_sniffer, http_server, wifi_dut,
                                                                         wifi_access_point, index_path, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the error response '0x1BBD2' from http get when remote server does not start SSL hand shake
    """
    try:
        test_name = '19210'
        wifi_dut.interfaces.wifi.clear_certificate()
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetching https data using get method")
        wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path, server_port=443,
                                          expected_status=SLStatus.SL_STATUS_SI91X_SSL_TLS_HANDSHAKE_FAILED)

        logger().info("**** Getting 1BBD2 status, which is expected ****")

        logger().info("Sniffer going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_http_get_functionality_non_existing_server_c19212(http_server, wifi_dut, http_client, index_path,
                                                                    wifi_access_point, utf_constants, wifi_sniffer,
                                                                    sl_collections):
    try:
        test_name = '19212'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_dut.interfaces.http.http_get(server=http_server.interfaces.http, server_ip='10.208.21.25',
                                          resource_path=index_path, server_port=80,
                                          expected_status=SLStatus.SL_STATUS_SI91X_CONNECT_TO_NON_EXISTING_TCP_SERVER_SOCKET)
        logger().info('**** Getting 0x1BB38 status which is expected ****')

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_http_get_with_host_name_c19216(http_server, wifi_sniffer, http_client, wifi_dut, wifi_access_point,
                                                 index_path, utf_constants, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the response from http get with host name
    """
    try:
        test_name = '19216'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetches https data using get method")
        status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path, server_port=443)
        logger().info(status)
        logger().info(content)
        assert not status, "failed to fetch the http data"
        assert content, "failed to load the http data"

        status = wifi_dut.interfaces.wifi.http_client_deinit()
        if status == SLStatus.SL_STATUS_OK:
            wlan_obj.http_client_initialized = False

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        power_save_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], da_addr=wlan_obj.ap_mac_address,
            filter_name="power_mgmt_bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                   'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if wlan_obj.http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_functionality_with_long_http_url_bit_disable_without_disconnect_c476944(http_server,
                                                                                                    wifi_dut,
                                                                                                    http_client,
                                                                                                    wifi_access_point,
                                                                                                    index_path,
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
        test_name = '476944'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if wlan_obj.http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_http_get_functionality_multiple_times_with_long_http_url_bit_enable_c476945(http_server, wifi_dut,
                                                                                              http_client,
                                                                                              wifi_access_point,
                                                                                              index_path, wifi_sniffer,
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
        test_name = '476945'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if wlan_obj.http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_functionality_multiple_times_with_long_http_url_bit_enable_c476965(http_server, wifi_dut,
                                                                                               http_client,
                                                                                               wifi_access_point,
                                                                                               index_path, wifi_sniffer,
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
        test_name = '476965'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if wlan_obj.http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_functionality_with_url_len_around_800_c476947(http_server, wifi_dut, http_client,
                                                                          wifi_access_point, wifi_sniffer,
                                                                          sl_collections, sniffer_filter):
    """HTTPS GET functionality with URL length is less than 1024 (i-e ~800)"""
    try:
        test_name = '476965'
        index_path = "url_approx_800bytes/" * 40 + "LONG_PATH.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client, test_name=test_name, sl_collections=sl_collections,
                              http_server=http_server, index_path=index_path, sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if wlan_obj.http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_functionality_with_url_len_exact_1024_c476948(http_server, wifi_dut, http_client,
                                                                          wifi_access_point, wifi_sniffer,
                                                                          sl_collections, sniffer_filter):
    """HTTPS GET functionality with URL length is with 1024"""
    try:
        test_name = '476965'
        index_path = "url_exact_1024_bytes/" * 48 + "url_len_1024.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client, test_name=test_name, sl_collections=sl_collections,
                              http_server=http_server, index_path=index_path, sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if wlan_obj.http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_functionality_with_url_len_1140_c476949(http_server, wifi_dut, http_client,
                                                                    wifi_access_point, wifi_sniffer,
                                                                    sl_collections, sniffer_filter):
    """HTTPS GET functionality with URL length is more than 1024 (i-e ~1080)"""
    try:
        test_name = '476965'
        index_path = "url_greater_than_1024_and_less_than_2048/" * 27 + "LONG_PATH.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client, test_name=test_name, sl_collections=sl_collections,
                              http_server=http_server, index_path=index_path, sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if wlan_obj.http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_functionality_with_url_len_2048_c476950(http_server, wifi_dut, http_client,
                                                                    wifi_access_point, wifi_sniffer,
                                                                    sl_collections, sniffer_filter):
    """HTTPS GET functionality with URL length is with 2048"""
    try:
        test_name = '476950'
        index_path = "url_exact_2048_bytes/" * 97 + "2048url.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client, test_name=test_name, sl_collections=sl_collections,
                              http_server=http_server, index_path=index_path, sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if wlan_obj.http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_with_url_length_greater_than_2048_c476951(http_server, wifi_dut, http_client,
                                                                      wifi_access_point, wifi_sniffer,
                                                                      sl_collections, sniffer_filter):
    """HTTPS GET functionality with URL length is more than 2048((i-e 2080) and HTTP GET should fail
    with error code 0x1E"""
    try:
        test_name = '476951'
        index_path = "url_greater_than_2048_bytes/" * 75 + "LONG_PATH.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client, test_name=test_name, sl_collections=sl_collections,
                              http_server=http_server, index_path=index_path, sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_functionality_with_url_len_2048_with_longer_url_bit_disable_c476952(http_server,
                                                                                                wifi_dut,
                                                                                                http_client,
                                                                                                wifi_access_point,
                                                                                                wifi_sniffer,
                                                                                                sl_collections,
                                                                                                sniffer_filter):
    """HTTPS GET functionality with URL length is with 2048 with HTTP longer URL support BIT disable in
    oper-mode and HTTP GET should fail with error code 0xBB3E"""
    try:
        test_name = '476952'
        index_path = "url_exact_2048_bytes/" * 97 + "2048url.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client, test_name=test_name, sl_collections=sl_collections,
                              http_server=http_server, index_path=index_path, sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_functionality_with_url_len_with_longer_url_bit_disable_2048_c476953(http_server, wifi_dut,
                                                                                                http_client,
                                                                                                wifi_access_point,
                                                                                                wifi_sniffer,
                                                                                                sl_collections,
                                                                                                sniffer_filter):
    """	HTTPS GET functionality with URL length is with more than 2048 with HTTP longer URL support BIT disable in
    oper-mode and HTTP GET should fail with error code 0x1E"""
    try:
        test_name = '476951'
        index_path = "url_greater_than_2048_bytes/" * 75 + "LONG_PATH.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client, test_name=test_name, sl_collections=sl_collections,
                              http_server=http_server, index_path=index_path, sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip()
@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_https_get_100_mb_with_url_length_2048_c476967(http_server, wifi_dut, http_client, wifi_access_point,
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
        test_name = '476967'
        index_path = "url_exact_2048_bytes/" * 97 + "bigfile.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if wlan_obj.http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.config("wifi_access_point", wifi={"security": 'Open'})
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_sni_functionality_c537610(http_server, wifi_dut, http_client, wifi_access_point, index_path,
                                                      utf_constants, wifi_sniffer, sl_collections, wifi_client,
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
        test_name = '537610'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              http_client=http_client, index_path=index_path, wifi_client=wifi_client,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if wlan_obj.http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_with_different_url_length_c19205(http_server, wifi_dut, http_client, wifi_access_point,
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
        index_paths = ["index.html", "index_index.htm", "index_index_index.htm", "index_index_index_index.htm",
                       "index_index_index_index_index.htm"]
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        for index_path in index_paths:
            logger().info("\n\n***Fetching the data on https using get method***\n\n")
            status_dut, content_dut = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,
                                                                        server_port=443)
            status_client, content_client = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

            assert not status_dut, "failed to fetch the https data"
            assert status_client, "failed to load the https data"

            logger().info(status_dut)
            logger().info(content_dut)
            assert content_dut in content_client, "fetched data is not same as expected data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        status = wifi_dut.interfaces.wifi.http_client_deinit()
        if status == SLStatus.SL_STATUS_OK:
            wlan_obj.http_client_initialized = False
        time.sleep(5)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if wlan_obj.http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 3, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_http_abort_functionality_c19228(http_server, wifi_dut, http_client, wifi_access_point, index_path,
                                                  utf_constants, wifi_sniffer, sl_collections):
    """HTTP abort for multiple times and check whether the Module closes the HTTP connection or not"""
    try:
        test_name = '19228'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("\n\n***Fetching the data on https using get method***\n\n")
        httpget = HttpGet(wifi_dut, http_server)
        httpdeinit = HttpDeInit(wifi_dut)
        httpget.start()
        httpdeinit.start()
        httpdeinit.wait_for_exit()
        logger().info("Called HTTP Abort")
        httpget.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_https_get_no_file_on_remote_c510834(http_server, wifi_dut, wifi_access_point,
                                                      wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the negative http get response
    """
    http_client_initialized = False
    try:
        test_name = '19209'
        index_path = "unsupported.htm"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("\n\n***Fetching the data on https using get method***\n\n")
        wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path, server_port=443,
                                          skip_http_data_print=1)

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        status = wifi_dut.interfaces.wifi.http_client_deinit()
        if status == SLStatus.SL_STATUS_OK:
            http_client_initialized = False
        time.sleep(5)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if http_client_initialized:
            wifi_dut.interfaces.wifi.http_client_deinit()
