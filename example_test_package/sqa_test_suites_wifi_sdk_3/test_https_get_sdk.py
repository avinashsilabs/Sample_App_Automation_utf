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
    Si91xPowerSaveProcedureTypes
)
from utf.interfaces.wifi import WlanError
from utf.utils.thread_base import ThreadBase


def logger():
    return get_logger(__name__)


"""setup requirement:
        1. SoC Board

     Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
"""


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None,
                 test_name=None, sl_collections=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.dut_addr = None
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_name = test_name

    def run(self):
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19209')
        time.sleep(3)

        self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point)

        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.http_client("raspi_http_client")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
# This test cases verifies the https get with the linux as server and client
def test_wifi_sdk_http_server_and_linux_client_get(http_server, http_client):
    method = "GET"
    index_path = "index.html"
    status, resp_content = http_client.interfaces.http.http_request(
        http_server.interfaces.http, method, index_path
    )
    logger().info(status)
    logger().info(resp_content)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_https_get_functionality_C19209(http_server, wifi_dut, http_client, wifi_access_point, index_path,
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
        test_name = 'test_19209'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetching the data on https using post method")
        status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
        status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

        assert status, "failed to fetch the https data"
        assert status1, "failed to load the https data"

        logger().info(status)
        logger().info(content)
        assert content == content1, "fetched data is not same as expected data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_https_get_functionality_feature_not_enabled_dut_C19204(http_server, wifi_dut, http_client,
                                                                         wifi_access_point, index_path, utf_constants,
                                                                         wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the error response '0xFF74' from http get response when get functionality is not enabled
    """
    try:
        test_name = 'test_19204'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetching https data using get method")
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
        assert exc_info.value.error_code == 0xFF74, "observed wrong error code expected is 0xFF74"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_https_get_functionality_not_loading_cert_C19203(http_server, wifi_dut, http_client, wifi_access_point,
                                                                  index_path, utf_constants, wifi_sniffer,
                                                                  sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the error response '0xBBD2' from http get when certificate is not enabled
    """
    try:
        test_name = 'test_19203'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetching https data using get method")
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
        assert exc_info.value.error_code == 0xBBD2, "observed wrong error code expected is 0xBBD2"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html", "index_long_crlf.html", "6KB.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_https_get_functionality_different_urls_C19205(http_server, wifi_dut, http_client, wifi_access_point,
                                                                index_path, utf_constants, wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the response from http get when urls of different length provided
    """
    try:
        test_name = 'test_19205'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetching  https data using get method")
        status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
        status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

        assert status, "failed to fetch the http data"
        assert content, "failed to load the http data"

        logger().info(status)
        logger().info(content)
        assert content == content1, "fetched data is not same as expected data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_https_get_functionality_send_100mbfile_from_peer_C19206(http_server, wifi_dut, http_client,
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
        test_name = 'test_19206'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetching  https data using get method")
        status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
        status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

        assert status, "failed to fetch the http data"
        assert content, "failed to load the http data"

        logger().info(status)
        logger().info(content)
        assert content == content1, "fetched data is not same as expected data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
# This test case verifies the Https Get functionality by comparing the data and, by issuing invalid IP
def test_wifi_sdk_https_get_functionality_invalid_ip(http_server, wifi_dut, http_client, wifi_access_point, index_path,
                                                     utf_constants, wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the error response '0xBB38' from http get when invalid IP is passed
    """
    try:
        test_name = 'test_wifi_sdk_https_get_functionality_invalid_ip'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetching  https data using get method")
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path, server_ip='192.168.9.99')
        assert exc_info.value.error_code == 0xBB38, "observed wrong error code expected is 0xBB38"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config("http_server", port=10)
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_https_get_functionality_port10_C19207_case1(http_server, wifi_dut, http_client, wifi_access_point,
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
        test_name = 'test_19207_case1'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetches https data using get method")
        status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
        logger().info(status)
        logger().info(content)
        assert status, "failed to fetch the http data"
        assert content, "failed to load the http data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config("http_server", port=200)
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_https_get_functionality_port10_C19207_case2(http_server, wifi_dut, http_client, wifi_access_point,
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
        test_name = 'test_19207_case2'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetches https data using get method")
        status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
        logger().info(status)
        logger().info(content)
        assert status, "failed to fetch the http data"
        assert content, "failed to load the http data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config("http_server", port=2000)
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_https_get_functionality_port10_C19207_case3(http_server, wifi_dut, http_client, wifi_access_point,
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
        test_name = 'test_19207_case3'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetches https data using get method")
        status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
        logger().info(status)
        logger().info(content)
        assert status, "failed to fetch the http data"
        assert content, "failed to load the http data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config("http_server", port=20000)
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_https_get_functionality_port10_C19207_case4(http_server, wifi_dut, http_client, wifi_access_point,
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
        test_name = 'test_19207_case4'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetches https data using get method")
        status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
        logger().info(status)
        logger().info(content)
        assert status, "failed to fetch the http data"
        assert content, "failed to load the http data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_http_get_with_host_name_c19216(http_server, wifi_sniffer, http_client, wifi_dut, wifi_access_point,
                                                 index_path, utf_constants, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the response from http get with host name
    """
    try:
        test_name = 'test_19216'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("fetches https data using get method")
        status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path, host_name="www.google.com")
        logger().info(status)
        logger().info(content)
        assert status, "failed to fetch the http data"
        assert content, "failed to load the http data"

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_http_get_when_httpserver_does_not_ssl_handshake_C19210(wifi_sniffer, http_server, http_client,
                                                                         wifi_dut, wifi_access_point, index_path,
                                                                         utf_constants, sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the error response '0xBBD2' from http get when remote server does not start SSL hand shake
    """
    try:
        test_name = 'test_19210'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        http_server.interfaces.http.stop_server()
        http_server.interfaces.http.tls_enabled = False
        http_server.interfaces.http.start_server()
        http_server.interfaces.http.tls_enabled = True

        logger().info("fetching https data using get method")
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
        assert exc_info.value.error_code == 0xBBD2, "observed wrong error code expected is 0xBBD2"

        logger().info("Sniffer going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info("stopping the HTTP server")
        http_server.interfaces.http.stop_server()
        http_server.interfaces.http.tls_enabled = False

        logger().info(f"DUT going to leave")
        wifi_dut.interfaces.wifi.leave()