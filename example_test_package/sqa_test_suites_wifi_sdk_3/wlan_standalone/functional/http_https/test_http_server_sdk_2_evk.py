import time
import pytest

from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode, Si91xTCPIPFeatureBitMap, Si91xJoinFeatureBitMap, Si91xOperatingMode, Si91xExtTCPIPFeatureBitMap, Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap,
)
from utf_wiseconnect_3.tests.devices.si91x import Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes, Si91xExtCustomFeatureBitMap

from utf.utils.logger import get_logger
import string
import random
from utf.utils.thread_base import ThreadBase
from datetime import datetime

"""The testcases added in this file can run below test steps :
        1. Configuration of DUT
        2. Association of Third party AP's
        3. Get the valid IP address
        4. HTTP get request from the Raspberry-pi to DUT 

setup requirement:
        1. Soc Board
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC Wifi Sniffer 

Author : Vasavi Kalla

"""


def logger():
    return get_logger(__name__)


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, capture_filename=None, wifi_access_point=None, wifi_sniffer=None, http_server=None
                 , http_client=None, sl_collections=None, sniffer_filter=None, utf_constants=None, index_path=None,
                 test_case=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.capture_filename = capture_filename
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.http_server = http_server
        self.http_client = http_client
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.utf_constants = utf_constants
        self.index_path = index_path
        self.test_case = test_case
        self.keep_alive_time = None
        self.dut_addr = None

    def run(self):
        try:
            self.dut_addr = self.sl_collections.join_to_wifi_network(
                self.wifi_dut, self.wifi_access_point, associated=self.wifi_dut.interfaces.wifi.associated)

        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
            raise e

    def dut_http_functionality(self, method, sec_dut_ip):

        if method == "GET":
            status_dut, content_dut = self.wifi_dut.interfaces.wifi.http_get(server=None, server_ip=sec_dut_ip, resource_path=self.index_path)
            logger().info(f"GET status from DUT is {status_dut} &  content_dut is {content_dut}")
        if method == "PUT":
            status_dut, content_dut = self.wifi_dut.interfaces.wifi.http_put(server=None, server_ip=sec_dut_ip, resource_path=self.index_path)
            logger().info(f"PUT status from DUT is {status_dut} &  content_dut is {content_dut}")
        if method == "POST":
            status_dut, content_dut = self.wifi_dut.interfaces.wifi.http_post(server=None, server_ip=sec_dut_ip, resource_path=self.index_path)
            logger().info(f"POST status from DUT is {status_dut} &  content_dut is {content_dut}")


@pytest.mark.skip("TC validation is in progree")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": 0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT
                              | Si91xExtTCPIPFeatureBitMap.Default,
        "ble_features": 0,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ble_custom_ext_features": 0,
        "band": 0,
        "boot_option": 49,
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
    }
)

@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_verify_http_functionality_with_GET_PUT_POST_using_our_Device_as_http_client_C547019(
        wifi_sniffer, wifi_dut, utf_constants, wifi_access_point, http_server, http_client,
        remote_wiseconnect3, sniffer_filter, sl_collections):
    """Verify HTTP functionality with GET, PUT, POST using our device as http client"""
    try:
        capture_filename = '547019.pcap'
        ping_count = utf_constants.get("ping_count")
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.
                                                             channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")
        index_path = "/test"

        logger().info(f"set_join from DUT2 is initiated")
        remote_wiseconnect3.interfaces.sapi.scan(channel=0, ssid=None)
        logger().info(f"scan from DUT2 is initiated")
        dut_addr = sl_collections.join_to_wifi_network(remote_wiseconnect3, wifi_access_point, associated=wifi_dut.interfaces.wifi.associated)

        logger().info(f"join from DUT2 mac address {dut_addr['dut_mac_address']} and its ip is {dut_addr['device_ip']}")
        logger().info(f"###### verifying GET functionality #######")
        remote_wiseconnect3.interfaces.wifi.http_server_init(http_port=80)
        logger().info(f"initiated http_server_init from DUT2")
        remote_wiseconnect3.interfaces.wifi.http_server_start()

        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, http_server=http_server, http_client=http_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                            index_path=index_path)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.http_client_init()
        wifi_obj.dut_http_functionality(method= "GET", sec_dut_ip=dut_addr['device_ip'])


        logger().info(f"initiating http_server_stop from DUT2")
        remote_wiseconnect3.interfaces.wifi.http_server_stop()
        remote_wiseconnect3.interfaces.wifi.http_server_deinit()

        logger().info(f"###### verifying PUT functionality #######")
        remote_wiseconnect3.interfaces.wifi.http_server_init(http_port=80)
        logger().info(f"initiated http_server_init from DUT2")
        remote_wiseconnect3.interfaces.wifi.http_server_start()
        wifi_obj.dut_http_functionality(method="PUT", sec_dut_ip=device_ip)
        logger().info(f"initiating http_server_stop from DUT2")
        remote_wiseconnect3.interfaces.wifi.http_server_stop()
        remote_wiseconnect3.interfaces.wifi.http_server_deinit()

        logger().info(f"###### verifying POST functionality #######")
        remote_wiseconnect3.interfaces.wifi.http_server_init(http_port=80)
        logger().info(f"initiated http_server_init from DUT2")
        remote_wiseconnect3.interfaces.wifi.http_server_start()
        wifi_obj.dut_http_functionality(method="POST", sec_dut_ip=device_ip)
        logger().info(f"initiating http_server_stop from DUT2")
        remote_wiseconnect3.interfaces.wifi.http_server_stop()
        remote_wiseconnect3.interfaces.wifi.http_server_deinit()


    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.http_client_deinit()
        wifi_dut.interfaces.wifi.leave()

@pytest.mark.skip("TC validation is in progree")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "config_features": 0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "bt_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT
                              | Si91xExtTCPIPFeatureBitMap.Default,
        "ble_features": 0,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ble_custom_ext_features": 0,
        "band": 0,
        "boot_option": 49,
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
    }
)

@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_verify_http_functionality_with_GET_PUT_POST_using_our_Device_as_http_client_for12hrs_C641378(
        wifi_sniffer, wifi_dut, utf_constants, wifi_access_point, http_server, http_client,
        remote_wiseconnect3, sniffer_filter, sl_collections):
    """Verify HTTP functionality with GET, PUT, POST using our device as http client"""
    try:
        capture_filename = '641378.pcap'
        ping_count = utf_constants.get("ping_count")

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.
                                                             channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")
        index_path = "/test"

        while sw.elapsed_sec < 43200:
            dut_addr = sl_collections.join_to_wifi_network(remote_wiseconnect3, wifi_access_point, associated=wifi_dut.interfaces.wifi.associated)

            logger().info(f"join from DUT2 mac address {dut_addr['dut_mac_address']} and its ip is {dut_addr['device_ip']}")
            logger().info(f"###### verifying GET functionality #######")
            remote_wiseconnect3.interfaces.wifi.http_server_init(http_port=80)
            logger().info(f"initiated http_server_init from DUT2")
            remote_wiseconnect3.interfaces.wifi.http_server_start()

            wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, http_server=http_server, http_client=http_client,
                                sl_collections=sl_collections, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                                index_path=index_path)

            wifi_obj.start()
            wifi_obj.wait_for_exit()
            wifi_dut.interfaces.wifi.http_client_init()
            wifi_obj.dut_http_functionality(method= "GET", sec_dut_ip=dut_addr['device_ip'])


            logger().info(f"initiating http_server_stop from DUT2")
            remote_wiseconnect3.interfaces.wifi.http_server_stop()
            remote_wiseconnect3.interfaces.wifi.http_server_deinit()

            logger().info(f"###### verifying PUT functionality #######")
            remote_wiseconnect3.interfaces.wifi.http_server_init(http_port=80)
            logger().info(f"initiated http_server_init from DUT2")
            remote_wiseconnect3.interfaces.wifi.http_server_start()
            wifi_obj.dut_http_functionality(method="PUT", sec_dut_ip=device_ip)
            logger().info(f"initiating http_server_stop from DUT2")
            remote_wiseconnect3.interfaces.wifi.http_server_stop()
            remote_wiseconnect3.interfaces.wifi.http_server_deinit()

            logger().info(f"###### verifying POST functionality #######")
            remote_wiseconnect3.interfaces.wifi.http_server_init(http_port=80)
            logger().info(f"initiated http_server_init from DUT2")
            remote_wiseconnect3.interfaces.wifi.http_server_start()
            wifi_obj.dut_http_functionality(method="POST", sec_dut_ip=device_ip)
            logger().info(f"initiating http_server_stop from DUT2")
            remote_wiseconnect3.interfaces.wifi.http_server_stop()
            remote_wiseconnect3.interfaces.wifi.http_server_deinit()
            time.sleep(10)


    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.http_client_deinit()
        wifi_dut.interfaces.wifi.leave()
