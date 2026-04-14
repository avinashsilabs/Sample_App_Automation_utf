import time
import pytest
from contextlib import suppress
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode, Si91xTCPIPFeatureBitMap, Si91xOperatingMode,
    Si91xExtTCPIPFeatureBitMap, Si91xFeatureBitMap, Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap,
)
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase

"""The testcases added in this file can run below test steps :
        1. Configuration of DUT
        2. Association of Third party AP's
        3. Get the valid IP address
        4. HTTP get request from the Raspberry-pi to DUT 

setup requirement:
        1. Soc Board - 2nos
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC Wifi Sniffer 

Author : Shaik Abdul Azeez

"""

def logger():
    return get_logger(__name__)


# (Re)initialize HTTP client cleanly on the DUT
def http_client_reinit(wifi_dut):
    try:
        wifi_dut.interfaces.wifi.http_client_deinit()
    except Exception:
        pass
    wifi_dut.interfaces.wifi.http_client_init()


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, capture_filename=None, wifi_access_point=None, wifi_sniffer=None,
                 http_server=None, http_client=None, sl_collections=None, sniffer_filter=None,
                 index_path=None, test_case=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.capture_filename = capture_filename
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.http_server = http_server
        self.http_client = http_client
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.index_path = index_path or "/"
        self.test_case = test_case
        self.dut_addr = None

    def run(self):
        self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point, associated=self.wifi_dut.interfaces.wifi.associated)

    def dut_http_functionality(self, method: str, server_ip: str):
        method = method.upper()
        if method == "GET":
            status, content = self.wifi_dut.interfaces.wifi.http_get(
                server=None, server_ip=server_ip, resource_path=self.index_path)
        elif method == "PUT":
            status, content = self.wifi_dut.interfaces.wifi.http_put(
                server=None, server_ip=server_ip, resource_path=self.index_path)
        elif method == "POST":
            status, content = self.wifi_dut.interfaces.wifi.http_post(
                server=None, server_ip=server_ip, resource_path=self.index_path)
        else:
            raise ValueError(f"Unsupported method {method}")
        logger().info(f"{method} status={status} content={content}")
        return status, content



@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": (Si91xFeatureBitMap.WPSSupportDisabled
                     | Si91xFeatureBitMap.Aggregation
                     | Si91xFeatureBitMap.OpenMode),
        "config_features": 0,
        "tcpip_features": (Si91xTCPIPFeatureBitMap.Default
                           | Si91xTCPIPFeatureBitMap.SSL
                           | Si91xTCPIPFeatureBitMap.HTTPClient),
        "bt_features": 0,
        "ext_tcpip_features": (Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                               | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                               | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT
                               | Si91xExtTCPIPFeatureBitMap.Default),
        "ble_features": 0,
        "ext_custom_features": (Si91xExtCustomFeatureBitMap.Default
                                | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode),
        "ble_custom_ext_features": 0,
        "band": 0,
        "boot_option": 49,
        "ca_cert": [
            ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
            ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
        ],
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": (Si91xTCPIPFeatureBitMap.Default
                           | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                           | Si91xTCPIPFeatureBitMap.DHCPv4Server),
        "ext_tcpip_features": (Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                               | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID),
        "ext_custom_features": (Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE
                                | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
                                | Si91xExtCustomFeatureBitMap.FeatureLowPower
                                | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                                | Si91xExtCustomFeatureBitMap.IEEE802_11W),
        "config_features": Si91xConfigFeatureBitMap.Default
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
@pytest.mark.test_src_map_id('C547019')
def test_wifi_sdk_verify_http_functionality_with_GET_PUT_POST_using_our_Device_as_http_client_C547019(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                                                      http_server, http_client, remote_wiseconnect3, sniffer_filter,
                                                                                                      sl_collections):
    """WiFi SDK Test: Verify HTTP functionality with GET, PUT, POST using our Device as HTTP client."""
    capture_filename = "547019.pcap"
    index_path = "/test"

    try:
        # Sniffer start
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        # Remote device (server) joins AP
        remote_wiseconnect3.interfaces.sapi.scan(channel=0, ssid=None)
        remote_info = sl_collections.join_to_wifi_network(remote_wiseconnect3, wifi_access_point,
                                                          associated=wifi_dut.interfaces.wifi.associated)
        remote_ip = remote_info["device_ip"]
        logger().info(f"Remote joined: mac={remote_info['dut_mac_address']} ip={remote_ip}")

        # DUT joins AP
        wifi_join = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                             wifi_sniffer=wifi_sniffer, http_server=http_server, http_client=http_client, sl_collections=sl_collections,
                             sniffer_filter=sniffer_filter, index_path=index_path)
        wifi_join.start()
        wifi_join.wait_for_exit()

        # Start HTTP server ONCE and keep it running
        remote_wiseconnect3.interfaces.wifi.http_server_init(http_port=80)
        remote_wiseconnect3.interfaces.wifi.http_server_start()

        # 3 rounds of GET, PUT, POST (client re-init each call)
        for round_idx in range(1, 4):
            logger().info(f"==== HTTP round {round_idx}/3 ====")
            for method in ("GET", "PUT", "POST"):
                logger().info(f"==== Verifying {method} (round {round_idx}) ====")
                http_client_reinit(wifi_dut)
                wifi_join.dut_http_functionality(method=method, server_ip=remote_ip)
                time.sleep(1)

        # Stop/deinit server
        remote_wiseconnect3.interfaces.wifi.http_server_stop()
        remote_wiseconnect3.interfaces.wifi.http_server_deinit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise
    finally:
        with suppress(Exception): wifi_dut.interfaces.wifi.http_client_deinit()
        with suppress(Exception): wifi_dut.interfaces.wifi.leave()
        with suppress(Exception): wifi_sniffer.interfaces.capture.stop_capture()



@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": (Si91xFeatureBitMap.WPSSupportDisabled
                     | Si91xFeatureBitMap.Aggregation
                     | Si91xFeatureBitMap.OpenMode),
        "config_features": 0,
        "tcpip_features": (Si91xTCPIPFeatureBitMap.Default
                           | Si91xTCPIPFeatureBitMap.SSL
                           | Si91xTCPIPFeatureBitMap.HTTPClient),
        "bt_features": 0,
        "ext_tcpip_features": (Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                               | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                               | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT
                               | Si91xExtTCPIPFeatureBitMap.Default),
        "ble_features": 0,
        "ext_custom_features": (Si91xExtCustomFeatureBitMap.Default
                                | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode),
        "ble_custom_ext_features": 0,
        "band": 0,
        "boot_option": 49,
        "ca_cert": [
            ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
            ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
        ],
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": (Si91xTCPIPFeatureBitMap.Default
                           | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                           | Si91xTCPIPFeatureBitMap.DHCPv4Server),
        "ext_tcpip_features": (Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                               | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID),
        "ext_custom_features": (Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE
                                | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
                                | Si91xExtCustomFeatureBitMap.FeatureLowPower
                                | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                                | Si91xExtCustomFeatureBitMap.IEEE802_11W),
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
@pytest.mark.test_src_map_id('C641378')
def test_wifi_sdk_verify_http_functionality_long_duration_GET_PUT_POST_using_our_Device_as_http_client_C641378(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                                                               remote_wiseconnect3, sl_collections, utf_constants):
    """WiFi SDK Test: Verify HTTP functionality long duration with GET, PUT, POST using our Device as HTTP client."""
    index_path = "/test"
    duration_s = int(utf_constants.get("long_duration"))
    end_ts = time.time() + duration_s
    capture_filename = "641378_longrun.pcap"

    # Sniffer start
    logger().info(f"[LONG] Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

    try:
        # Remote joins AP
        remote_wiseconnect3.interfaces.sapi.scan(channel=0, ssid=None)
        remote_info = sl_collections.join_to_wifi_network(remote_wiseconnect3, wifi_access_point, associated=wifi_dut.interfaces.wifi.associated)
        remote_ip = remote_info["device_ip"]
        logger().info(f"[LONG] Remote joined: mac={remote_info['dut_mac_address']} ip={remote_ip}")

        # DUT joins AP
        wifi_join = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections, index_path=index_path)
        wifi_join.start()
        wifi_join.wait_for_exit()

        # Start HTTP server once and keep it running
        remote_wiseconnect3.interfaces.wifi.http_server_init(http_port=80)
        remote_wiseconnect3.interfaces.wifi.http_server_start()

        # Loop until time budget expires; inside each loop, run 3 rounds of GET/PUT/POST
        while time.time() < end_ts:
            for round_idx in range(1, 4):
                logger().info(f"[LONG] HTTP round {round_idx}/3")
                for method in ("GET", "PUT", "POST"):
                    logger().info(f"[LONG] Verifying {method} (round {round_idx})")
                    http_client_reinit(wifi_dut)
                    wifi_join.dut_http_functionality(method=method, server_ip=remote_ip)
                    time.sleep(1)

        # Stop/deinit server
        remote_wiseconnect3.interfaces.wifi.http_server_stop()
        remote_wiseconnect3.interfaces.wifi.http_server_deinit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise
    finally:
        with suppress(Exception): wifi_dut.interfaces.wifi.http_client_deinit()
        with suppress(Exception): wifi_dut.interfaces.wifi.leave()
        with suppress(Exception): wifi_sniffer.interfaces.capture.stop_capture()
