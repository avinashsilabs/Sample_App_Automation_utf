import re
import time
import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.wifi import SecurityMode
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xExtCustomFeatureBitMap, Si91xJoinFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.interfaces.wifi import WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.iperf.iperf_utils import ping
from utf.utils.logger import get_logger


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9117
        1. Configuration of DUT in 2G : B/G/N/AX
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Enable the power save mode in DUT & BLE
        6. Stop the sniffer  
        7. Analyizing all sniffer capture packets for wpa3 enhancements
    setup requirement:
        1. DUT(RS9117)
        2. WSDK 3.0 Board
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Benazeer K
"""


class WifiConnectionThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_sniffer=None, remote_wiseconnect3=None, sniffer_filter=None,
                 test_name=None, test_case_no=None, sl_collections=None, ping_count=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.test_case_no = test_case_no
        self.test_name = test_name
        self.ping_count = ping_count
        self.sl_collections = sl_collections

    def run(self):
        if self.test_case_no == 537919:
            ssid = "Concurent_ap"
            security = "wpa3"
            password = "Automation@Silabs"
            channel = "1"
            dtim_count = "1"
            beacon_interval = "100"
            ht_caps = 1
            keepalive_type = 1
        if self.test_case_no == 537918:
            ssid = "Concurent_ap"
            security = "wpa3"
            password = "Automation@Silabs"
            channel = "1"
            dtim_count = "1"
            beacon_interval = "100"
            ht_caps = 1
            keepalive_type = 3
        if self.test_case_no == 463726:
            ssid = "Concurent_ap"
            security = "wpa3"
            password = "Automation@Silabs"
            channel = "1"
            dtim_count = "1"
            beacon_interval = "100"
            ht_caps = 1
        if self.test_case_no == 468602 or self.test_case_no == 468523 or self.test_case_no == 468525 or \
                self.test_case_no == 468526 or self.test_case_no == 468604 or self.test_case_no == 468622:
            ssid = "Concurent_ap"
            security = "wpa3_transition"
            password = "Automation@Silabs"
            channel = "1"
            dtim_count = "1"
            beacon_interval = "100"
            ht_caps = 1
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        if self.test_case_no == 537919 or self.test_case_no == 537918:
            self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                               dtim_beacon_count=dtim_count, beacon_interval=beacon_interval,
                                                   encryption=None, ht_caps=ht_caps, keepalive_type=keepalive_type)
        elif self.test_case_no == 468523 or self.test_case_no == 468525:
            self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                                   dtim_beacon_count=dtim_count, tdi_flags=1,
                                                   beacon_interval=beacon_interval, encryption=None,
                                                   ht_caps=ht_caps)
        elif self.test_case_no == 468526:
            self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                                   dtim_beacon_count=dtim_count, tdi_flags=0,
                                                   beacon_interval=beacon_interval, encryption=None,
                                                   ht_caps=ht_caps)
        else:
            self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                                   dtim_beacon_count=dtim_count,
                                                   beacon_interval=beacon_interval, encryption=None,
                                                   ht_caps=ht_caps)
        self.remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ip_version = 'ipv4'
        ssid = "Concurent_ap"
        channel = 1
        password = "Automation@Silabs"
        self.remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        time.sleep(2)
        if self.test_case_no == 468602:
            self.remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                     security="wpa2",
                                                     passphrase=password,
                                                     channel=channel, timeout=60)
        elif self.test_case_no == 468525 or self.test_case_no == 468526 or self.test_case_no == 468604:
            self.remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                     security="wpa3_transition",
                                                     passphrase=password,
                                                     channel=channel, timeout=60)
        else:
            self.remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                     security="wpa3",
                                                     passphrase=password,
                                                     channel=channel, timeout=60)
        self.remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                     static_subnet=static_subnet,
                                                     static_gateway=static_gateway, timeout=10)
        time.sleep(2)
        self.remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=self.ping_count,
                                           ping_timeout=10,  ip_version='ipv4', ping_size=64)
        time.sleep(2)

        if self.test_case_no == 468622:
            for i in range(1, 10):
                logger().info(f"============ iteration {i} : disconnect AP and connect again to AP ============")
                self.remote_wiseconnect3.interfaces.sapi.leave()
                time.sleep(10)
                self.remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                              security="wpa3_transition",
                                                              passphrase=password,
                                                              channel=channel, timeout=60)
                self.remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                                  static_subnet=static_subnet,
                                                                  static_gateway=static_gateway, timeout=10)
                self.remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway,
                                                              num_ping_attempts=self.ping_count,
                                                              ping_timeout=10, ip_version='ipv4', ping_size=64)

        if self.test_case_no == 468525 or self.test_case_no == 468526 or self.test_case_no == 468604:
            logger().info(f" Leave will happen at end of the test case")
        else:
            self.remote_wiseconnect3.interfaces.sapi.leave()
            time.sleep(1)
            self.wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Stop Sniffer finally")
            time.sleep(2)


class WifiPingThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_client=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client

    def run(self):
        ip_version = "ipv4"
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        logger().info(f"Initiate ping from DUT to third party wifi-client")
        self.wifi_dut.interfaces.wifi.ping(server_ip=host_ip, ip_version=ip_version, ping_size=64,
                                           num_ping_attempts=45)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_conn_wpa3_in_aput_func_deauth_C537919(wifi_sniffer, wifi_dut, utf_constants, request,
                                                        remote_wiseconnect3, sniffer_filter, sl_collections):
    """Verify WPA3 functionality with Deauth based"""
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        time.sleep(2)
        sec_obj = WifiConnectionThread(wifi_dut=wifi_dut, test_name=test_name, wifi_sniffer=wifi_sniffer,
                                             test_case_no=537919, remote_wiseconnect3=remote_wiseconnect3,
                                             sl_collections=sl_collections, ping_count=ping_count)
        sec_obj.start()
        sec_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac,
            filter_name="aput_wpa3_alone")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_conn_wpa3_in_aput_func_Keep_alive_C537918(wifi_sniffer, wifi_dut, utf_constants, request,
                                                        remote_wiseconnect3, sniffer_filter, sl_collections):
    """ Verify WPA3 functionality with Keep alive based"""
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        time.sleep(2)
        sec_obj = WifiConnectionThread(wifi_dut=wifi_dut, test_name=test_name, wifi_sniffer=wifi_sniffer,
                                             test_case_no=537918, remote_wiseconnect3=remote_wiseconnect3,
                                             sl_collections=sl_collections, ping_count=ping_count)
        sec_obj.start()
        sec_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac,
            filter_name="aput_wpa3_alone")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_aput_wpa3_with_wpa2_sta_C468602(wifi_sniffer, wifi_dut, utf_constants, request,
                                                        remote_wiseconnect3, sniffer_filter, sl_collections):
    """Verify WPA3 Transition functionality in APUT mode by connecting WPA2 STA do ping or any data transfer"""
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        time.sleep(2)
        sec_obj = WifiConnectionThread(wifi_dut=wifi_dut, test_name=test_name, wifi_sniffer=wifi_sniffer,
                                             test_case_no=468602, remote_wiseconnect3=remote_wiseconnect3,
                                             sl_collections=sl_collections, ping_count=ping_count)
        sec_obj.start()
        sec_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac,
            filter_name="aput_wpa3_mixed")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_aput_wpa3_with_wpa3_sta_func_C463726(wifi_sniffer, wifi_dut, utf_constants, request,
                                                        remote_wiseconnect3, sniffer_filter, sl_collections):
    """Verify Connect and ping 3rd party STA and Verify the APUT in functionality in WPA3 H2E mode."""
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        time.sleep(2)
        sec_obj = WifiConnectionThread(wifi_dut=wifi_dut, test_name=test_name, wifi_sniffer=wifi_sniffer,
                                             test_case_no=463726, remote_wiseconnect3=remote_wiseconnect3,
                                             sl_collections=sl_collections, ping_count=ping_count)
        sec_obj.start()
        sec_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac,
            filter_name="aput_wpa3_alone")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_aput_wpa3_with_full_sae_C468608(wifi_sniffer, wifi_dut, utf_constants, request,
                                                        remote_wiseconnect3, sniffer_filter, sl_collections):
    """Verify PMKSA func in APUT mode with WPA3 sec when STA is con-ting for the first time full SAE should happen"""
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        time.sleep(2)
        sec_obj = WifiConnectionThread(wifi_dut=wifi_dut, test_name=test_name, wifi_sniffer=wifi_sniffer,
                                             test_case_no=463726, remote_wiseconnect3=remote_wiseconnect3,
                                             sl_collections=sl_collections, ping_count=ping_count)
        sec_obj.start()
        sec_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=sec_sdk_mac,
            filter_name="wpa3_4_way_handshake_message")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_aput_wpa3_with_pmf_h2e_C463725(wifi_sniffer, wifi_dut, utf_constants, request,
                                                        remote_wiseconnect3, sniffer_filter, sl_collections):
    """Verify APUT beacon(Check PMF(Required, capable),RSNX IE along with H2E only membership) in WPA3 H2E mode"""
    try:
        ssid = "Concurent_ap"
        security = "wpa3"
        password = "Automation@Silabs"
        channel = "1"
        dtim_count = "1"
        beacon_interval = "100"
        ht_caps = 1
        test_name = request.node.name
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                          dtim_beacon_count=dtim_count,
                                          beacon_interval=beacon_interval, encryption=None,
                                          ht_caps=ht_caps)
        time.sleep(15)
        logger().info(f'Waiting 15 sec to capture the sniffer packets for sniffer validation')
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac,
            filter_name="concurrent_wpa3")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_aput_wpa3_with_full_transition_C468614(wifi_sniffer, wifi_dut, utf_constants, request,
                                                        remote_wiseconnect3, sniffer_filter, sl_collections):
    """Verify PMKSA func in APUT mode with WPA3 transition sec when STA is con-ting for the first time
        full SAE should happen"""
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        time.sleep(2)
        sec_obj = WifiConnectionThread(wifi_dut=wifi_dut, test_name=test_name, wifi_sniffer=wifi_sniffer,
                                             test_case_no=468602, remote_wiseconnect3=remote_wiseconnect3,
                                             sl_collections=sl_collections, ping_count=ping_count)
        sec_obj.start()
        sec_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=sec_sdk_mac,
            filter_name="wpa3_4_way_handshake_message")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_aput_wpa3_with_trasition_C468599(wifi_sniffer, wifi_dut, utf_constants, request,
                                                        remote_wiseconnect3, sniffer_filter, sl_collections):
    """Verify WPA3 Transition func in APUT mode by enabling MFP capable only and check in
      beacon RSN element should have AKM suite 2 and 8"""
    try:
        ssid = "Concurent_ap"
        security = "wpa3_transition"
        password = "Automation@Silabs"
        channel = "1"
        dtim_count = "1"
        beacon_interval = "100"
        ht_caps = 1
        test_name = request.node.name
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                          dtim_beacon_count=dtim_count,
                                          beacon_interval=beacon_interval, encryption=None,
                                          ht_caps=ht_caps)
        time.sleep(15)
        logger().info(f'Waiting 15 sec to capture the sniffer packets for sniffer validation')
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac,
            filter_name="aput_wpa3_mixed")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa3_in_enable_tdi_C468523(wifi_sniffer, wifi_dut, utf_constants, request, remote_wiseconnect3,
                                             sniffer_filter, sl_collections):
    """Verify WPA3 Transition functionality in APUT mode by enabling TDI and connect to
    WPA3 transition enabled STA do ping or any data transfer"""
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        time.sleep(2)
        sec_obj = WifiConnectionThread(wifi_dut=wifi_dut, test_name=test_name, wifi_sniffer=wifi_sniffer,
                                             test_case_no=468523, remote_wiseconnect3=remote_wiseconnect3,
                                             sl_collections=sl_collections, ping_count=ping_count)
        sec_obj.start()
        sec_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac,
            filter_name="aput_wpa3_mixed")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "passphrase": "Automation@Silabs", "ssid": 'Concurent_ap', "channel": 1})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa3_enable_tdi_aput_3rd_party_ap_C468525(wifi_access_point, wifi_sniffer, wifi_dut, utf_constants, request,
                                                        remote_wiseconnect3, sniffer_filter, sl_collections):
    """Enable TDI functionality in APUT mode with WPA3 transition mode , configure third party AP with same SSID as
    APUT but security in WPA2 after STA gets connected with APUT stop AP and check whether STA is able to connect to
    WPA2 enabled AP or not"""
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        time.sleep(2)
        wifi_access_point.interfaces.wifi.stop_ap()
        time.sleep(10)
        sec_obj = WifiConnectionThread(wifi_dut=wifi_dut, test_name=test_name, wifi_sniffer=wifi_sniffer,
                                             test_case_no=468525, remote_wiseconnect3=remote_wiseconnect3,
                                             sl_collections=sl_collections, ping_count=ping_count)
        sec_obj.start()
        sec_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        time.sleep(2)
        wifi_access_point.interfaces.wifi.start_ap()
        time.sleep(60)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac,
            filter_name="aput_wpa3_mixed")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=sec_sdk_mac, da_addr=ap_mac_address,
            filter_name="assoc_req_resp_eapol_4_way_handshake")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa2 packets connection flow packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_access_point.interfaces.wifi.stop_ap()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "passphrase": "Automation@Silabs", "ssid": 'Concurent_ap', "channel": 1})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa3_disable_tdi_aput_3rd_party_ap_C468526(wifi_access_point, wifi_sniffer, wifi_dut, utf_constants, request,
                                                        remote_wiseconnect3, sniffer_filter, sl_collections):
    """Disable TDI functionality in APUT mode with WPA3 transition mode , configure third party AP with same SSID as
    APUT but security in WPA2 after STA gets connected with APUT stop AP and check whether STA is able to connect to
    WPA2 enabled AP or not"""
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        time.sleep(2)
        wifi_access_point.interfaces.wifi.stop_ap()
        time.sleep(10)
        sec_obj = WifiConnectionThread(wifi_dut=wifi_dut, test_name=test_name, wifi_sniffer=wifi_sniffer,
                                             test_case_no=468526, remote_wiseconnect3=remote_wiseconnect3,
                                             sl_collections=sl_collections, ping_count=ping_count)
        sec_obj.start()
        sec_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        time.sleep(2)
        wifi_access_point.interfaces.wifi.start_ap()
        time.sleep(60)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac,
            filter_name="aput_wpa3_mixed")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=sec_sdk_mac, da_addr=ap_mac_address,
            filter_name="assoc_req_resp_eapol_4_way_handshake")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa2 packets connection flow packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_access_point.interfaces.wifi.stop_ap()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_aput_wpa3_with_start_stop_C468604(wifi_sniffer, wifi_dut, utf_constants, request,
                                                        remote_wiseconnect3, sniffer_filter, sl_collections):
    """Verify WPA3 Transition functionality in APUT mode by connecting WPA3 transition enabled STA do start and stop AP
for every 1 minute ping or any data transfe"""
    ssid = "Concurent_ap"
    security = "wpa3_transition"
    password = "Automation@Silabs"
    channel = "1"
    dtim_count = "1"
    beacon_interval = "100"
    ht_caps = 1
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        time.sleep(2)
        sec_obj = WifiConnectionThread(wifi_dut=wifi_dut, test_name=test_name, wifi_sniffer=wifi_sniffer,
                                       test_case_no=468604, remote_wiseconnect3=remote_wiseconnect3,
                                       sl_collections=sl_collections, ping_count=ping_count)
        sec_obj.start()
        sec_obj.wait_for_exit()
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            logger().info(f"Stopping & Starting AP for {i} iteration")
            wifi_dut.interfaces.wifi.stop_soft_ap_interface()
            time.sleep(10)
            wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                              dtim_beacon_count=dtim_count, beacon_interval=beacon_interval,
                                              encryption=None, ht_caps=ht_caps)
            logger().info(f"AP started successfully")
            logger().info(f"Waiting for 5 minute to start & stop AP")
            time.sleep(300)
        remote_wiseconnect3.interfaces.sapi.leave()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=sec_sdk_mac,
            filter_name="wpa3_4_way_handshake_message")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_null_based_keep_alive_c463728(wifi_sniffer, wifi_dut, remote_wiseconnect3, sniffer_filter,
                                                sl_collections):
    """Verify APUT Keep alive functionality(Sending NULL packet to STA on timer expire) in WPA3 H2E mode"""
    ssid = "Concurent_ap"
    security = "wpa3"
    password = "Automation@Silabs"
    channel = "1"
    dtim_count = "1"
    beacon_interval = 100
    ht_caps = 1
    keepalive_type = 3
    static_ip = "192.168.100.77"
    static_subnet = "255.255.255.0"
    static_gateway = "192.168.100.76"
    client_idle_timeout = 10
    keep_alive_time = (beacon_interval * 32 * client_idle_timeout)/1000
    try:
        aput_mac = wifi_dut.interfaces.wifi.get_mac_address()
        sta_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"**** APUT MAC: {aput_mac} and STA MAC: {sta_mac}")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=aput_mac,
                                                                                        da_addr=sta_mac,
                                                                                        filter_name='aput_wpa3_null_function')
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=aput_mac,
                                                                                        filter_name='deauthentication')
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="463728")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip=static_ip,
                                                  static_subnet=static_subnet,
                                                  static_gateway=static_gateway)
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                          dtim_beacon_count=dtim_count, beacon_interval=beacon_interval,
                                          encryption=None, ht_caps=ht_caps, keepalive_type=keepalive_type,
                                          client_idle_timeout=client_idle_timeout)
        remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid, security="wpa3", passphrase=password, channel=channel, timeout=60)

        remote_wiseconnect3.interfaces.sapi.reset()

        logger().info(f"**** Setting APUT IDLE for {keep_alive_time*3.8} seconds")
        time.sleep(keep_alive_time*3.8)

        null_packets = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1, packet_filter2='    Arrival Time:')['find_packet_num']
        assert int(null_packets) == 3, "Not able to find 3 null-function"

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count']

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        lines = filter_file.read()
        time_delta = re.findall(r'((?<=Time delta from previous displayed frame:\s)\d+)', lines)
        time_delta = set([int(i) for i in time_delta])
        for i in time_delta:
            assert i == 0 or i == keep_alive_time, "Getting different keep_alive interval"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_deauth_based_keep_alive_c463729(wifi_sniffer, wifi_dut, remote_wiseconnect3, sniffer_filter,
                                                  sl_collections):
    """Verify APUT Keep alive functionality(Triggering deauth directly on timer expire) in WPA3 H2E mode"""
    ssid = "Concurent_ap"
    security = "wpa3"
    password = "Automation@Silabs"
    channel = "1"
    dtim_count = "1"
    beacon_interval = 100
    ht_caps = 1
    keepalive_type = 1
    static_ip = "192.168.100.77"
    static_subnet = "255.255.255.0"
    static_gateway = "192.168.100.76"
    client_idle_timeout = 10
    keep_alive_time = (beacon_interval * 32 * client_idle_timeout) / 1000
    try:
        aput_mac = wifi_dut.interfaces.wifi.get_mac_address()
        sta_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"**** APUT MAC: {aput_mac} and STA MAC: {sta_mac}")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=aput_mac,
                                                                                        filter_name='deauthentication')
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="463729")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip=static_ip,
                                                  static_subnet=static_subnet,
                                                  static_gateway=static_gateway)
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                          dtim_beacon_count=dtim_count, beacon_interval=beacon_interval,
                                          encryption=None, ht_caps=ht_caps, keepalive_type=keepalive_type,
                                          client_idle_timeout=client_idle_timeout)
        remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid, security="wpa3", passphrase=password, channel=channel, timeout=60)

        remote_wiseconnect3.interfaces.sapi.reset()

        logger().info(f"**** Setting APUT IDLE for {keep_alive_time*2} seconds")
        time.sleep(keep_alive_time*2)

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_keep_alive_disable_c463730(wifi_sniffer, wifi_dut, remote_wiseconnect3, sniffer_filter,
                                             sl_collections):
    """Verify APUT functionality when keep alive is disable so when STA is IDLE AP should not discard STA"""
    ssid = "Concurent_ap"
    security = "wpa3"
    password = "Automation@Silabs"
    channel = "1"
    dtim_count = "1"
    beacon_interval = 100
    ht_caps = 1
    keepalive_type = 1
    static_ip = "192.168.100.77"
    static_subnet = "255.255.255.0"
    static_gateway = "192.168.100.76"
    client_idle_timeout = 10
    try:
        aput_mac = wifi_dut.interfaces.wifi.get_mac_address()
        sta_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"**** APUT MAC: {aput_mac} and STA MAC: {sta_mac}")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=aput_mac,
                                                                                        filter_name='deauthentication')
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="463730")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip=static_ip,
                                                  static_subnet=static_subnet,
                                                  static_gateway=static_gateway)
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                          dtim_beacon_count=dtim_count, beacon_interval=beacon_interval,
                                          encryption=None, ht_caps=ht_caps, keepalive_type=keepalive_type,
                                          client_idle_timeout=client_idle_timeout)
        remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid, security="wpa3", passphrase=password, channel=channel, timeout=60)
        remote_wiseconnect3.interfaces.sapi.reset()
        logger().info("**** Setting APUT IDLE for 60 seconds")
        time.sleep(60)

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
@pytest.mark.WLAN_Dev_sanity_917
def test_wifi_sdk_calculate_assoc_time_c463731(wifi_sniffer, wifi_dut, remote_wiseconnect3, sniffer_filter,
                                               sl_collections):
    """Verify 3rd party association time with APUT in WPA3 H2E mode(150 to 180 ms)"""
    ssid = "Concurent_ap"
    security = "wpa3"
    password = "Automation@Silabs"
    channel = "1"
    dtim_count = "1"
    beacon_interval = 100
    ht_caps = 1
    keepalive_type = 1
    static_ip = "192.168.100.77"
    static_subnet = "255.255.255.0"
    static_gateway = "192.168.100.76"
    client_idle_timeout = 10
    try:
        aput_mac = wifi_dut.interfaces.wifi.get_mac_address()
        sta_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"**** APUT MAC: {aput_mac} and STA MAC: {sta_mac}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="463731")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip=static_ip,
                                                  static_subnet=static_subnet,
                                                  static_gateway=static_gateway)
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                          dtim_beacon_count=dtim_count, beacon_interval=beacon_interval,
                                          encryption=None, ht_caps=ht_caps, keepalive_type=keepalive_type,
                                          client_idle_timeout=client_idle_timeout)
        remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid, security="wpa3", passphrase=password, channel=channel, timeout=60)
        remote_wiseconnect3.interfaces.sapi.start_ip(static_gateway=static_gateway)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_ip)
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=aput_mac,
                                                                                        ta_addr=sta_mac,
                                                                                        filter_name='assoc_req_resp')
        wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1, packet_filter2='    Arrival Time:')

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        lines = filter_file.read()
        time_delta = re.findall(r'((?<=Time delta from previous displayed frame:\s)\d+\.\d+)', lines)
        time_delta = [float(i) for i in time_delta]
        logger().info(f'**** Time delta: {time_delta}')
        assert time_delta[1] - time_delta[0] < 0.180, "Association exchange time is larger than 180 ms"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        wifi_sniffer.interfaces.capture.stop_capture()
        

@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_min_and_max_keepalive_c537917(wifi_sniffer, wifi_dut, remote_wiseconnect3, sniffer_filter,
                                                sl_collections):
    """Verify WPA3 functionality with minimum and maximum keep alive values """
    ssid = "Concurent_ap"
    security = "wpa3"
    password = "Automation@Silabs"
    channel = "1"
    dtim_count = "1"
    beacon_interval = 100
    ht_caps = 1
    keepalive_type = 3
    static_ip = "192.168.100.77"
    static_subnet = "255.255.255.0"
    static_gateway = "192.168.100.76"
    client_idle_timeout = 1
    keep_alive_time = (beacon_interval * 32 * client_idle_timeout) // 1000
    try:
        aput_mac = wifi_dut.interfaces.wifi.get_mac_address()
        sta_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"**** APUT MAC: {aput_mac} and STA MAC: {sta_mac}")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=aput_mac,
                                                                                        da_addr=sta_mac,
                                                                                        filter_name='aput_wpa3_null_function')

        for i in range(2):
            if i == 1:
                client_idle_timeout = 255
                keep_alive_time = (beacon_interval * 32 * client_idle_timeout) // 1000
                logger().info(f"\n\n **** Setting APUT IDLE for {keep_alive_time} seconds \n\n")
                wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                wifi_dut.interfaces.wifi.init(load_certificate=False)
                wifi_dut.interfaces.wifi.initialize_thread()
                wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
                remote_wiseconnect3.interfaces.wifi.test_agent_thread_enabled = False
                remote_wiseconnect3.interfaces.wifi.init(load_certificate=False)
                remote_wiseconnect3.interfaces.wifi.initialize_thread()
                remote_wiseconnect3.interfaces.wifi.test_agent_thread_enabled = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file="537917")
            sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip=static_ip,
                                                      static_subnet=static_subnet,
                                                      static_gateway=static_gateway)
            wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                              dtim_beacon_count=dtim_count, beacon_interval=beacon_interval,
                                              encryption=None, ht_caps=ht_caps, keepalive_type=keepalive_type,
                                              client_idle_timeout=client_idle_timeout)

            remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
            )
            remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
            remote_wiseconnect3.interfaces.sapi.join(ssid=ssid, security="wpa3", passphrase=password, channel=channel,
                                                     timeout=60)
            time.sleep(10)
            dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
            logger().info(f"**** AP DUT MAC: {dut_ap_mac_address}")
            packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_ap_mac_address,
                                                                                            filter_name='beacon_rsn_mfpr')

            remote_wiseconnect3.interfaces.sapi.reset()

            logger().info(f"**** Setting APUT IDLE for {keep_alive_time * 3.8} seconds")
            time.sleep(keep_alive_time * 3.8)

            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count']

            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                              packet_filter2='    Arrival Time:')[
                'find_packet_num']

            filter_file = open(f'./reports/filter2_file.txt', 'r')
            lines = filter_file.read()
            time_delta = re.findall(r'((?<=Time delta from previous displayed frame:\s)\d+)', lines)
            time_delta = set([int(i) for i in time_delta])
            for i in time_delta:
                assert i == 0 or i <= keep_alive_time + 30, "Getting different keep_alive interval"

            wifi_sniffer.interfaces.capture.stop_capture()
            wifi_dut.interfaces.wifi.stop_soft_ap_interface()
            time.sleep(2)
            wifi_dut.interfaces.wifi.reset()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
def test_wifi_sdk_rejoin_functionality_c463734(wifi_sniffer, wifi_dut, remote_wiseconnect3, sniffer_filter,
                                               sl_collections):
    """Verify rejoin functionality with APUT WPA3 H2E mode"""
    ssid = "Concurent_ap"
    security = "wpa3"
    password = "Automation@Silabs"
    channel = "1"
    dtim_count = "1"
    beacon_interval = 100
    ht_caps = 1
    keepalive_type = 0
    static_ip = "192.168.100.77"
    static_subnet = "255.255.255.0"
    static_gateway = "192.168.100.76"
    client_idle_timeout = 100
    try:
        aput_mac = wifi_dut.interfaces.wifi.get_mac_address()
        sta_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"**** APUT MAC: {aput_mac} and STA MAC: {sta_mac}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="463734")
        remote_wiseconnect3.interfaces.sapi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                            beacon_missed_count=40,
                                                                            first_time_retry_enable=0)

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip=static_ip,
                                                  static_subnet=static_subnet,
                                                  static_gateway=static_gateway)
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                          dtim_beacon_count=dtim_count, beacon_interval=beacon_interval,
                                          encryption=None, ht_caps=ht_caps, keepalive_type=keepalive_type,
                                          client_idle_timeout=client_idle_timeout)
        remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid, security=security, passphrase=password, channel=channel,
                                                 timeout=60)
        remote_wiseconnect3.interfaces.sapi.start_ip(static_gateway=static_gateway)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_ip)

        wifi_dut.interfaces.wifi.stop_soft_ap_interface()

        time.sleep(30)

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip=static_ip, static_subnet=static_subnet,
                                                  static_gateway=static_gateway)
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                          dtim_beacon_count=dtim_count, beacon_interval=beacon_interval,
                                          encryption=None, ht_caps=ht_caps, keepalive_type=keepalive_type,
                                          client_idle_timeout=client_idle_timeout)
        time.sleep(30)

        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_ip)

        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.deployed_25q4
def test_wifi_sdk_APUT_wpa3_functionality_client_interface_up_down_c468622(wifi_sniffer, wifi_dut, remote_wiseconnect3,
                                                                           sniffer_filter, request, utf_constants,
                                                                           sl_collections):
    test_name = request.node.name
    ping_count = utf_constants.get("ping_count")
    try:
        aput_mac = wifi_dut.interfaces.wifi.get_mac_address()
        sta_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"**** APUT MAC: {aput_mac} and STA MAC: {sta_mac}")
        sec_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, test_name=test_name,
                                       test_case_no=468622, remote_wiseconnect3=remote_wiseconnect3,
                                       sl_collections=sl_collections, ping_count=ping_count)
        sec_obj.start()
        sec_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=['reset'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
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
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "wpa3_transition", "ssid": "AP_WPA3_Transition", "passphrase": "Automation@123", "channel": 1
    },
)
def test_wifi_sdk_wpa3_transition_in_apmode_C468601(
        wifi_sniffer, wifi_dut, utf_constants, request, sl_collections, remote_wiseconnect3, sniffer_filter):
    """Verify WPA3 Transition functionality in APUT mode by connecting WPA3 transition enabled STA do ping or any data
     transfer after connection do reset in client and check behavior."""
    try:
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ssid = "AP_WPA3_Transition"
        password = "Automation@123"
        security = "wpa3_transition"
        ip_version = 'ipv4'
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=1)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        time.sleep(2)
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=1,
                                          psk=password, dtim_beacon_count=1, tdi_flags=1,
                                          beacon_interval=100, encryption=None, ht_caps=1)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.scan(channel=0)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                      security=security,
                                                      passphrase=password,
                                                      channel=1, timeout=60)
        remote_wiseconnect3.interfaces.sapi.start_ip()
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=ping_count,
                                                      ping_timeout=10, ip_version='ipv4', ping_size=64)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac,
            filter_name="aput_wpa3_mixed")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_wiseconnect3.interfaces.sapi.leave()
        wifi_dut.interfaces.wifi.reset()
