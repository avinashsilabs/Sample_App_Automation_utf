import time
import pytest
from random import randint
import random
import string
from utf.utf_config import UtfConfig
import re
from utf.interfaces.wifi import SecurityMode
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.wifi import WlanError
from utf.utils import print_dict
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes,\
    Si91xExtCustomFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xRegion, Si91xRegionCode, Si91xModuleType, Si91xJoinFeatureBitMap
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI


"""Test Author = Jyothi Nagireddy
        1. Start the sniffer before connection
        2. Initiate connection from Wifi client(evk)
        4. Initiate ping from the wifi client
        5. Disconnect the wifi client
        6. Stop the sniffer capture 
        7. Analysing all sniffer capture packets.
setup requirement:
        1. Dual DUT(Soc917)                                        
        2. Access Point(Third Party AP's)
"""


def logger():
    return get_logger(__name__)


class WifiConnectionThread(ThreadBase):
    def __init__(self, wifi_dut=None, remote_wiseconnect3=None,
                 sl_collections=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.sl_collections = sl_collections

    def ap_mode_start(self):
        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        self.wifi_dut.interfaces.wifi.start_ap(ssid="silabs_ap", security="wpa2", channel=11, psk="Automation@123",
                                               dtim_beacon_count=4, beacon_interval=100
                                               )
        time.sleep(15)

    def sta_connection(self):
        for count in range(0, 4):
            try:
                self.remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
                self.remote_wiseconnect3.interfaces.sapi.join(ssid="silabs_ap",
                                                              security="wpa2",
                                                              passphrase="Automation@123",
                                                              channel=11, timeout=60)
                time.sleep(5)
                break
            except Exception as e:
                logger().info(f"....Scanning for AP unsuccessfull....retrying for the {count + 1} iteration")
                logger().info(f"ERROR FOUND -> {str(e)}")
        time.sleep(2)

        self.remote_wiseconnect3.interfaces.sapi.start_ip(ip_version="ipv4", static_ip="192.168.100.77",
                                                          static_subnet="255.255.255.0",
                                                          static_gateway="192.168.100.76", timeout=10)
        self.remote_wiseconnect3.interfaces.sapi.ping(server_ip="192.168.100.76", num_ping_attempts=10,
                                                      ping_timeout=10, ip_version='ipv4', ping_size=64)


class IperfServerThread(ThreadBase):
    def __init__(self, remote_wiseconnect3, local_ip, remote_ip, timeout):
        super().__init__()
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.local_ip = local_ip
        self.remote_ip = remote_ip
        self.timeout = timeout

    def run(self):
        try:
            iperf_server = self.remote_wiseconnect3.interfaces.wifi.iperf(
                throughput_type=3, async_socket=1, ttl=30, local_ip=self.local_ip, remote_ip=self.remote_ip,
                timeout=self.timeout)
            logger().info("Iperf server started successfully")
        except Exception as e:
            logger().error(f"Iperf server error: {e}")


class IperfClientThread(ThreadBase):
    def __init__(self, wifi_dut, local_ip, remote_ip, timeout):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.local_ip = local_ip
        self.remote_ip = remote_ip
        self.timeout = timeout

    def run(self):
        try:
            iperf_client = self.wifi_dut.interfaces.wifi.iperf(
                throughput_type=1, async_socket=0, ttl=30, local_ip=self.local_ip, remote_ip=self.remote_ip,
                timeout=self.timeout)
            logger().info("Iperf client started successfully")
        except Exception as e:
            logger().error(f"Iperf client error: {e}")


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
        "region": 1,
        "region_code": "japan",
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
        "ssid": "sliabs_ap", "passphrase": "Automation@123",
        "region": 1,
        "region_code": "japan",
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_sta_japan_region_aput_c551266( wifi_dut,
                                             sl_collections, remote_wiseconnect3):
    """Verify APUT beacon with region JP, WPA2 security, Channel 14, DTIM 3 , Beacon interval 500ms configurations"""
    try:
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ip_version = 'ipv4'

        time.sleep(3)
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        time.sleep(2)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid="silabs_ap", security="wpa2", channel=14, psk="Automation@123",
                                          dtim_beacon_count=3, beacon_interval=500
                                          )
        time.sleep(30)
        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.join(ssid="silabs_ap",
                                                 security="wpa2",
                                                 passphrase="Automation@123",
                                                 channel=14, timeout=60)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                     static_subnet=static_subnet,
                                                     static_gateway=static_gateway, timeout=10)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=10,
                                                 ping_timeout=10, ip_version='ipv4', ping_size=64)

        remote_wiseconnect3.interfaces.sapi.leave()
        time.sleep(2)

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
        "region": 1,
        "region_code": "us",
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
        "ssid": "sliabs_ap", "passphrase": "Automation@123",
        "region": 1,
        "region_code": "us",
    },
)
@pytest.mark.parametrize("listen_interval", [500, 700, 1000])
@pytest.mark.legacy_deployed
def test_wifi_sdk_sta_with_listen_intervals_c19445(wifi_sniffer, wifi_dut,
                                                   sl_collections, remote_wiseconnect3, listen_interval):
    """APUT functionality ,when a STA connected with various listen intervals."""
    try:
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C19445.pcap")
        time.sleep(3)
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        time.sleep(2)
        sec_obj = WifiConnectionThread(wifi_dut=wifi_dut,
                                       remote_wiseconnect3=remote_wiseconnect3,
                                       sl_collections=sl_collections)
        sec_obj.ap_mode_start()
        remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(join_feature_bitmap=
                                                                    Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
        remote_wiseconnect3.interfaces.sapi.set_listen_interval(listen_interval=listen_interval)
        time.sleep(5)
        sec_obj.sta_connection()
        remote_wiseconnect3.interfaces.sapi.leave()
        time.sleep(2)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


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
        "region": 1,
        "region_code": "japan",
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
        "ssid": "sliabs_ap", "passphrase": "Automation@123",
        "region": 1,
        "region_code": "japan",
    },
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_ap_mode_scan_in_region_japan_c654502(wifi_dut, sl_collections, remote_wiseconnect3):
    """Verify APUT beacon with region JP, WPA2 security, Channel 14, DTIM 3 , Beacon interval 500ms configurations"""
    try:
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ip_version = 'ipv4'

        time.sleep(3)
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        time.sleep(2)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid="silabs_ap", security="wpa2", channel=14, psk="Automation@123",
                                          dtim_beacon_count=3, beacon_interval=500
                                          )
        time.sleep(30)
        logger().info("**********************Scanning after After AP start using on AP interface********************")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, interface="ap")
        time.sleep(20)
        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        time.sleep(2)
        logger().info("Scan Results:\n")
        assert len(scan_results) >= 1, " region based probe requests not seen in scan results"
        remote_wiseconnect3.interfaces.sapi.join(ssid="silabs_ap",
                                                 security="wpa2",
                                                 passphrase="Automation@123",
                                                 channel=14, timeout=60)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                     static_subnet=static_subnet,
                                                     static_gateway=static_gateway, timeout=10)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=10,
                                                 ping_timeout=10, ip_version='ipv4', ping_size=64)

        remote_wiseconnect3.interfaces.sapi.leave()
        time.sleep(2)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
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
        "region": 1,
        "region_code": "korea",
        "channel": 13,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP| Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "korea",
        "channel": 13,
    }
)
@pytest.mark.legacy_deployed
def test_wifi_sdk_sta_korea_region_ap_c477831(wifi_sniffer, wifi_dut,
                                              sl_collections, remote_wiseconnect3, utf_constants, sniffer_filter):
    """verify connection between 2 DUTs, one setup as STA and other setup as AP  channel 13 and region set to Korea"""
    try:
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ip_version = 'ipv4'

        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=13)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_c477831.pcap")
        time.sleep(3)

        sec_sdk_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {sec_sdk_mac}")
        ap_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {ap_mac}")
        time.sleep(2)

        sl_collections.configure_dut_in_static_ip(
            remote_wiseconnect3,
            static_ip="192.168.100.76",
            static_subnet="255.255.255.0",
            static_gateway="192.168.100.76"
        )

        remote_wiseconnect3.interfaces.wifi.start_ap(
            ssid="silabs_ap", security="wpa2", channel=13, psk="Automation@123"
        )
        time.sleep(30)

        wifi_dut.interfaces.wifi.scan(channel=None, ssid=None)
        time.sleep(2)

        wifi_dut.interfaces.wifi.join(
            ssid="silabs_ap",
            security="wpa2",
            passphrase="Automation@123",
            channel=13, timeout=100
        )
        time.sleep(2)

        wifi_dut.interfaces.wifi.start_ip(
            ip_version=ip_version, static_ip=static_ip,
            static_subnet=static_subnet, static_gateway=static_gateway, timeout=10
        )

        wifi_dut.interfaces.wifi.ping(
            server_ip=static_gateway, num_ping_attempts=10,
            ping_timeout=10, ip_version='ipv4', ping_size=64
        )
        logger().info("Initiating wlan but power save")
        logger().info("enabling wifi/bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=2, psp_type=0)

        # Start iperf server and client in separate threads
        server_thread = IperfServerThread(remote_wiseconnect3, local_ip='192.168.100.77', remote_ip='192.168.100.76',
                                          timeout=35)
        client_thread = IperfClientThread(wifi_dut, local_ip='192.168.100.77', remote_ip='192.168.100.76', timeout=35)

        server_thread.start()
        time.sleep(2)
        client_thread.start()

        client_thread.wait_for_exit()
        server_thread.wait_for_exit()
        time.sleep(5)

        wifi_dut.interfaces.wifi.leave()

        time.sleep(2)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


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
        "security": "WPA2", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
def test_wifi_sdk_wpa2_deauth_based_keep_alive_c551269(wifi_sniffer, wifi_dut, remote_wiseconnect3, sniffer_filter,
                                                  sl_collections):
    """Verify APUT Keep alive functionality with DEAUTH_BASED_KEEP_ALIVE configuration in WPA2"""
    ssid = "Concurent_ap"
    security = "wpa2"
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
        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid, security="wpa2", passphrase=password, channel=channel, timeout=60)

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
        "security": "WPA2", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
def test_wifi_sdk_wpa2_null_based_keep_alive_C551270(wifi_sniffer, wifi_dut, remote_wiseconnect3, sniffer_filter,
                                                sl_collections):
    """Verify APUT Keep alive functionality with NULL_BASED_KEEP_ALIVE configuration in WPA2 mode"""
    ssid = "Concurent_ap"
    security = "wpa2"
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
        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid, security="wpa2", passphrase=password, channel=channel, timeout=60)

        remote_wiseconnect3.interfaces.sapi.reset()

        logger().info(f"**** Setting APUT IDLE for {keep_alive_time*4} seconds")
        time.sleep(keep_alive_time*4.2)

        null_packets = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1, packet_filter2='    Arrival Time:')['find_packet_num']
        assert int(null_packets) == 4, "Not able to find 4 null-function"

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


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features":0,
        "ext_tcpip_features": 0,
        "security": "OPEN", "ssid": "SILABS_AP", "passphrase": "Automation@123", "channel": 11,
        "region": Si91xRegion.FromUser,
        "region_code": Si91xRegionCode.US
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               },
         },
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
    },
)
@pytest.mark.end_state("wifi_dut", wifi="reset")
def test_wifi_sdk_ping_from_nonps_to_ps_device_c19459(wifi_sniffer, wifi_dut, wifi_clients, remote_wiseconnect3,
                                                      sl_collections, sniffer_filter):
    """APUT's functionality when the station is inactive for 5 minutes"""
    try:
        logger().info("********** configuring the sniffer with APUT channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c19439")
        time.sleep(3)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count=1,
                                          beacon_interval=100,
                                          ht_caps=0)
        wifi_clients[0].interfaces.wifi.join()
        non_ps_device_ip = wifi_clients[0].interfaces.wifi.get_ip_address()

        rc, stdout, stderr = wifi_clients[0].interfaces.wifi.shell.execute(
            f"sudo ping -c 10 192.168.100.76")
        assert rc == 0, "Failed to ping to APUT"

        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        remote_wiseconnect3.interfaces.sapi.join(ssid="SILABS_AP", security="wpa2", passphrase="Automation@123",
                                                 channel=11,
                                                 timeout=60)
        ps_device_ip = remote_wiseconnect3.interfaces.sapi.start_ip(static_gateway="192.168.100.76").ip.decode()
        remote_wiseconnect3.interfaces.sapi.ping(server_ip="192.168.100.76")

        logger().info("....Applying performance profile mode : power_save_low_latency")
        remote_wiseconnect3.interfaces.wifi.set_performance_profile('power_save_low_latency', 0, 0, 0, 0)
        remote_wiseconnect3.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        rc, stdout, stderr = wifi_clients[0].interfaces.wifi.shell.execute(
            f"sudo ping -c 10 -i 2 {ps_device_ip}")
        assert rc == 0, "Failed to ping to APUT"

        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features":0,
        "ext_tcpip_features": 0,
        "security": "OPEN", "ssid": "SILABS_AP", "passphrase": "Automation@123", "channel": 11,
        "region": Si91xRegion.FromUser,
        "region_code": Si91xRegionCode.US
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               },
           1: {
                "security": "WPA2",
                "ssid": "SILABS_AP",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
               },
         },
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
    },
)
@pytest.mark.end_state("wifi_dut", wifi="reset")
def test_wifi_sdk_ping_between_nonps_devices_while_ps_device_is_connected_c19460(wifi_sniffer, wifi_dut, wifi_clients,
                                                                                 remote_wiseconnect3, sl_collections,
                                                                                 sniffer_filter):
    """Connect one power save enabled station to module.Connect two power save disabled stations to module and start
    sending from one power save disable station to another power save disabled station."""
    try:
        logger().info("********** configuring the sniffer with APUT channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c19439")
        time.sleep(3)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count=1,
                                          beacon_interval=100,
                                          ht_caps=0)
        wifi_clients[0].interfaces.wifi.join()
        non_ps_device_ip1 = wifi_clients[0].interfaces.wifi.get_ip_address()

        rc, stdout, stderr = wifi_clients[0].interfaces.wifi.shell.execute(
            f"sudo ping -c 10 192.168.100.76")
        assert rc == 0, "Failed to ping to APUT"

        wifi_clients[1].interfaces.wifi.join()

        non_ps_device_ip2 = wifi_clients[1].interfaces.wifi.get_ip_address()

        rc, stdout, stderr = wifi_clients[1].interfaces.wifi.shell.execute(
            f"sudo ping -c 10 192.168.100.76")
        assert rc == 0, "Failed to ping to APUT"

        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        remote_wiseconnect3.interfaces.sapi.join(ssid="SILABS_AP", security="wpa2", passphrase="Automation@123",
                                                 channel=11,
                                                 timeout=60)
        ps_device_ip = remote_wiseconnect3.interfaces.sapi.start_ip(static_gateway="192.168.100.76").ip.decode()
        remote_wiseconnect3.interfaces.sapi.ping(server_ip="192.168.100.76")

        logger().info("....Applying performance profile mode : power_save_low_latency")
        remote_wiseconnect3.interfaces.wifi.set_performance_profile('power_save_low_latency', 0, 0, 0, 0)
        remote_wiseconnect3.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        rc, stdout, stderr = wifi_clients[1].interfaces.wifi.shell.execute(
            f"sudo ping -c 10 {non_ps_device_ip1}")
        assert rc == 0, "Failed to ping to APUT"

        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
