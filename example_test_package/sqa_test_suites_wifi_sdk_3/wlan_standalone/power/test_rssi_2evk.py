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


"""Test Author = Benazeer K
        1. Initiate the Pri-DUT as AP
        2. Initiate connection from Sec-DUT
        3. Initiate ping from the Sec-DUT
        4. Get the current signal strength of STA
        5. Do the attenuation from attenuator from 0 to 60
        6. while attenuation get all RSSI Values
        7. Disconnect the wifi client
setup requirement:
        1. Dual DUT(required 2 Soc917)                                        
        2. Attenuator 50PA-500
"""


def logger():
    return get_logger(__name__)


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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "us"
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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ssid": "power@silabs", "passphrase": "Automation@123",
        "region": 1,
        "region_code": "us"
    },
)
def test_wifi_sdk_sta_rssi_in_channel_1_c551266(wifi_dut, sl_collections, rf_attenuator, remote_wiseconnect3):
    """Verify RSSI with WPA2 security in Channel 1"""
    try:
        set_db_value = 0
        wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel=1, db_value=set_db_value)
        time.sleep(10)
        set_db_value = 0
        wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel=2, db_value=set_db_value)
        time.sleep(10)
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
        wifi_dut.interfaces.wifi.start_ap(ssid="power@silabs", security="wpa2", channel=1, psk="Automation@123",
                                          beacon_interval=100)
        time.sleep(30)
        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.join(ssid="power@silabs",
                                                 security="wpa2",
                                                 passphrase="Automation@123",
                                                 channel=1, timeout=60)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                     static_subnet=static_subnet,
                                                     static_gateway=static_gateway, timeout=10)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=5,
                                                 ping_timeout=10, ip_version='ipv4', ping_size=64)
        time.sleep(2)
        remote_wiseconnect3.interfaces.wifi.poll_signal_strength()
        time.sleep(2)

        for set_db_value in range(25):
            wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel=1, db_value=set_db_value)
            time.sleep(10)
            remote_wiseconnect3.interfaces.wifi.poll_signal_strength()
            time.sleep(5)
        remote_wiseconnect3.interfaces.sapi.leave()
        time.sleep(2)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info(f"Test Completed without execution")
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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "us"
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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ssid": "power@silabs", "passphrase": "Automation@123",
        "region": 1,
        "region_code": "us"
    },
)
def test_wifi_sdk_sta_rssi_in_channel_6_c551266(wifi_dut, sl_collections, rf_attenuator, remote_wiseconnect3):
    """Verify RSSI with WPA2 security in Channel 6"""
    try:
        set_db_value = 0
        wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel=1, db_value=set_db_value)
        time.sleep(10)
        set_db_value = 0
        wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel=2, db_value=set_db_value)
        time.sleep(10)
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
        wifi_dut.interfaces.wifi.start_ap(ssid="power@silabs", security="wpa2", channel=6, psk="Automation@123",
                                          beacon_interval=100)
        time.sleep(30)
        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.join(ssid="power@silabs",
                                                 security="wpa2",
                                                 passphrase="Automation@123",
                                                 channel=6, timeout=60)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                     static_subnet=static_subnet,
                                                     static_gateway=static_gateway, timeout=10)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=5,
                                                 ping_timeout=10, ip_version='ipv4', ping_size=64)
        time.sleep(2)
        remote_wiseconnect3.interfaces.wifi.poll_signal_strength()
        time.sleep(2)
        for set_db_value in range(25):
            wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel=1, db_value=set_db_value)
            time.sleep(10)
            remote_wiseconnect3.interfaces.wifi.poll_signal_strength()
            time.sleep(5)
        remote_wiseconnect3.interfaces.sapi.leave()
        time.sleep(2)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info(f"Test Completed without execution")
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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "us"
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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ssid": "power@silabs", "passphrase": "Automation@123",
        "region": 1,
        "region_code": "us"
    },
)
def test_wifi_sdk_sta_rssi_in_channel_11_c551266(wifi_dut, sl_collections, rf_attenuator, remote_wiseconnect3):
    """Verify RSSI with WPA2 security in Channel 11"""
    try:
        set_db_value = 0
        wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel=1, db_value=set_db_value)
        time.sleep(10)
        set_db_value = 0
        wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel=2, db_value=set_db_value)
        time.sleep(10)
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
        wifi_dut.interfaces.wifi.start_ap(ssid="power@silabs", security="wpa2", channel=11, psk="Automation@123",
                                          beacon_interval=100)
        time.sleep(30)
        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.join(ssid="power@silabs",
                                                 security="wpa2",
                                                 passphrase="Automation@123",
                                                 channel=11, timeout=60)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                     static_subnet=static_subnet,
                                                     static_gateway=static_gateway, timeout=10)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=5,
                                                 ping_timeout=10, ip_version='ipv4', ping_size=64)
        time.sleep(2)
        remote_wiseconnect3.interfaces.wifi.poll_signal_strength()
        time.sleep(2)
        for set_db_value in range(25):
            wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel=1, db_value=set_db_value)
            time.sleep(10)
            remote_wiseconnect3.interfaces.wifi.poll_signal_strength()
            time.sleep(5)
        remote_wiseconnect3.interfaces.sapi.leave()
        time.sleep(2)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info(f"Test Completed without execution")
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()