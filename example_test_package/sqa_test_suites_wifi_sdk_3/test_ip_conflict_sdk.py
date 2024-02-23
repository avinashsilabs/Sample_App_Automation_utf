import ipaddress
from utf.utils.stopwatch import Stopwatch
import pytest
import re
from utf.utils.thread_base import ThreadBase
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping, print_dict
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf.interfaces.wifi import WlanError
import random
import string
import time
from random import randint
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xOperatingMode, SocketOptions, \
    Cipher, DeviceConstants


def logger():
    return get_logger(__name__)


"""
    Author : M.Harshitha

    Setup Requirement: 
       1. DUT(Soc917)
       2. Raspberry PI4
       3. Access point(Third Part AP's)
       4. Sniffer-NUC

    Description : Raspi should be connected to AP and configured with static IP in ap page

"""


class Ip_Conflict(ThreadBase):

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None, mode=None, dhcp_start=None,
                 dhcp_end=None, utf_constants=None, start_ap=True, static_ip=True, sl_collections=None,
                 test_case_id=None, ap_mode=True):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.mode = mode
        self.dhcp_start = dhcp_start
        self.dhcp_end = dhcp_end
        self.utf_constants = utf_constants
        self.sl_collections = sl_collections
        self.dut_addr = None
        self.start_ap = start_ap
        self.test_case_id = test_case_id
        self.static_ip = static_ip
        self.ap_mode = ap_mode

    def access_point_gateway(self):
        dhcp_start = self.wifi_access_point.interfaces.wifi.dhcp_start_addr
        dhcp_end = self.wifi_access_point.interfaces.wifi.dhcp_end_addr
        self.wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                              dhcp_lease="3600")
        logger().info(f" dhcp_start value {dhcp_start} and dhcp_end value {dhcp_end}")

    def wifi_client_join(self, dhcp_start=None, dhcp_end=None):
        if dhcp_start is None and dhcp_end is None:
            dhcp_start = self.wifi_access_point.interfaces.wifi.dhcp_start_addr
            dhcp_end = self.wifi_access_point.interfaces.wifi.dhcp_end_addr
        logger().info("**** Associating raspi to wifi AP *****")
        self.wifi_client.interfaces.wifi.join(security="WPA2", ssid="IPConflict_Sil_917", passphrase="test1234",
                                              channel='8')
        wifi_client_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        wifi_client_gateway_ip = self.wifi_client.interfaces.wifi.get_gateway_ip()
        if wifi_client_ip is None:
            raise ValueError("Wifi client IP address is None")
        wifi_client_start_ip = int(wifi_client_ip.split('.')[-1]) + 1
        if dhcp_start is None or dhcp_end is None:
            raise ValueError("dhcp_start and dhcp_end cannot be None")
        dhcp_start_value = int(dhcp_start.split('.')[-1])
        dhcp_end_value = int(dhcp_end.split('.')[-1])
        dut_ip = wifi_client_ip
        if wifi_client_start_ip >= dhcp_end_value:
            value = randint(dhcp_start_value, wifi_client_start_ip - 2)
        else:
            value = randint(wifi_client_start_ip, dhcp_end_value)
        dut_ip = re.sub("\d{1,3}$", str(value), dut_ip)
        assert ipaddress.ip_address(wifi_client_ip) > ipaddress.IPv4Address(
            '169.254.255.255'), f"RASPI IP Address is static ip--{wifi_client_ip} hence test is terminating"
        return wifi_client_ip, dut_ip, wifi_client_gateway_ip

    def static_ap_client(self):
        self.access_point_gateway()
        static_subnet = '255.255.255.0'
        constants = UtfConfig.instance().data.get("constants")
        hostname = constants.get("hostname").get("value")
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = self.wifi_client_join(dhcp_start=self.dhcp_start,
                                                                               dhcp_end=self.dhcp_end)
        if self.ap_mode:
            self.wifi_dut.interfaces.wifi.start_ap(security="WPA2", ssid="RS9117_AP_Silabs", dtim_beacon_count=3,
                                                   psk="12345678", channel=8, beacon_interval=100)

        self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        logger().info("****** Configuring static ip to DUT****** ")
        ap_client_ip = self.wifi_access_point.interfaces.wifi.read_ip_client_address(hostname)
        self.wifi_dut.interfaces.wifi.start_ip(static_ip=ap_client_ip, static_subnet=static_subnet,
                                               static_gateway=wifi_client_gateway_ip, vid=0,
                                               expected_status=SLStatus.SL_STATUS_SI91X_IP_CONFLICT_ERROR)
        logger().info(
            f" DUT unable tp configure ip address due to ip conflict, observed error code 0x1ff75 which is expected")
        if self.static_ip:
            self.wifi_dut.interfaces.wifi.start_ip(static_ip=dut_ip, static_subnet=static_subnet,
                                                   static_gateway=wifi_client_gateway_ip, vid=0)

    def run(self):
        if self.mode == "static":
            static_subnet = '255.255.255.0'
            self.access_point_gateway()
            wifi_client_ip, dut_ip, wifi_client_gateway_ip = self.wifi_client_join(dhcp_start=self.dhcp_start,
                                                                                   dhcp_end=self.dhcp_end)
            logger().info(f" DUT IP IS : {dut_ip}")
            if self.start_ap:
                self.wifi_dut.interfaces.wifi.start_ap(security="WPA2", ssid="RS9117_AP_Silabs", dtim_beacon_count=3,
                                                       psk="12345678",
                                                       channel=8, beacon_interval=100)
            self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            logger().info("****** Configuring static ip to DUT****** ")
            self.wifi_dut.interfaces.wifi.start_ip(static_ip=dut_ip, static_subnet=static_subnet,
                                                   static_gateway=wifi_client_gateway_ip, vid=0)

        if self.mode == "dynamic":
            self.access_point_gateway()
            if self.start_ap:
                self.wifi_dut.interfaces.wifi.start_ap(security="WPA2", ssid="RS9117_AP_Silabs", dtim_beacon_count=3,
                                                       psk="12345678", channel=8, beacon_interval=100)
            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     power_save=False,
                                                                     ping_after_power_save=True)
            logger().info(
                f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")

        if self.test_case_id == 101962:
            self.static_ap_client()

        if self.test_case_id == 101980:
            self.access_point_gateway()
            static_subnet = '255.255.255.0'
            constants = UtfConfig.instance().data.get("constants")
            hostname = constants.get("hostname").get("value")
            for i in range(1, 6):
                wifi_client_ip, dut_ip, wifi_client_gateway_ip = self.wifi_client_join(dhcp_start=self.dhcp_start,
                                                                                       dhcp_end=self.dhcp_end)
                ap_client_ip = self.wifi_access_point.interfaces.wifi.read_ip_client_address(hostname)
                logger().info(f" Expected Error Code for iteration count {i}")
                self.wifi_dut.interfaces.wifi.start_ip(static_ip=ap_client_ip, static_subnet=static_subnet,
                                                       static_gateway=wifi_client_gateway_ip, vid=0,
                                                       expected_status=SLStatus.SL_STATUS_SI91X_IP_CONFLICT_ERROR)
                logger().info(
                    f" DUT unable tp configure ip address due to ip conflict, observed error code 0x1ff75 which is"
                    f"expected")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_917',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_917", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_static_ip_assignment_to_DUT_c101963(wifi_dut, wifi_access_point, wifi_client, request,
                                                      sl_collections, utf_constants, wifi_sniffer):
    """Verify Static assignment to the DUT"""
    try:
        mode = 'static'
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                  mode=mode, start_ap=False, static_ip=False, ap_mode=False)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'Device is {device_ip}')
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_917',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_917", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_dynamic_ip_assignment_to_DUT_C101964(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, request,
                                                       sl_collections):
    """Verify dynamic ip assignment to the dut"""
    try:
        mode = 'dynamic'
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                  mode=mode, sl_collections=sl_collections, start_ap=False, static_ip=False, ap_mode=False)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "security": "WPA2", "ssid": "RS9117_AP_Silabs", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_917',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_917", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_static_ip_assignment_when_dut_in_concurrent_mode_c101967(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                           wifi_client, request, sl_collections,
                                                                           utf_constants):
    """Verify the dynamic ip assignment in the concurrent mode"""
    try:
        mode = 'static'
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                  mode=mode, start_ap=True, static_ip=False, ap_mode=False)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'Device is {device_ip}')
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "security": "WPA2", "ssid": "RS9117_AP_Silabs", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_917',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_917", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_dynamic_IP_Assignment_when_dut_in_concurrent_Mode_C101973(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                            wifi_client, request, sl_collections,
                                                                            utf_constants):
    """Verify the dynamic ip assignment in the concurrent mode"""
    try:
        mode = 'dynamic'
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                  mode=mode, sl_collections=sl_collections, start_ap=True, static_ip=False, ap_mode=False)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_917',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_917", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_static_ip_assignment_with_existing_ip_c101962(wifi_dut, wifi_sniffer, wifi_access_point, request,
                                                                wifi_client, sl_collections):
    """verifies the Static IP assignment to the device which is already existing in the Network"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                  test_case_id=101962, sl_collections=sl_collections, start_ap=False, static_ip=False, ap_mode=False)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_917',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_917", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_static_ip_assignment_with_and_Without_ip_Conflict_c101965(wifi_dut, wifi_sniffer, wifi_access_point,
                                                                            request, wifi_client, sl_collections):
    """Verifies Static ip assignment to the device when the existing ip is assigned to the DUT and then assign the
        non existing ip"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                  test_case_id=101962, sl_collections=sl_collections, start_ap=False, static_ip=True, ap_mode=False)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_917',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_917", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
def test_wifi_sdk_tcp_tx_once_ip_conflict_resolved_static_mode_c101974(wifi_dut, wifi_sniffer, wifi_access_point,
                                                                       request, wifi_client, sl_collections,
                                                                       net_perf_client,
                                                                       protocol, utf_constants):
    """ verifies the Static IP assignment to the device when the Existing IP is assigned to the
            DUT and then assign the non existing IP"""
    try:
        timeout = 30
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                  test_case_id=101962, sl_collections=sl_collections, start_ap=False, static_ip=True, ap_mode=False)

        wifi_thread.start()
        wifi_thread.wait_for_exit()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        logger().info("....Pinging to DUT.....")
        status = ping(device_ip, ping_count)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        logger().info("PING TO DUT IS SUCCESSFULLY DONE....")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=protocol,
                                   device_ip=device_ip, host_ip=host_ip, timeout=timeout, traffic_type="TX")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_917',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_917", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
def test_wifi_sdk_tcp_rx_once_ip_conflict_resolved_static_mode_c101975(wifi_dut, wifi_sniffer, wifi_access_point,
                                                                       request, wifi_client, sl_collections,
                                                                       net_perf_client,
                                                                       protocol, utf_constants):
    """ verifies the Static IP assignment to the device when the Existing IP is assigned to the
     DUT and then assign the Non existing IP"""
    try:
        timeout = 30
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                  test_case_id=101962, sl_collections=sl_collections, start_ap=False, static_ip=True, ap_mode=False)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        logger().info("....Pinging to DUT.....")
        status = ping(device_ip, ping_count)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        logger().info("PING TO DUT IS SUCCESSFULLY DONE....")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=protocol,
                                   device_ip=device_ip, host_ip=host_ip, timeout=timeout, traffic_type="RX")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_917',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_917", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
def test_wifi_sdk_udp_tx_once_ip_conflict_resolved_static_mode_c101976(wifi_dut, wifi_sniffer, wifi_access_point,
                                                                       request, wifi_client, sl_collections,
                                                                       net_perf_client, protocol, utf_constants):
    """ verifies the Static IP assignment to the device when the Existing IP is assigned to the
            DUT and then assign the non existing IP"""
    try:
        timeout = 30
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                  test_case_id=101962, sl_collections=sl_collections, start_ap=False, static_ip=True, ap_mode=False)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        logger().info("....Pinging to DUT.....")
        status = ping(device_ip, ping_count)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        logger().info("PING TO DUT IS SUCCESSFULLY DONE....")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=protocol,
                                   device_ip=device_ip, host_ip=host_ip, timeout=timeout, traffic_type="TX")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_917',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_917", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
def test_wifi_sdk_udp_rx_once_ip_conflict_resolved_static_mode_c101977(wifi_dut, wifi_sniffer, wifi_access_point,
                                                                       request, wifi_client, sl_collections,
                                                                       net_perf_client,
                                                                       protocol, utf_constants):
    """ verifies the Static IP assignment to the device when the Existing IP is assigned to the
     DUT and then assign the Non existing IP"""
    try:
        timeout = 30
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                  test_case_id=101962, sl_collections=sl_collections, start_ap=False, static_ip=True, ap_mode=False)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info("....Pinging to DUT.....")
        status = ping(device_ip, ping_count)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        logger().info("PING TO DUT IS SUCCESSFULLY DONE....")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=protocol,
                                   device_ip=device_ip, host_ip=host_ip, timeout=timeout, traffic_type="RX")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_917',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_917", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_static_ip_conflict_multiple_iterations_c101980(wifi_dut, wifi_sniffer, wifi_access_point, request,
                                                                 wifi_client, sl_collections):
    """verifies the Static ip conflict for multiple iterations"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        wifi_thread = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                  test_case_id=101980, sl_collections=sl_collections, start_ap=False, static_ip=False, ap_mode=False)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_917',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_917", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_ssl_tx_once_ip_conflict_resolved_in_static_ip_c101978(wifi_dut, wifi_sniffer, wifi_access_point,
                                                                        request, ssl_server, utf_constants,
                                                                        wifi_client, sl_collections):
    """verifies the ssl tx once ip conflict resolved in Static ip mode"""
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                  test_case_id=101962, sl_collections=sl_collections, start_ap=False, static_ip=True, ap_mode=False)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        logger().info("....Pinging to DUT.....")
        status = ping(device_ip, ping_count)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        logger().info("PING TO DUT IS SUCCESSFULLY DONE....")
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server()
        server_ip = ssl_server.interfaces.ssl.server_ip
        logger().info(f"SSL server started with server ip:{server_ip}")
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        # Socket binds at (device_ip, port) in DUT
        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=port1, timeout=15)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                  server_port=port1)
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            # The api returns 100 bytes of random data
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            logger().info(f"Sending data {data} over socket_no->{sock}")
            # DUT sends 100 bytes of data over ssl socket
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
            time.sleep(1)
            # SSL server receives the data over ssl socket
            server_socket_no = 1
            data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, buffer_size=len(data))
            logger().info(f"Data received on remote socket opened is {data_receive}")
            assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
            logger().info("Data sent by DUT and received on server is matching\n\n")
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger().info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_917',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_917", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_ssl_rx_once_ip_conflict_resolved_in_static_ip_c101979(wifi_dut, wifi_sniffer, wifi_access_point,
                                                                        request, ssl_server, utf_constants,
                                                                        wifi_client, sl_collections):
    """verifies the ssl rx once ip conflict resolved in Static ip mode"""
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                  test_case_id=101962, sl_collections=sl_collections, start_ap=False, static_ip=True, ap_mode=False)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        logger().info("....Pinging to DUT.....")
        status = ping(device_ip, ping_count)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        logger().info("PING TO DUT IS SUCCESSFULLY DONE....")
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server(port=port1)
        server_ip = ssl_server.interfaces.ssl.server_ip
        logger().info(f"SSL server started with server ip:{server_ip}")
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        # Socket binds at (device_ip, port) in DUT
        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                  server_port=port1)
        logger().info(f"sock: {sock}")
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            buffer_length = 100
            pkt_count = 1
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
            ssl_server.interfaces.ssl.send_data(1, pkt_count, buffer_length, message=tx_buffer)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger().info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        logger().info("Initiating wlan disconnect from DUT")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "security": "WPA2", "ssid": "RS9117_AP_Silabs", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_917',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_917", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_static_ip_with_ip_conflict_in_concurrent_mode_c101968(wifi_dut, wifi_sniffer, wifi_access_point,
                                                                        request, wifi_client, sl_collections):
    """verifies the dut in concurrent mode when the dut is assigned with existing ip address"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                  test_case_id=101962, sl_collections=sl_collections, start_ap=False, static_ip=False,
                                  ap_mode=True)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "security": "WPA2", "ssid": "RS9117_AP_Silabs", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_917',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_917", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_static_ip_with_and_without_ipconflict_when_dut_in_concurrent_mode_c101970(wifi_dut, wifi_sniffer,
                                                                                            wifi_access_point, request,
                                                                                            wifi_client, sl_collections):
    """verifies the dut in concurrent mode when the dut is assigned with existing ip s assigned to the DUT and
     then assign the non existing ip"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                  test_case_id=101962, sl_collections=sl_collections, ap_mode=True,
                                  static_ip=True, start_ap=False)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
