import time
import ipaddress
import pytest
import re
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping, print_dict
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf.interfaces.wifi import WlanError
import random
import string
from random import randint
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xOperatingMode, Si91xBand, SocketOptions, \
    SocketType, Cipher, DeviceConstants, Si91xStoreConfiguration
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf import UtfDatabaseProperties


def logger():
    return get_logger(__name__)

"""
    Author : M.Harshitha

    Setup Requirement: 
       1. DUT (Si917)
       2. Raspberry PI4
       3. Access point(Third Part AP's)
       4. Sniffer-NUC
       
    Description : Raspi should be connected to AP and configured with static IP in ap page

"""

class Ip_Conflict(ThreadBase):

    def __init__(self, wifi_dut=None, wifi_access_point=None, mode=None, utf_constants=None, static_ip_wifi_client=True,
                 static_ip_dut=True, static_ip_dut_concurrent=True, static_ip_wifi_client_concurrent=True, dynamic=True,
                 dynamic_ip_concurrent=True, dhcp_start=None, dhcp_end=None, wifi_client=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.mode = mode
        self.utf_constants = utf_constants
        self.static_ip_wifi_client = static_ip_wifi_client
        self.static_ip_dut = static_ip_dut
        self.static_ip_dut_concurrent = static_ip_dut_concurrent
        self.static_ip_wifi_client_concurrent = static_ip_wifi_client_concurrent
        self.dynamic = dynamic
        self.dynamic_ip_concurrent = dynamic_ip_concurrent
        self.dhcp_start = dhcp_start
        self.dhcp_end = dhcp_end
        self.wifi_client = wifi_client

    def access_point_gateway(self):
        ap_ip = self.wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP ip is {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        self.wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                     dhcp_lease="3600")
        logger().info(f" dhcp_start {dhcp_start} and dhcp_end value {dhcp_end}")

    def wifi_client_join(self, dhcp_start=None, dhcp_end=None):
        if dhcp_start and dhcp_end is None:
            ap_ip = self.wifi_access_point.interfaces.wifi.ap_test_ip
            assert ap_ip, "Please Add the AP test ip in the ap section of harness"
            logger().info(f"AP Ip {ap_ip}")
            dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
            dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        logger().info("**** Associating raspi to wifi AP *****")
        self.wifi_client.interfaces.wifi.join(security="WPA2", ssid="IPConflict_Sil_916", passphrase="test1234", channel='8')
        wifi_client_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"****** Wifi Client ip ******{wifi_client_ip}")
        wifi_client_gateway_ip = self.wifi_client.interfaces.wifi.get_gateway_ip()
        logger().info(f"***** Wifi Client gateway ip address *******{wifi_client_gateway_ip}")
        logger().info("*** After client join raspberry get the ip address: " + wifi_client_ip)
        wifi_client_start_ip = int(wifi_client_ip.split('.')[-1]) + 1
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

    def run(self):
        if self.mode=="static":
            static_subnet = '255.255.255.0'
            ping_count = self.utf_constants.get("ping_count")
            self.access_point_gateway()
            self.wifi_dut.interfaces.wifi.associated = False
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,beacon_missed_count=40,
                                                                          first_time_retry_enable=0)
            mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"**** DUT MAC_Address is : {mac_address} ****")
            logger().info("****** Associating dut to AP *******")
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            time.sleep(10)
            if self.static_ip_wifi_client:
                logger().info("Sending static ip configuration address")
                self.wifi_client.interfaces.wifi.config["interface"] = "wlan0"
                wifi_client_ip, dut_ip, wifi_client_gateway_ip = self.wifi_client_join(dhcp_start=self.dhcp_start, dhcp_end=self.dhcp_end)
                time.sleep(10)
                with pytest.raises(WlanError) as exc_info:
                    result = self.wifi_dut.interfaces.wifi.start_ip(static_ip=wifi_client_ip, static_subnet=static_subnet,static_gateway=wifi_client_gateway_ip)
                    logger().info(f"result : {result}")
                assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
            if self.static_ip_dut:
                wifi_client_ip, dut_ip, wifi_client_gateway_ip = self.wifi_client_join(dhcp_start=self.dhcp_start, dhcp_end=self.dhcp_end)
                logger().info("****** Configuring static ip to DUT****** ")
                self.wifi_dut.interfaces.wifi.start_ip(static_ip=dut_ip, static_subnet=static_subnet,static_gateway=wifi_client_gateway_ip)
                device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                logger().info(f'Device is {device_ip}')
                status = ping(device_ip, ping_count)
                assert status is True, "DUT is not responding to ping request from third party device"
                logger().info(f"ping is successful")

        if self.mode=="dynamic":
            self.wifi_dut.interfaces.wifi.associated = False
            self.access_point_gateway()
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6, beacon_missed_count=40,
                                                                          first_time_retry_enable=0)
            mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"**** DUT MAC_Address is : {mac_address}*****")
            logger().info(" ****** Associating dut to AP ******** ")
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            if self.dynamic:
                logger().info("***** Configuring dynamic ip to dut ******")
                with pytest.raises(WlanError) as exc_info:
                    result = self.wifi_dut.interfaces.wifi.start_ip()
                    logger().info(f"result : {result}")
                assert exc_info.value.error_code == 0xFF9C, "The 0xFF9C Error is expected for this test"

        if self.mode=="static_in_concurrent":
            static_subnet = '255.255.255.0'
            self.access_point_gateway()
            ping_count = self.utf_constants.get("ping_count")
            wifi_client_ip, dut_ip, wifi_client_gateway_ip = self.wifi_client_join(dhcp_start=self.dhcp_start, dhcp_end=self.dhcp_end)
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6, beacon_missed_count=40,
                                                                          first_time_retry_enable=0)
            self.wifi_dut.interfaces.wifi.associated = False
            time.sleep(3)
            logger().info(f"starting RSI_DUT as ACCESS Point in channel no {self.channel}")
            ap_mac = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"***** AP mac is {ap_mac} *****")
            logger().info(f"***** DUT MAC_Address: {dut_mac_address} ******")
            logger().info("**** Starting DUT in AP mode ****** ")
            self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security="WPA2", passphrase="12345678",channel=8)
            time.sleep(10)
            logger().info(" ********* Associating dut to AP ********* ")
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            if self.static_ip_dut_concurrent:
                logger().info("****** Configuring static ip to DUT****** ")
                self.wifi_dut.interfaces.wifi.start_ip(static_ip=dut_ip, static_subnet=static_subnet, static_gateway=wifi_client_gateway_ip)
                device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                status = ping(device_ip, ping_count)
                assert status is True, "DUT is not responding to ping request from third party device"
                logger().info(f"ping is successful")
            if self.static_ip_wifi_client_concurrent:
                logger().info("****** Configuring static ip to Wifi Client****** ")
                with pytest.raises(WlanError) as exc_info:
                    result = self.wifi_dut.interfaces.wifi.start_ip(static_ip=wifi_client_ip, static_subnet=static_subnet, static_gateway=wifi_client_gateway_ip)
                    logger().info(f"result : {result}")
                    assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"

        if self.mode=="dynamic_in_concurrent":
            self.access_point_gateway()
            ping_count = self.utf_constants.get("ping_count")
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
            self.wifi_dut.interfaces.wifi.associated = False
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"starting RSI_DUT as ACCESS Point in channel no {self.channel}")
            ap_mac = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"***** AP Mac is {ap_mac}*****")
            logger().info(f"****** DUT MAC_Address: {dut_mac_address}****")
            logger().info("*******Starting DUT as an AP mode*******")
            self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security="WPA2", passphrase="12345678", channel=8)
            time.sleep(10)
            logger().info("****** Associating dut to AP ******")
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            if self.dynamic_ip_concurrent:
                with pytest.raises(WlanError) as exc_info:
                    result = self.wifi_dut.interfaces.wifi.start_ip()
                    logger().info(f"result : {result}")
                assert exc_info.value.error_code == 0xFF9C, "The 0xFF9C Error is expected for this test"
                ap_ip = self.wifi_access_point.interfaces.wifi.ap_test_ip
                dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
                dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
                self.wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end, dhcp_lease="3600")
                time.sleep(60)  # waiting for 60 seconds to rejoin
                for ip_count in range(4):
                    try:
                        ip_config = self.wifi_dut.interfaces.wifi.start_ip()
                        assert isinstance(ip_config,
                                          self.wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {ip_config}"
                        dut_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                        break
                    except:
                        logger().info(f"Get IP address through dhcp process is failed. retry count -> {ip_count + 1}")
                        time.sleep(10)
                assert dut_ip, "ip setting in DUT has failed"
                logger().info(f'DUT ip {dut_ip}')
                logger().info("============ ip address sending ================")
                self.wifi_dut.interfaces.wifi.start_ip()
                device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                status = ping(device_ip, ping_count)
                assert status is True, "DUT is not responding to ping request from third party device"
                logger().info(f"ping is successful")

    def ssl_tx_rx(self):

        self.ssl_server.interfaces.ssl.start_server()
        # Open ssl client socket in the DUT
        sock = self.wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET', option_val=SocketOptions.SOL_SOCKET)
        self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE', option_val=SocketOptions.SO_SSL_ENABLE)
        self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE', option_val=SocketOptions.SSL_ENABLE)
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        # ssl socket opened in DUT connects to the server
        server_ip = self.ssl_server.interfaces.ssl.server_ip
        port1 = self.ssl_server.interfaces.ssl.config['device_port1']
        self.wifi_dut.interfaces.wifi.bsdSocketConnect(tsocket_fd=sock, server_ip=server_ip, server_port=port1)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101962(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, utf_constants, sl_collections):
    """Verify Static IP assignment when the existing IP is assigned to the DUT"""
    try:
        mode='static'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101962')
        wlan_obj = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, utf_constants=utf_constants
                               , mode=mode, static_ip_wifi_client=True, static_ip_dut=True, dynamic=False,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=False,
                               static_ip_wifi_client_concurrent=False, dhcp_start=None, dhcp_end=None,
                               wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101963(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, utf_constants, sl_collections):
    """Verify Static assignment to the DUT"""
    try:
        mode = 'static'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101962')
        wlan_obj = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, utf_constants=utf_constants
                               , mode=mode, static_ip_wifi_client=False, static_ip_dut=True, dynamic=False,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=False,
                               static_ip_wifi_client_concurrent=False, dhcp_start=None, dhcp_end=None,
                               wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101965(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, utf_constants, sl_collections):
    """Verify static ip assignment with and without IP conflict to the DUT"""
    try:
        mode='static'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101965')
        wlan_obj = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, utf_constants=utf_constants
                               , mode=mode, static_ip_wifi_client=True, static_ip_dut=True, dynamic=False,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=False,
                               static_ip_wifi_client_concurrent=False, dhcp_start=None, dhcp_end=None,
                               wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101964(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, utf_constants, sl_collections):
    """Verify dynamic Ip assignment to the dut"""
    try:
        mode="dynamic"
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101964')
        wlan_obj = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, utf_constants=utf_constants
                               , mode=mode, static_ip_wifi_client=False, static_ip_dut=False, dynamic=True,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=False,
                               static_ip_wifi_client_concurrent=False, dhcp_start=None, dhcp_end=None,
                               wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 6,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101966(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, wifi_client, sl_collections):
    """Verify dynamic IP assignment with and without IP conflict"""
    try:
        mode='dynamic'
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101966')
        wlan_obj = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, utf_constants=utf_constants
                               , mode=mode, static_ip_wifi_client=False, static_ip_dut=True, dynamic=True,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=False,
                               static_ip_wifi_client_concurrent=False, dhcp_start=None, dhcp_end=None,
                               wifi_client=wifi_client)
        ap_ip =wlan_obj.start()
        wlan_obj.wait_for_exit()
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                        dhcp_lease="3600")
        time.sleep(10)
        for retry_count in range(5):
            try:
                wifi_dut.interfaces.wifi.start_ip()
                device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            except Exception as err:
                logger().info(f"Failed to get dhcp ip..retry_count{retry_count + 1}\nException:{err}")
                time.sleep(10)
        for retry_count in range(5):
            try:
                logger().info(f"DUT ip {device_ip}")
                logger().info("pinging to dut.....")
                status = ping(device_ip, ping_count)
                assert status, "DUT not responding for ping request......"
                logger().info("ping to DUT is successful....")
                break
            except Exception as err:
                logger().info(f"Failed to ping to DUT...retry_count{retry_count + 1}\nException:{err}")
                time.sleep(10)
        assert status, "DUT not responding for ping request......"
        logger().info(f"ping is successful")
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
@pytest.mark.config('wifi_access_point',
                    wifi={'ssid': 'IPConflict_Sil_916', 'security': 'WPA2', 'passphrase': 'test1234', 'channel': 8})
def test_wifi_sdk_ip_conflict_c101969(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, utf_constants, sl_collections):
    """ Verify Dynamic IP assignment when the dhcp pool got exhausted"""
    try:
        mode = 'dynamic'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101966')
        wlan_obj = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, utf_constants=utf_constants
                               , mode=mode, static_ip_wifi_client=False, static_ip_dut=False, dynamic=True,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=False,
                               static_ip_wifi_client_concurrent=False, dhcp_start=None, dhcp_end=None,
                               wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info("stops Sniffer Finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": Si91xBand.TwoPointFourGHz,
        "security": "WPA2", "ssid": "Si91x_AP_C19312", "passphrase": "12345678", "channel": 8

    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101973(firmware_loader,wifi_sniffer,wifi_dut,wifi_access_point, wifi_client, utf_constants, sl_collections):
    """Verify the dynamic ip assignment in the concurrent mode"""
    try:
        mode ='dynamic_in_concurrent'
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101973')
        wlan_obj = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, utf_constants=utf_constants
                               , mode=mode, static_ip_wifi_client=False, static_ip_dut=False, dynamic=False,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=False,
                               static_ip_wifi_client_concurrent=False, dhcp_start=None, dhcp_end=None,
                               wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info("====ip address sending ====")
        wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": Si91xBand.TwoPointFourGHz,
        "security": "WPA2", "ssid": "Si91x_AP_C101971", "passphrase": "12345678", "channel": 8

    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101971(firmware_loader, wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, utf_constants, sl_collections):
    """Verify dynamic ip assignment in the concurrent mode with and without ip conflict"""
    try:
        mode='dynamic_in_concurrent'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101971')
        wlan_obj = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, utf_constants=utf_constants
                               , mode=mode, static_ip_wifi_client=False, static_ip_dut=False, dynamic=False,
                               dynamic_ip_concurrent=True, static_ip_dut_concurrent=False,
                               static_ip_wifi_client_concurrent=False, dhcp_start=None, dhcp_end=None,
                               wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": Si91xBand.TwoPointFourGHz,
        "security": "WPA2", "ssid": "Si91x_AP_C19312", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101972(firmware_loader, wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, utf_constants, sl_collections):
    """Verify dynamic ip assignment in the concurrent mode when the dhcp pool is exhausted"""
    try:
        mode = 'dynamic_in_concurrent'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101972')
        wlan_obj = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, utf_constants=utf_constants
                               , mode=mode, static_ip_wifi_client=False, static_ip_dut=False, dynamic=False,
                               dynamic_ip_concurrent=True, static_ip_dut_concurrent=False,
                               static_ip_wifi_client_concurrent=False, dhcp_start=None, dhcp_end=None,
                               wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": Si91xBand.TwoPointFourGHz,
        "security": "WPA2", "ssid": "Si91x_AP_C19312", "passphrase": "12345678", "channel": 8

    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101967(firmware_loader, wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, utf_constants, sl_collections):
    """ Verify IP assignment when the dut is configured in concurrent mood """
    try:
        mode='static_in_concurrent'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101967')
        wlan_obj = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, utf_constants=utf_constants
                               , mode=mode, static_ip_wifi_client=False, static_ip_dut=True, dynamic=False,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=True,
                               static_ip_wifi_client_concurrent=False, dhcp_start=None, dhcp_end=None,
                               wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": Si91xBand.TwoPointFourGHz,
        "security": "WPA2", "ssid": "Si91x_AP_C101968", "passphrase": "12345678", "channel": 8

    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8}
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101968(firmware_loader, wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, utf_constants, sl_collections):
    """Verify static ip in the concurrent mode with ip conflict"""
    try:
        mode ='static_in_concurrent'
        wifi_client.interfaces.wifi.config["interface"] = "wlan0"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101968')
        wlan_obj = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, utf_constants=utf_constants
                               , mode=mode, static_ip_wifi_client=True, static_ip_dut=True, dynamic=False,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=False,
                               static_ip_wifi_client_concurrent=False, dhcp_start=None, dhcp_end=None,
                               wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": Si91xBand.TwoPointFourGHz,
        "security": "WPA2", "ssid": "Si91x_AP_C19312", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101970(firmware_loader, wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, utf_constants, sl_collections):
    """ Verify static ip assignment in concurrent mode with and without ip conflict"""
    try:
        mode='static_in_concurrent'
        wifi_client.interfaces.wifi.config["interface"] = "wlan0"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101968')
        wlan_obj = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, utf_constants=utf_constants
                               , mode=mode, static_ip_wifi_client=False, static_ip_dut=False, dynamic=False,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=True,
                               static_ip_wifi_client_concurrent=True, dhcp_start=None, dhcp_end=None,
                               wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101980(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, self, utf_constants, sl_collections):
    """ Test case verify ip conflict detection for multiple iterations"""
    try:
        mode='static'
        loop_count = 5
        static_subnet = '255.255.255.0'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101980')
        wlan_obj = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, utf_constants=utf_constants
                               , mode=mode, static_ip_wifi_client=False, static_ip_dut=False, dynamic=False,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=True,
                               static_ip_wifi_client_concurrent=False, dhcp_start=None, dhcp_end=None,
                               wifi_client=wifi_client)
        wifi_client.interfaces.wifi.config["interface"] = "wlan0"
        logger().info("============ ip address sending ================")
        for i in range(0, loop_count):
            logger().info("Sending static ip configuration address")
            wifi_client.interfaces.wifi.config["interface"] = "wlan0"
            wifi_client_ip, dut_ip, wifi_client_gateway_ip = self.wifi_client_join()
            time.sleep(10)
            logger().info(" Assign the ip address in static mode and check for the conflict ")
            logger().info(f" Error code expected for iteration count {i} ")
            with pytest.raises(WlanError) as exc_info:
                result += result[i]
                result = wifi_dut.interfaces.wifi.start_ip(static_ip=wifi_client_ip, static_subnet=static_subnet,
                                                                static_gateway=wifi_client_gateway_ip)
                logger().info(f"result of static ip mode set of iteration {i} is : {result[i]}")
            assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
            time.sleep(10)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
@pytest.mark.config('wifi_access_point',
                    wifi={'ssid': 'IPConflict_Sil_916', 'security': 'WPA2', 'passphrase': 'test1234', 'channel': 8})
def test_wifi_sdk_ip_conflict_c101985(self,wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, utf_constants, sl_collections):
    """ Test case verify the ip conflict detection when the dhcp fails """
    try:
        mode='dynamic'
        static_subnet = '255.255.255.0'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101985')
        wlan_obj = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, utf_constants=utf_constants
                               , mode=mode, static_ip_wifi_client=False, static_ip_dut=False, dynamic=True,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=False,
                               static_ip_wifi_client_concurrent=False, dhcp_start=None, dhcp_end=None,
                               wifi_client=wifi_client)
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = self.wifi_client_join()
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.start_ip(static_ip=wifi_client_ip, static_subnet=static_subnet,
                                                          static_gateway=wifi_client_gateway_ip)
            logger().info(f"result {result}")
        assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "set_send_feature_frame": 1,
        "ca_cert": "ca-chain.cert.pem",
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101978(self, wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, wifi_client, utf_constants, sl_collections):
    """ Test Case to verify ssl tx once ip conflict is resolved"""
    try:
        mode='static'
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        bytes_sent = (pkt_count * buffer_length)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101978')
        wlan_obj = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, utf_constants=utf_constants
                               , mode=mode, static_ip_wifi_client=True, static_ip_dut=True, dynamic=False,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=False,
                               static_ip_wifi_client_concurrent=False, dhcp_start=None, dhcp_end=None,
                               wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        self.wifi_client.interfaces.wifi.config["interface"] = "Wlan0"
        sock = self.ssl_tx_rx()
        logger().info(f"****API returns 100 bytes of random data*****")
        data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        data_length = len(data_sent)
        logger().info(f"Sending data {data_sent} over socket_no->{sock}")
        logger().info(f" ******DUT sends 100 bytes of data over ssl socket*********")
        wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
        server_socket_no = 1
        logger().info(f"***####SSL server receives the data over ssl socket****####")
        data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
        logger().info(f"Data received on remote socket opened is {data_receive}")
        assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
        logger().info("Data sent by DUT and received on server is matching")

        if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
            ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
        result = wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
        logger().info(f"Number of bytes sent by dut {result}")
        bytes_sent = result
        bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
        logger().info(f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger().info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        time.sleep(2)
        wifi_dut.interfaces.wifi.leave()
        logger().info(f" Sniffer Stop Finally ")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "set_send_feature_frame": 1,
        "ca_cert": "ca-chain.cert.pem",
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101979(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, wifi_client, self, utf_constants, sl_collections):
    """ Test case to verify the ssl rx once the ip conflict is resolved"""
    try:
        mode = 'static'
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        bytes_sent = (pkt_count * buffer_length)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101979')
        wlan_obj = Ip_Conflict(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, utf_constants=utf_constants
                               , mode=mode, static_ip_wifi_client=True, static_ip_dut=True, dynamic=False,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=False,
                               static_ip_wifi_client_concurrent=False, dhcp_start=None, dhcp_end=None,
                               wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_client.interfaces.wifi.config["interface"] = "Wlan0"
        sock = self.ssl_tx_rx()
        server_socket_no = 1
        pkt_count = 50000
        duration = 60
        ssl_server.interfaces.ssl.send_data(server_socket_no, pkt_count, msg_length=buffer_length, duration=duration)
        time.sleep(80)
        bytes_sent = ssl_server.interfaces.ssl.data_send_stats(server_socket_no)
        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
        logger().info(f"*** result of rx_stats in wifi dut {result}")
        bytes_received = int(result.split(b":")[1])
        logger().info(f"bytes sent by remote peer -> {bytes_sent}")
        logger().info(f"bytes received on socket {sock} -> {bytes_received}")
        logger().info(f"SSL rx throughput ->  {((bytes_received * 8) / (1000 * 1000 * duration))} Mbps")
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger().info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        time.sleep(5)
        wifi_dut.interfaces.wifi.leave()
        logger().info(f" Sniffer Stop Finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)