import time
import ipaddress
import pytest
import re
from datetime import datetime, date
from retry import retry
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping, print_dict
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.interfaces.wifi import WlanError
import random
import string
from random import randint
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116PowerSaveModes, RS9116PowerSaveProcedureTypes, RS9116TCPIPFeatureBitMap, RS9116CustomFeatureBitMap, \
    RS9116ExtCustomFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116OperatingMode, RS9116Band, SocketOptions, \
    SocketType, Cipher, DeviceConstants, RS9116StoreConfiguration
from utf import UtfDatabaseProperties


def logger():
    return get_logger(__name__)

"""
    Author : M.Harshitha

    Setup Requirement: DUT(RS9116) , EFR32, 1 Raspberry PI required,
    Raspi should be connected to AP and configured with static IP in ap page
    Access Point(Third Party AP'), Sniffer(NUC) , 
    Description:ip_conflict cases

"""

class Ip_Conflict(ThreadBase):

    def __init__(self, wifi_dut, wifi_access_point, mode, utf_constants, static_ip_wifi_client=True, static_ip_dut=True,
                     static_ip_dut_concurrent=True, static_ip_wifi_client_concurrent=True, dynamic=True, dynamic_ip_concurrent=True):
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
        wifi_client_ip = self.wifi_client.interfaces.wifi.start_ip()
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
                                                                          first_time_retry_enable=0, thread=True)
            mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(thread=True)
            logger().info(f"**** DUT MAC_Address is : {mac_address} ****")
            logger().info("****** Associating dut to AP *******")
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point, thread=True)
            time.sleep(10)
            if self.static_ip_wifi_client:
                logger().info("Sending static ip configuration address")
                self.wifi_client.interfaces.wifi.config["interface"] = "wlan0"
                wifi_client_ip, dut_ip, wifi_client_gateway_ip = self.wifi_client_join(dhcp_start=self.dhcp_start, dhcp_end=self.dhcp_end)
                time.sleep(10)
                with pytest.raises(WlanError) as exc_info:
                    result = self.wifi_dut.interfaces.wifi.start_ip(static_ip=wifi_client_ip, static_subnet=static_subnet,static_gateway=wifi_client_gateway_ip, thread=True)
                    logger().info(f"result : {result}")
                assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
            if self.static_ip_dut:
                wifi_client_ip, dut_ip, wifi_client_gateway_ip = self.wifi_client_join(dhcp_start=self.dhcp_start, dhcp_end=self.dhcp_end)
                logger().info("****** Configuring static ip to DUT****** ")
                self.wifi_dut.interfaces.wifi.start_ip(static_ip=dut_ip, static_subnet=static_subnet,static_gateway=wifi_client_gateway_ip, thread=True)
                device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8', thread=True)
                logger().info(f'Device is {device_ip}')
                status = ping(device_ip, ping_count)
                assert status is True, "DUT is not responding to ping request from third party device"
                logger().info(f"ping is successful")

        if self.mode=="dynamic":
            self.wifi_dut.interfaces.wifi.associated = False
            self.access_point_gateway()
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6, beacon_missed_count=40,
                                                                          first_time_retry_enable=0, thread=True)
            mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(thread=True)
            logger().info(f"**** DUT MAC_Address is : {mac_address}*****")
            logger().info(" ****** Associating dut to AP ******** ")
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point, thread=True)
            if self.dynamic:
                logger().info("***** Configuring dynamic ip to dut ******")
                with pytest.raises(WlanError) as exc_info:
                    result = self.wifi_dut.interfaces.wifi.start_ip(thread=True)
                    logger().info(f"result : {result}")
                assert exc_info.value.error_code == 0xFF9C, "The 0xFF9C Error is expected for this test"

        if self.mode=="static_in_concurrent":
            static_subnet = '255.255.255.0'
            self.access_point_gateway()
            ping_count = self.utf_constants.get("ping_count")
            wifi_client_ip, dut_ip, wifi_client_gateway_ip = self.wifi_client_join(dhcp_start=self.dhcp_start, dhcp_end=self.dhcp_end)
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address(thread=True)
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6, beacon_missed_count=40,
                                                                          first_time_retry_enable=0, thread=True)
            self.wifi_dut.interfaces.wifi.associated = False
            time.sleep(3)
            logger().info(f"starting RSI_DUT as ACCESS Point in channel no {self.channel}")
            ap_mac = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"***** AP mac is {ap_mac} *****")
            logger().info(f"***** DUT MAC_Address: {dut_mac_address} ******")
            logger().info("**** Starting DUT in AP mode ****** ")
            self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security="WPA2", passphrase="12345678",channel=8, thread=True)
            time.sleep(10)
            logger().info(" ********* Associating dut to AP ********* ")
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point, thread=True)
            if self.static_ip_dut_concurrent:
                logger().info("****** Configuring static ip to DUT****** ")
                self.wifi_dut.interfaces.wifi.start_ip(static_ip=dut_ip, static_subnet=static_subnet, static_gateway=wifi_client_gateway_ip, thread=True)
                device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8', thread=True)
                status = ping(device_ip, ping_count)
                assert status is True, "DUT is not responding to ping request from third party device"
                logger().info(f"ping is successful")
            if self.static_ip_wifi_client_concurrent:
                logger().info("****** Configuring static ip to Wifi Client****** ")
                with pytest.raises(WlanError) as exc_info:
                    result = self.wifi_dut.interfaces.wifi.start_ip(static_ip=wifi_client_ip, static_subnet=static_subnet, static_gateway=wifi_client_gateway_ip, thread=True)
                    logger().info(f"result : {result}")
                    assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"

        if self.mode=="dynamic_in_concurrent":
            self.access_point_gateway()
            ping_count = self.utf_constants.get("ping_count")
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0, thread=True)
            self.wifi_dut.interfaces.wifi.associated = False
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(thread=True)
            logger().info(f"starting RSI_DUT as ACCESS Point in channel no {self.channel}")
            ap_mac = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"***** AP Mac is {ap_mac}*****")
            logger().info(f"****** DUT MAC_Address: {dut_mac_address}****")
            logger().info("*******Starting DUT as an AP mode*******")
            self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security="WPA2", passphrase="12345678", channel=8, thread=True)
            time.sleep(10)
            logger().info("****** Associating dut to AP ******")
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point, thread=True)
            if self.dynamic_ip_concurrent:
                with pytest.raises(WlanError) as exc_info:
                    result = self.wifi_dut.interfaces.wifi.start_ip(thread=True)
                    logger().info(f"result : {result}")
                assert exc_info.value.error_code == 0xFF9C, "The 0xFF9C Error is expected for this test"
                ap_ip = self.wifi_access_point.interfaces.wifi.ap_test_ip
                dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
                dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
                self.wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end, dhcp_lease="3600")
                time.sleep(60)  # waiting for 60 seconds to rejoin
                for ip_count in range(4):
                    try:
                        ip_config = self.wifi_dut.interfaces.wifi.start_ip(thread=True)
                        assert isinstance(ip_config,
                                          self.wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {ip_config}"
                        dut_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8', thread=True)
                        break
                    except:
                        logger().info(f"Get IP address through dhcp process is failed. retry count -> {ip_count + 1}")
                        time.sleep(10)
                assert dut_ip, "ip setting in DUT has failed"
                logger().info(f'DUT ip {dut_ip}')
                logger().info("============ ip address sending ================")
                self.wifi_dut.interfaces.wifi.start_ip(thread=True)
                device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8', thread=True)
                status = ping(device_ip, ping_count)
                assert status is True, "DUT is not responding to ping request from third party device"
                logger().info(f"ping is successful")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101962(wifi_sniffer, wifi_dut, wifi_access_point, utf_constants):
    """Verify Static IP assignment when the existing IP is assigned to the DUT"""
    try:
        mode='static'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101962')
        wlan_obj = Ip_Conflict(wifi_dut, wifi_access_point, utf_constants, mode, static_ip_wifi_client=True, static_ip_dut=False,dynamic=False, dynamic_ip_concurrent=False,
                               static_ip_dut_concurrent=False, static_ip_wifi_client_concurrent=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101963(wifi_sniffer, wifi_dut, wifi_access_point, utf_constants):
    """Verify Static assignment to the DUT"""
    try:
        mode = 'static'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101962')
        wlan_obj = Ip_Conflict(wifi_dut, wifi_access_point, utf_constants, mode, static_ip_wifi_client=False, static_ip_dut=True, dynamic=False, dynamic_ip_concurrent=False,
                               static_ip_dut_concurrent=False, static_ip_wifi_client_concurrent=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101965(wifi_sniffer, wifi_dut, wifi_access_point, utf_constants):
    """Verify static ip assignment with and without IP conflict to the DUT"""
    try:
        mode='static'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101965')
        wlan_obj = Ip_Conflict(wifi_dut, wifi_access_point, utf_constants, mode, static_ip_wifi_client=True, static_ip_dut=True,
                                            dynamic=False, dynamic_ip_concurrent=False, static_ip_dut_concurrent=False, static_ip_wifi_client_concurrent=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101964(wifi_sniffer, wifi_dut, wifi_access_point, utf_constants):
    """Verify dynamic Ip assignment to the dut"""
    try:
        mode="dynamic"
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101964')
        wlan_obj = Ip_Conflict(wifi_dut, wifi_access_point, mode, utf_constants, dynamic=True, static_ip_dut=False, static_ip_wifi_client=False, dynamic_ip_concurrent=False,
                               static_ip_dut_concurrent=False, static_ip_wifi_client_concurrent=False,)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8', thread=True)
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101966(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants):
    """Verify dynamic IP assignment with and without IP conflict"""
    try:
        mode='dynamic'
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101966')
        wlan_obj = Ip_Conflict(wifi_dut, wifi_access_point, mode, utf_constants, dynamic=True, static_ip_dut=False, static_ip_wifi_client=False,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=False, static_ip_wifi_client_concurrent=False)
        ap_ip =wlan_obj.start()
        wlan_obj.wait_for_exit()
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                        dhcp_lease="3600")
        time.sleep(10)
        for retry_count in range(5):
            try:
                wifi_dut.interfaces.wifi.start_ip(thread=True)
                device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8', thread=True)
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
    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
@pytest.mark.config('wifi_access_point',
                    wifi={'ssid': 'IPConflict_Sil_916', 'security': 'WPA2', 'passphrase': 'test1234', 'channel': 8})
def test_wifi_sdk_ip_conflict_c101969(wifi_sniffer, wifi_dut, wifi_access_point, utf_constants):
    """ Verify Dynamic IP assignment when the dhcp pool got exhausted"""
    try:
        mode = 'dynamic'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101966')
        wlan_obj = Ip_Conflict(wifi_dut, wifi_access_point, mode, utf_constants, dynamic=True, static_ip_dut=False,static_ip_wifi_client=False,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=False, static_ip_wifi_client_concurrent=False, )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info("stops Sniffer Finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19312", "passphrase": "12345678", "channel": 8

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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101973(firmware_loader,wifi_sniffer,wifi_dut,wifi_access_point,utf_constants):
    """Verify the dynamic ip assignment in the concurrent mode"""
    try:
        mode ='dynamic_in_concurrent'
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101973')
        wlan_obj = Ip_Conflict(wifi_dut, wifi_access_point, mode, utf_constants, dynamic=False, static_ip_dut=False, static_ip_wifi_client=False,
                               dynamic_ip_concurrent=False, static_ip_dut_concurrent=False, static_ip_wifi_client_concurrent=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info("====ip address sending ====")
        wifi_dut.interfaces.wifi.start_ip(thread=True)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8', thread=True)
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C101971", "passphrase": "12345678", "channel": 8

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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101971(firmware_loader, wifi_sniffer, wifi_dut, wifi_access_point, utf_constants):
    """Verify dynamic ip assignment in the concurrent mode with and without ip conflict"""
    try:
        mode='dynamic_in_concurrent'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101971')
        wlan_obj = Ip_Conflict(wifi_dut, wifi_access_point, mode, utf_constants, dynamic=False, static_ip_dut=False,
                               dynamic_ip_concurrent=True, static_ip_wifi_client=False,
                               static_ip_dut_concurrent=False, static_ip_wifi_client_concurrent=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19312", "passphrase": "12345678", "channel": 8
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101972(firmware_loader, wifi_sniffer, wifi_dut, wifi_access_point,utf_constants):
    """Verify dynamic ip assignment in the concurrent mode when the dhcp pool is exhausted"""
    try:
        mode = 'dynamic_in_concurrent'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101972')
        wlan_obj = Ip_Conflict(wifi_dut, wifi_access_point, mode, utf_constants, dynamic=False, static_ip_dut=False,
                               dynamic_ip_concurrent=True, static_ip_wifi_client=False,
                               static_ip_dut_concurrent=False, static_ip_wifi_client_concurrent=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19312", "passphrase": "12345678", "channel": 8

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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101967(firmware_loader, wifi_sniffer, wifi_dut, wifi_access_point, utf_constants):
    """ Verify IP assignment when the dut is configured in concurrent mood """
    try:
        mode='static_in_concurrent'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101967')
        wlan_obj = Ip_Conflict(wifi_dut, wifi_access_point, utf_constants, mode, static_ip_dut_concurrent=True,static_ip_wifi_client=False, static_ip_dut=False,
                                                    dynamic=False, dynamic_ip_concurrent=False, static_ip_wifi_client_concurrent=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C101968", "passphrase": "12345678", "channel": 8

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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101968(firmware_loader, wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, utf_constants):
    """Verify static ip in the concurrent mode with ip conflict"""
    try:
        mode ='static_in_concurrent'
        wifi_client.interfaces.wifi.config["interface"] = "wlan0"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101968')
        wlan_obj = Ip_Conflict(wifi_dut, wifi_access_point, utf_constants, mode, static_ip_wifi_client_concurrent=True, static_ip_dut_concurrent=False,
                                    static_ip_wifi_client=False, static_ip_dut=False, dynamic=False, dynamic_ip_concurrent=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19312", "passphrase": "12345678", "channel": 8
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_wifi_sdk_ip_conflict_c101970(firmware_loader, wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, utf_constants):
    """ Verify static ip assignment in concurrent mode with and without ip conflict"""
    try:
        mode='static_in_concurrent'
        wifi_client.interfaces.wifi.config["interface"] = "wlan0"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c101968')
        wlan_obj = Ip_Conflict(wifi_dut, wifi_access_point, utf_constants, mode, static_ip_wifi_client_concurrent=True,
                                static_ip_dut_concurrent=True, static_ip_wifi_client=False, static_ip_dut=False, dynamic=False,
                               dynamic_ip_concurrent=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False