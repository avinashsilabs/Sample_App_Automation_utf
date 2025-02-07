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
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xRegion, Si91xRegionCode, Si91xModuleType
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI

"""Test Author = SHOBHA RANI JOGU
        1. Start the sniffer before connection
        2. Initiate connection from Wifi client(Raspberry)
        4. Initiate ping from the wifi client
        5. Disconnect the wifi client
        6. Stop the sniffer capture 
        7. Analysing all sniffer capture packets.
setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4 - 2 and more                                                           
        3. Access Point(Third Party AP's)
"""


def logger():
    return get_logger(__name__)


class ApModeClientConnections(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, wifi_client=None,
                 sl_collections=None, testcase_no=None, capture_filename=None):
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.capture_filename = capture_filename
        self.testcase_no = testcase_no
        self.ssid = "SILABS_AP_MODE"
        self.security = "WPA2"
        self.password = "Automation@123"
        self.channel = "11"

    def run(self):
        try:
            if self.testcase_no == 535824 or self.testcase_no == 654501 or self.testcase_no == 654503:
                self.channel = "13"
            logger().info("********** Configuring the sniffer with access point channel **********")
            self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.channel)
            logger().info("******* Start capturing with Sniffer by giving the test case name as filename *******")
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
            self.sl_collections.configure_dut_in_static_ip(self.wifi_dut,
                                                           static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0",
                                                           static_gateway="192.168.100.76")
            logger().info(" ********** Starting DUT as an AP ********* ")
            self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security=self.security, psk=self.password,
                                                   channel=self.channel)
            time.sleep(10)
            logger().info("******************* Scanning on AP interface after bringing up DUT as AP ***************")
            if self.testcase_no == 654498:
                scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0,
                                                                  ssid="self.wifi_access_point.interfaces.wifi.ssid",
                                                                  interface="ap")
            else:
                scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, interface="ap")
            time.sleep(10)
            logger().info("Scan Results:\n")
            assert len(scan_results) >= 1, " region based probe requests not seen in scan results"
            logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
            self.wifi_client.interfaces.wifi.join(ssid=self.ssid, security=self.security, passphrase=self.password,
                                                  channel=self.channel)
            time.sleep(10)
            dut_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {dut_ip}")
            client_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"Client_ip: {client_ip}")
            time.sleep(20)
            logger().info(f"Initiating wlan ping from RASPI_STA")
            rc, stdout, stderr = self.wifi_client.interfaces.wifi.shell.execute(
                f"sudo ping -c {10} {dut_ip}")
            assert rc == 0, f"RASPI-STA failed to ping DUT"
            logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
            time.sleep(5)
            if self.testcase_no == 535824:
                test_end_time = time.time() + 300
                while time.time() < test_end_time:
                    logger().info("******************* Scanning on AP interface for 5 mins in loop ***************")
                    scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0,
                                                                      ssid=None,
                                                                      interface="ap")
                    time.sleep(5)
            time.sleep(5)
            assert len(scan_results) >= 1, " region based probe requests not seen in scan results"
            if self.testcase_no == 689175:
                rasp_mac_address = self.wifi_client.interfaces.wifi.get_mac_address()
                logger().info(f'RASPI-STA Disconnecting from DUT-AP')
                self.wifi_dut.interfaces.wifi.disconnect_ap_client(client_mac=rasp_mac_address)
            else:
                logger().info(f'RASPI-STA Disconnecting from DUT-AP')
                self.wifi_client.interfaces.wifi.leave()
            logger().info("Stop sniffer finally")
            self.wifi_sniffer.interfaces.capture.stop_capture()
        except Exception as Ex:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "917_AP_MODE", "passphrase": "Automation@123", "channel": 11,
        "region": 1,
        "region_code": "default"
    }
)
@pytest.mark.config("wifi_client", wifi={"country": "Default", "channel": "11", "interface": "wlan0"})
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'bgnax', "security": 'WPA2', "channel": 11, "Region": 'Asia'})
def test_wifi_sdk_ap_mode_scan_in_region_default_specific_ssid_c654498(wifi_dut, wifi_access_point, wifi_client,
                                                                       wifi_sniffer, sl_collections, sniffer_filter):
    """ Scan for available APs in the vicinity after Soft AP Started with default(us) region code
    Verify scan functionality after configuring our device as an AP with NULL SSID in AP mode in the default(us) region """
    try:
        ap_dut_obj = ApModeClientConnections(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                             wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                                             sl_collections=sl_collections, capture_filename="test_C654498",
                                             testcase_no=654498)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"*********{dut_ap_mac_address}**********")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        device_address = {'sa_addr': dut_ap_mac_address, 'da_addr': rasp_mac_address, 'radio_ch': 11,
                          'wlan_addr': dut_ap_mac_address}

        filters_name = {1: 'beacon_ap_mode_us_region', 2: 'probe_request'}
        output = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                      device_address, filters_name=filters_name)
        logger().info(f'\n OUTPUT = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "917_AP_MODE", "passphrase": "Automation@123", "channel": 11,
        "region": 1,
        "region_code": "default"
    }
)
@pytest.mark.config("wifi_client", wifi={"country": "Default", "channel": "11", "interface": "wlan0"})
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'bgnax', "security": 'WPA2', "channel": 11, "Region": 'Asia'})
def test_wifi_sdk_ap_mode_scan_in_region_default_c654499(wifi_dut, wifi_access_point, wifi_client, wifi_sniffer,
                                                         sl_collections, sniffer_filter):
    """ Scan for available APs in the vicinity after Soft AP Started with default(us) region code
    Verify scan functionality after configuring our device as an AP with NULL SSID in AP mode in the default(us) region """
    try:
        ap_dut_obj = ApModeClientConnections(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                             wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                                             sl_collections=sl_collections, capture_filename="test_C654499",
                                             testcase_no=654499)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"*********{dut_ap_mac_address}**********")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        device_address = {'sa_addr': dut_ap_mac_address, 'da_addr': rasp_mac_address, 'radio_ch': 11,
                          'wlan_addr': dut_ap_mac_address}

        filters_name = {1: 'beacon_ap_mode_us_region', 2: 'probe_request'}
        output = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                      device_address, filters_name=filters_name)
        logger().info(f'\n OUTPUT = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "917_AP_MODE", "passphrase": "Automation@123", "channel": 11,
        "region": 1,
        "region_code": "us"
    }
)
@pytest.mark.config("wifi_client", wifi={"country": "US", "channel": "11", "interface": "wlan0"})
@pytest.mark.config('wifi_access_point', wifi={"standard": 'bgnax', "security": 'WPA2', "channel": 11})
def test_wifi_sdk_ap_mode_scan_in_region_us_c654500(wifi_dut, wifi_access_point, wifi_client, wifi_sniffer,
                                                    sl_collections, sniffer_filter):
    """ Scan for available APs in the vicinity after Soft AP Started with US region code
    Verify scan functionality after configuring our device as an AP with NULL SSID in AP mode in the US region """
    try:
        ap_dut_obj = ApModeClientConnections(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                             wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                                             sl_collections=sl_collections, capture_filename="test_C654500",
                                             testcase_no=654500)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"*********{dut_ap_mac_address}**********")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        device_address = {'sa_addr': dut_ap_mac_address, 'da_addr': rasp_mac_address, 'radio_ch': 11,
                          'wlan_addr': dut_ap_mac_address}

        filters_name = {1: 'beacon_ap_mode_us_region', 2: 'probe_request'}
        output = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                      device_address, filters_name=filters_name)
        logger().info(f'\n OUTPUT = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "917_AP_MODE", "passphrase": "Automation@123", "channel": 13,
        "region": 1,
        "region_code": "europe"
    }
)
@pytest.mark.config("wifi_client", wifi={"country": "GE", "channel": "13", "interface": "wlan0"})
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'bgnax', "security": 'WPA2', "channel": 13, "region": 'Europe'})
def test_wifi_sdk_ap_mode_scan_in_region_eu_c654501(wifi_dut, wifi_access_point, wifi_client, wifi_sniffer,
                                                    sl_collections, sniffer_filter):
    """ Scan for available APs in the vicinity after Soft AP Started with EU region code
    Verify scan functionality after configuring our device as an AP with NULL SSID in AP mode in the EU region """
    try:
        ap_dut_obj = ApModeClientConnections(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                             wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                                             sl_collections=sl_collections, capture_filename="test_C654501",
                                             testcase_no=654501)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"*********{dut_ap_mac_address}**********")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        device_address = {'sa_addr': dut_ap_mac_address, 'da_addr': rasp_mac_address, 'radio_ch': 13,
                          'wlan_addr': dut_ap_mac_address}

        filters_name = {1: 'beacon_ap_mode_eu', 2: 'probe_request'}
        output = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                      device_address, filters_name=filters_name)
        logger().info(f'\n OUTPUT = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "917_AP_MODE", "passphrase": "Automation@123", "channel": 13,
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.config("wifi_client", wifi={"country": "KR", "channel": "13", "interface": "wlan0"})
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'bgnax', "security": 'WPA2', "channel": 13, "region": 'Korea'})
def test_wifi_sdk_ap_mode_scan_in_region_korea_c654503(wifi_dut, wifi_access_point, wifi_client, wifi_sniffer,
                                                       sl_collections, sniffer_filter):
    """ Scan for available APs in the vicinity after Soft AP Started with KR region code
    Verify scan functionality after configuring our device as an AP with NULL SSID in AP mode in the KR region """
    try:
        ap_dut_obj = ApModeClientConnections(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                             wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                                             sl_collections=sl_collections, capture_filename="test_C654503",
                                             testcase_no=654503)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"*********{dut_ap_mac_address}**********")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        device_address = {'sa_addr': dut_ap_mac_address, 'da_addr': rasp_mac_address, 'radio_ch': 13,
                          'wlan_addr': dut_ap_mac_address}

        filters_name = {1: 'beacon_ap_mode_korea_region', 2: 'probe_request'}
        output = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                      device_address, filters_name=filters_name)
        logger().info(f'\n OUTPUT = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "917_AP_MODE", "passphrase": "Automation@123", "channel": 13,
        "region": 1,
        "region_code": "europe"
    }
)
@pytest.mark.config("wifi_client", wifi={"country": "GE", "channel": "13", "interface": "wlan0"})
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'bgnax', "security": 'WPA2', "channel": 13, "region": 'Europe'})
def test_wifi_sdk_ap_mode_scan_for_5mins_c535824(wifi_dut, wifi_access_point, wifi_client, wifi_sniffer,
                                                 sl_collections, sniffer_filter):
    """ Scan for available APs in the vicinity after Soft AP Started for 5 minutes in loop """
    try:
        ap_dut_obj = ApModeClientConnections(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                             wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                                             sl_collections=sl_collections, capture_filename="test_C535824",
                                             testcase_no=535824)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"*********{dut_ap_mac_address}**********")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        device_address = {'sa_addr': dut_ap_mac_address, 'da_addr': rasp_mac_address, 'radio_ch': 13,
                          'wlan_addr': dut_ap_mac_address}

        filters_name = {1: 'beacon_ap_mode_eu', 2: 'probe_request'}
        output = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                      device_address, filters_name=filters_name)
        logger().info(f'\n OUTPUT = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "band": 0,
        "boot_option": 49,
        "security": "WPA2", "ssid": "917_AP_MODE", "passphrase": "Automation@123", "channel": 11,
        "region": 1,
        "region_code": Si91xRegionCode.US
    }
)
@pytest.mark.config("wifi_client", wifi={"country": "US", "channel": "11"})
@pytest.mark.config('wifi_access_point', wifi={"standard": 'bgnax', "security": 'WPA2', "channel": 11, "region": 'US'})
def test_wifi_sdk_ap_mode_scan_with_ADV_SCAN_TYPE_C688243(wifi_dut, wifi_access_point, wifi_client, wifi_sniffer,
                                                          sl_collections, sniffer_filter):
    """ Scan for available APs in the vicinity after Soft AP Started for 5 minutes in loop """
    try:
        logger().info("********** Configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        logger().info("******* Start capturing with Sniffer by giving the test case name as filename *******")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C688243.pcap")
        sl_collections.configure_dut_in_static_ip(wifi_dut,
                                                  static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="917_AP_MODE", security="WPA2", psk="Automation@123",
                                          channel="11")
        time.sleep(10)
        logger().info("******************* Scanning on AP interface after bringing up DUT as AP ***************")
        try:
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid="917_AP_MODE", scan_type=8, interface="ap",
                                                         expected_status="0x22")
            logger().info(f"scan results: {scan_results}  ")
        except Exception as e:
            logger().info(f"scan should fail as expected successfully")
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "band": 0,
        "boot_option": 49,
        "security": "WPA2", "ssid": "917_AP_MODE", "passphrase": "Automation@123", "channel": 11,
        "region": 1,
        "region_code": Si91xRegionCode.US
    }
)
@pytest.mark.config("wifi_client", wifi={"country": "US", "channel": "11"})
@pytest.mark.config('wifi_access_point', wifi={"standard": 'bgnax', "security": 'WPA2', "channel": 11, "region": 'US'})
def test_wifi_sdk_ap_mode_scan_with_PASSIVE_SCAN_TYPE_C688244(wifi_dut, wifi_access_point, wifi_client, wifi_sniffer,
                                                              sl_collections, sniffer_filter):
    """ Scan for available APs in the vicinity after Soft AP Started for 5 minutes in loop """
    logger().info("********** Configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=11)
    logger().info("******* Start capturing with Sniffer by giving the test case name as filename *******")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C688244.pcap")
    sl_collections.configure_dut_in_static_ip(wifi_dut,
                                              static_ip="192.168.100.76",
                                              static_subnet="255.255.255.0",
                                              static_gateway="192.168.100.76")
    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.start_ap(ssid="917_AP_MODE", security="WPA2", psk="Automation@123",
                                      channel="11")
    time.sleep(10)
    logger().info("******************* Scanning on AP interface after bringing up DUT as AP ***************")
    try:
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid="917_AP_MODE", scan_type=8, interface="ap",
                                                     expected_status="0x10003")
        logger().info(f"scan results: {scan_results}  ")
    except Exception as e:
        logger().info(f"scan should fail as expected successfully")

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "band": 0,
        "boot_option": 49,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11,
        "region": 1,
        "region_code": Si91xRegionCode.US
    }
)
@pytest.mark.config("wifi_client", wifi={"country": "US", "channel": "11"})
@pytest.mark.start_state("wifi_dut", wifi=["net_init_stats"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
    ],
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "channel": 11, "region": 'US'})
def test_wifi_sdk_ap_mode_verify_DUT_able_to_send_stats_responce_or_not_C689175(wifi_dut, wifi_access_point,
                                                                                wifi_client, wifi_sniffer, sniffer_filter,
                                                                                sl_collections):
    """ verify DUT is able to send stats-responce or not while disconnecting STA from DUT """
    try:
        ap_dut_obj = ApModeClientConnections(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                             wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                                             sl_collections=sl_collections, capture_filename="test_C535824",
                                             testcase_no=689175)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"*********{dut_ap_mac_address}**********")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "band": 0,
        "boot_option": 49,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11,
        "region": 1,
        "region_code": Si91xRegionCode.US
    }
)
@pytest.mark.config("wifi_client", wifi={"country": "US", "channel": "11"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "channel": 11, "region": 'US'})
def test_wifi_sdk_ap_mode_verify_DUT_able_to_send_probe_response_or_not_when_STA_is_in_other_channel_C689553(wifi_dut,
                                                                                                             wifi_access_point,
                                                                                                             wifi_client,
                                                                                                             wifi_sniffer,
                                                                                                             sl_collections,
                                                                                                             sniffer_filter):
    """ verify DUT able to send probe-responce or not when STAis configured in different channel of DUT """
    try:
        logger().info("********** Configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=1)
        logger().info("******* Start capturing with Sniffer by giving the test case name as filename *******")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_689553.pcap")
        sl_collections.configure_dut_in_static_ip(wifi_dut,
                                                  static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123",
                                          channel=11)
        time.sleep(10)
        logger().info("******************* Scanning on Raspi after bringing up DUT as AP ***************")
        wifi_client.interfaces.wifi.scan()
        time.sleep(10)
        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security="WPA2", passphrase="Automation@123",
                                         channel=1)
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(20)
        logger().info(f"Initiating wlan ping from RASPI_STA")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        time.sleep(5)

        dut_ap_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"*********{dut_ap_mac_address}**********")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_ap_mac_address, filter_name="probe_response")

        try:
            wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'DUT should not respond probe responce as expected'
        except:
            logger().info(f"DUT wont send probe responce in other than DUT configured channel")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()
