import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xRegion,
    Si91xRegionCode,
    Si91xModuleType,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xCertificateType,
    IEEE802_11W
)
from utf.utf_config import UtfConfig
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.time_measurer import TimeMeasurer
from datetime import datetime, date
import re




def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz in bypass
        2. Join the access point and enable the dhcp in EAP mode with TLS version 1.0/1.2,TTLS.PEAP
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. data transfer

    Author: Swathi.Chinthala

"""


class SnifferValidationEAP(ThreadBase):

    def __init__(self, wifi_sniffer=None, wifi_access_point=None, dut_mac_address=None,
                 ap_mac_address=None, sniffer_filter=None, sl_collections=None, tcp_ip_bypass=False):
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_mac_address = ap_mac_address
        self.sniffer_filter = sniffer_filter
        self.sl_collections = sl_collections
        self.tcp_ip_bypass = tcp_ip_bypass
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def verify_sniffer_validation_eap(self, eap_type="tls", tls_version=None):

        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.ap_mac_address,
            da_addr=self.dut_mac_address, filter_name='beacon_wpa2_entr_akms_check')

        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Unable to find beacons in sniffer'

        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=self.ap_mac_address,
                                                                                            sa_addr=self.dut_mac_address,
                                                                                            filter_name=f'eap_type_{eap_type}_verification')
        logger().info(f"Validating EAP frames sent from AP in sniffer")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        if tls_version:
            if tls_version == "1.2":
                filter_name = 'eap_tls_cert_verification_1_2'
            if tls_version == "1.0":
                filter_name = 'eap_tls_cert_verification_1_0'
            if filter_name:
                packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address,
                da_addr=self.ap_mac_address,
                filter_name=filter_name)
                logger().info(f"Validating EAP frames TLS version {tls_version} in sniffer")
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
                    'packet_count'], \
                    f'Unable to find EAP frames with TLS version {tls_version} sent'











class WPA2Enterprise(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None,
                 sl_collections=None, test_name=None, eap_type="tls", net_perf_client=None, protocol=None,
                 test_type=None, tcp_ip_bypass=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.eap_type = eap_type
        self.dut_addr = None
        self.device_ip = None
        self.dut_mac_address = None
        self.test_type = test_type
        self.tcp_ip_bypass = tcp_ip_bypass
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def join_to_ap_eap(self):

        logger().info(f"associated state : {self.wifi_dut.interfaces.wifi.associated}")

        if not self.wifi_dut.interfaces.wifi.associated:
            self.wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                          beacon_missed_count=40,
                                                                          first_time_retry_enable=0)
            if self.tcp_ip_bypass:
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        eap_type=self.eap_type,
                                                                        tcp_ip_bypass=True,
                                                                        retry_count=1)

                self.dut_mac_address = self.dut_addr['dut_mac_address']
                logger().info(
                    f"device_mac : {self.dut_mac_address}")
            else:
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        eap_type=self.eap_type,
                                                                        ping_after_power_save=True)

                self.device_ip = self.dut_addr['device_ip']
                self.dut_mac_address = self.dut_addr['dut_mac_address']
                logger().info(
                    f"device_ip, device_mac : {self.device_ip}, {self.dut_mac_address}")

    def run_traffic(self, protocol="TCP", traffic_type="TX"):

        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                        protocol=protocol, device_ip=self.device_ip,
                                        host_ip=host_ip, timeout=60, traffic_type=traffic_type)

    def run(self):
        if self.test_type == "ping":
            self.join_to_ap_eap()
            if not self.tcp_ip_bypass:
                status = ping(self.device_ip, 30)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V1,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable",
                                         "ble_stop_adv", "clear_certs"])
def test_sdk_WPA2_EAP_tls_tcp_bypass_V1_C113807(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sniffer_filter,
                                            radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method with version 1.o in tcp ip bypass mode"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        iter_count = utf_constants.get("iter_count")

        for count in range(0, iter_count):

            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         eap_type="tls", sl_collections=sl_collections,
                                         test_name=test_name, test_type="ping", tcp_ip_bypass=True)
            wifi_thread.join_to_ap_eap()
            dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
            logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
            wifi_dut.interfaces.wifi.leave()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")

        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_obj = SnifferValidationEAP(wifi_sniffer=wifi_sniffer,
                                           wifi_access_point=wifi_access_point,
                                           dut_mac_address=dut_mac_address,
                                           ap_mac_address=ap_mac_address,
                                           sniffer_filter=sniffer_filter,
                                           sl_collections=sl_collections,
                                           tcp_ip_bypass=True
                                           )

        sniffer_obj.verify_sniffer_validation_eap(eap_type="tls", tls_version="1.0")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)





@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V1,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable",
                                         "ble_stop_adv", "clear_certs"])
def test_sdk_WPA2_EAP_ttls_tcp_bypass_V1_C113808(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sniffer_filter,
                                            radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap ttls method with version 1.o in tcp ip bypass mode"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        iter_count = utf_constants.get("iter_count")
        for count in range(0, iter_count):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         eap_type="ttls", sl_collections=sl_collections,
                                         test_name=test_name, test_type="ping", tcp_ip_bypass=True)
            wifi_thread.join_to_ap_eap()
            dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
            logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
            wifi_dut.interfaces.wifi.leave()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")

        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_obj = SnifferValidationEAP(wifi_sniffer=wifi_sniffer,
                                           wifi_access_point=wifi_access_point,
                                           dut_mac_address=dut_mac_address,
                                           ap_mac_address=ap_mac_address,
                                           sniffer_filter=sniffer_filter,
                                           sl_collections=sl_collections,
                                           tcp_ip_bypass=True
                                           )

        sniffer_obj.verify_sniffer_validation_eap(eap_type="ttls", tls_version="1.0")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)






@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V1,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable",
                                         "ble_stop_adv", "clear_certs"])
def test_sdk_WPA2_EAP_peap_tcp_bypass_V1_C113809(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sniffer_filter,
                                            radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap peap method with version 1.o in tcp ip bypass mode"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        iter_count = utf_constants.get("iter_count")
        for count in range(0, iter_count):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         eap_type="peap", sl_collections=sl_collections,
                                         test_name=test_name, test_type="ping", tcp_ip_bypass=True)
            wifi_thread.join_to_ap_eap()
            dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
            logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
            wifi_dut.interfaces.wifi.leave()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")

        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_obj = SnifferValidationEAP(wifi_sniffer=wifi_sniffer,
                                           wifi_access_point=wifi_access_point,
                                           dut_mac_address=dut_mac_address,
                                           ap_mac_address=ap_mac_address,
                                           sniffer_filter=sniffer_filter,
                                           sl_collections=sl_collections,
                                           tcp_ip_bypass=True
                                           )

        sniffer_obj.verify_sniffer_validation_eap(eap_type="peap", tls_version="1.0")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)





@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V2,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable",
                                         "ble_stop_adv", "clear_certs"])
def test_sdk_WPA2_EAP_tls_tcp_bypass_V12_C113811(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sniffer_filter,
                                            radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method with version 1.2 in tcp ip bypass mode"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        iter_count = utf_constants.get("iter_count")
        for count in range(0, iter_count):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         eap_type="tls", sl_collections=sl_collections,
                                         test_name=test_name, test_type="ping", tcp_ip_bypass=True)
            wifi_thread.join_to_ap_eap()
            dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
            logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
            wifi_dut.interfaces.wifi.leave()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")

        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_obj = SnifferValidationEAP(wifi_sniffer=wifi_sniffer,
                                           wifi_access_point=wifi_access_point,
                                           dut_mac_address=dut_mac_address,
                                           ap_mac_address=ap_mac_address,
                                           sniffer_filter=sniffer_filter,
                                           sl_collections=sl_collections,
                                           tcp_ip_bypass=True
                                           )

        sniffer_obj.verify_sniffer_validation_eap(eap_type="tls", tls_version="1.2")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)





@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V2,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable",
                                         "ble_stop_adv", "clear_certs"])
def test_sdk_WPA2_EAP_ttls_tcp_bypass_V12_C113812(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sniffer_filter,
                                            radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap ttls method with version 1.2 in tcp ip bypass mode"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        iter_count = utf_constants.get("iter_count")
        for count in range(0, iter_count):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         eap_type="ttls", sl_collections=sl_collections,
                                         test_name=test_name, test_type="ping", tcp_ip_bypass=True)
            wifi_thread.join_to_ap_eap()
            dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
            logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
            wifi_dut.interfaces.wifi.leave()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")

        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_obj = SnifferValidationEAP(wifi_sniffer=wifi_sniffer,
                                           wifi_access_point=wifi_access_point,
                                           dut_mac_address=dut_mac_address,
                                           ap_mac_address=ap_mac_address,
                                           sniffer_filter=sniffer_filter,
                                           sl_collections=sl_collections,
                                           tcp_ip_bypass=True
                                           )

        sniffer_obj.verify_sniffer_validation_eap(eap_type="ttls", tls_version="1.2")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V2,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable",
                                         "ble_stop_adv", "clear_certs"])
def test_sdk_WPA2_EAP_peap_tcp_bypass_V12_C113813(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sniffer_filter,
                                            radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap peap method with version 1.2 in tcp ip bypass mode"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        iter_count = utf_constants.get("iter_count")
        for count in range(0, iter_count):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         eap_type="peap", sl_collections=sl_collections,
                                         test_name=test_name, test_type="ping", tcp_ip_bypass=True)
            wifi_thread.join_to_ap_eap()
            dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
            logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
            wifi_dut.interfaces.wifi.leave()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")

        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_obj = SnifferValidationEAP(wifi_sniffer=wifi_sniffer,
                                           wifi_access_point=wifi_access_point,
                                           dut_mac_address=dut_mac_address,
                                           ap_mac_address=ap_mac_address,
                                           sniffer_filter=sniffer_filter,
                                           sl_collections=sl_collections,
                                           tcp_ip_bypass=True
                                           )
        sniffer_obj.verify_sniffer_validation_eap(eap_type="peap", tls_version="1.2")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)





@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "tcpip_features": Si91xTCPIPFeatureBitMap.TCPIPBypass
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp
                           | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678', \
                          'protected_management_frame': 'Capable'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable",
                                         "ble_stop_adv", "clear_certs"])
def test_sdk_WPA2_EAP_tls_tcp_bypass_pmf_C113816(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sniffer_filter,
                                            radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method with pmf in tcp ip bypass mode"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        iter_count = utf_constants.get("iter_count")

        for count in range(0, iter_count):
            wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=IEEE802_11W.Protection_capable)

            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         eap_type="tls", sl_collections=sl_collections,
                                         test_name=test_name, test_type="ping", tcp_ip_bypass=True)
            wifi_thread.join_to_ap_eap()
            dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
            logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
            wifi_dut.interfaces.wifi.leave()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")

        wifi_sniffer.interfaces.capture.stop_capture()

        sniffer_obj = SnifferValidationEAP(wifi_sniffer=wifi_sniffer,
                                           wifi_access_point=wifi_access_point,
                                           dut_mac_address=dut_mac_address,
                                           ap_mac_address=ap_mac_address,
                                           sniffer_filter=sniffer_filter,
                                           sl_collections=sl_collections,
                                           tcp_ip_bypass=True
                                           )
        sniffer_obj.verify_sniffer_validation_eap(eap_type="tls", tls_version="1.2")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac_address,
            filter_name="beacon_pmf")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Unable to find packets for Association req, with mgmt frame with protection capable'
        # Packet filter for Association req, with mgmt frame with protection capable
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=dut_mac_address, radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="protection_capable_with_assoc_req")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Unable to find packets for Association req, with mgmt frame with protection capable'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

