import time
import pytest
from utf.utils.thread_base import ThreadBase
from random import randint
from utf_wiseconnect_3.tests.devices.si91x import (Si91xCoexMode, Si91xPowerSaveModes, Si91xFeatureBitMap,
                                                   Si91xOperatingMode,
                                                   Si91xCustomFeatureBitMap,
                                                   Si91xConfigFeatureBitMap,
                                                   Si91xTCPIPFeatureBitMap,
                                                   Si91xExtCustomFeatureBitMap,
                                                   Si91xExtTCPIPFeatureBitMap,
                                                   Si91xCertificateType, Si91xCertIdentifier,
                                                   Si91xPowerSaveProcedureTypes, Si91xJoinFeatureBitMap,
                                                   DeviceConstants, Si91xMqttQos
                                                   )
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
import string
import random
import time
import re
from datetime import datetime
import uuid
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.interfaces.wifi import SecurityMode
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from test_wlan_sta_enterprise_sdk import SnifferValidationProcess


def logger():
    return get_logger(__name__)


""" 
    This test plan aims to connect the wifi ap in enterprise mode
        1. Configuration of DUT in 2G mode
        2. Verifying eap connection in tls mode
        3. Verifying eap connection in ttls mode
        4. Verifying eap connection in peapv0 mode
        5. Verifying eap connection by loading wrong certificate in tls mode
        6. Verifying eap connection by loading no ceritificate in tls mode
        7. Verifying eap connection by setting expired date in tls mode

    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's) -ASUS
        4. Sniffer -NUC 
        5. Free Radius Server (For now running on NUC)

    Author: M.Harshitha 

"""


class Eap_SnifferValidationProcess:

    def __init__(self, wifi_sniffer=None, wifi_access_point=None, dut_mac_address=None,
                 ap_mac_address=None, conn_status=True, eap_type="tls", sniffer_filter=None):

        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_mac_address = ap_mac_address
        self.conn_status = conn_status
        self.eap_type = eap_type
        self.sniffer_filter = sniffer_filter

    def verify_eap_failure_sniffer_validation(self):
        if self.wifi_access_point.interfaces.wifi.security == SecurityMode.WPAEnterprise:
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.ap_mac_address,
                da_addr=self.dut_mac_address, filter_name='beacon_wpa2_entr_wfa_check')
        else:
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.ap_mac_address,
                da_addr=self.dut_mac_address, filter_name='beacon_wpa2_entr_akms_check')

        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_mac_address,
            da_addr=self.ap_mac_address,
            filter_name='assoc_req_resp_eapol_4_way_handshake')

        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.ap_mac_address,
            da_addr=self.dut_mac_address,
            filter_name='eap_connection_failure')
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacons in sniffer'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find assoc_req_resp_eapol_4_way_handshake packet in sniffer'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find EAP failure frames sent from AP in sniffer '


class WPA2Enterprise(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None, sniffer_filter=None, wifi_sniffer=None,
                 sl_collections=None, test_name=None, eap_type=None, eap_type_tls_no_cert=None, http_Otaf=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.eap_type = eap_type
        self.eap_type_tls_no_cert = eap_type_tls_no_cert
        self.dut_addr = None
        self.device_ip = None
        self.sniffer_filter = sniffer_filter
        self.wifi_sniffer = wifi_sniffer
        self.http_Otaf = http_Otaf

    def run(self):
        try:
            if self.eap_type == "tls" or self.eap_type == "ttls" or self.eap_type == "peap":
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        eap_type=self.eap_type,
                                                                        ping_after_power_save=True)
                logger().info(
                    f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")

            if self.eap_type_tls_no_cert == "tls" or self.eap_type_tls_no_cert == "ttls" or self.eap_type_tls_no_cert == "peap":
                self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=self.wifi_access_point.interfaces.wifi.ssid)
                self.wifi_dut.interfaces.wifi.set_eap_credentials()
                self.wifi_dut.interfaces.wifi.join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                                   security="wpa2_enterprise", uid="user1",
                                                   enc=self.eap_type_tls_no_cert, timeout_ms=1,
                                                   expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
                logger().info(
                    f" Connection failed when expired certificate is loaded into the device,observed error code "
                    f"  0x10008 which is expected")
                self.wifi_dut.interfaces.wifi.start_ip(
                    expected_status=SLStatus.SL_STATUS_SI91X_COMMAND_GIVEN_IN_INVALID_STATE)
                logger().info(
                    f"IP configuration failed when command given in incorrect state,observed error code 0x10021 which "
                    f" is expected")

            if self.http_Otaf == "tls":
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        eap_type=self.http_Otaf, power_save=False,
                                                                        ping_after_power_save=False)

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.RealTimeClockFromHost,
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
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_expired_date_eap_tls_c113771(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                               sniffer_filter, radius_server, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity when the expired date is set
            while using EAP TLS Method"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hours=23, day=1, month=1, weekday=4, year=1930)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"****** DUT MAC ADDRESS **** {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"**** AP mac address*****{ap_mac_address}")
        wifi_dut.interfaces.wifi.set_eap_credentials()
        for count in range(0, utf_constants.get('iter_count')):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         sl_collections=sl_collections, test_name=test_name, eap_type_tls_no_cert="tls")
            wifi_thread.start()
            wifi_thread.wait_for_exit()
        sniffer_verification = Eap_SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address,
                                                            ap_mac_address=ap_mac_address)
        sniffer_verification.verify_eap_failure_sniffer_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.RealTimeClockFromHost,
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
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_expired_date_ttls_c113772(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                            sniffer_filter, radius_server, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity when the expired date is set while
                using EAP TTLS Method"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hours=23, day=1, month=1, weekday=4, year=1930)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"****** DUT MAC ADDRESS **** {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"**** AP mac address*****{ap_mac_address}")
        wifi_dut.interfaces.wifi.set_eap_credentials()
        for count in range(0, utf_constants.get('iter_count')):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         sl_collections=sl_collections, test_name=test_name,
                                         eap_type_tls_no_cert="ttls")
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            sniffer_verification = Eap_SnifferValidationProcess(wifi_sniffer=wifi_sniffer,
                                                                sniffer_filter=sniffer_filter,
                                                                wifi_access_point=wifi_access_point,
                                                                dut_mac_address=dut_mac_address,
                                                                ap_mac_address=ap_mac_address)
            sniffer_verification.verify_eap_failure_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.RealTimeClockFromHost,
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
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_expired_date_peap_c113773(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                            sniffer_filter, radius_server, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity when the expired date is set while
                            using EAP PEAP Method"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hours=23, day=1, month=1, weekday=4, year=1930)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"****** DUT MAC ADDRESS **** {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"**** AP mac address*****{ap_mac_address}")
        wifi_dut.interfaces.wifi.set_eap_credentials()
        for count in range(0, utf_constants.get('iter_count')):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         sl_collections=sl_collections, test_name=test_name,
                                         eap_type_tls_no_cert="peap")
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            sniffer_verification = Eap_SnifferValidationProcess(wifi_sniffer=wifi_sniffer,
                                                                sniffer_filter=sniffer_filter,
                                                                wifi_access_point=wifi_access_point,
                                                                dut_mac_address=dut_mac_address,
                                                                ap_mac_address=ap_mac_address)
            sniffer_verification.verify_eap_failure_sniffer_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.RealTimeClockFromHost,
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_eap_tls_no_cert_c113779(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                          sniffer_filter, radius_server, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the certificate
            is not loaded into the device """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"****** DUT MAC ADDRESS **** {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"**** AP mac address*****{ap_mac_address}")
        # wifi_dut.interfaces.wifi.set_eap_credentials()
        for count in range(0, utf_constants.get('iter_count')):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         sl_collections=sl_collections, test_name=test_name, eap_type_tls_no_cert="tls")
            wifi_thread.start()
            wifi_thread.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = Eap_SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address,
                                                            ap_mac_address=ap_mac_address)
        sniffer_verification.verify_eap_failure_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip("Test case duplicate of C113857")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.RealTimeClockFromHost,
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_eap_ttls_no_cert_c113780(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                           sniffer_filter, radius_server, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TTLS Method when the certificate
            is not loaded into the device """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"****** DUT MAC ADDRESS **** {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"**** AP mac address*****{ap_mac_address}")
        for count in range(0, utf_constants.get('iter_count')):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         sl_collections=sl_collections, test_name=test_name,
                                         eap_type_tls_no_cert="ttls")
            wifi_thread.start()
            wifi_thread.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = Eap_SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address,
                                                            ap_mac_address=ap_mac_address)
        sniffer_verification.verify_eap_failure_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip("Test case duplicate of C113855")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.RealTimeClockFromHost,
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_eap_peap_no_cert_c113781(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                           sniffer_filter, radius_server, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TTLS Method when the certificate
            is not loaded into the device """
    try:
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"****** DUT MAC ADDRESS **** {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"**** AP mac address*****{ap_mac_address}")
        for count in range(0, utf_constants.get('iter_count')):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         sl_collections=sl_collections, test_name=test_name,
                                         eap_type_tls_no_cert="peap")
            wifi_thread.start()
            wifi_thread.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = Eap_SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address,
                                                            ap_mac_address=ap_mac_address)
        sniffer_verification.verify_eap_failure_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_wpa2_enterprise_eap_ttls_1_0_c113776(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                       radius_server, sl_collections, request, utf_constants,
                                                       net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the certificate
        is loaded using the in TTLs version 1.0 """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="ttls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        time.sleep(5)
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_ttls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_0')
        logger().info(f"Validating EAP frames TLS version 1.0 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.0 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_wpa2_enterprise_eap_peap_1_0_c113777(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                       radius_server, sl_collections, request, utf_constants,
                                                       net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the certificate
        is loaded using the in peap version 1.0 """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="peap", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        time.sleep(5)
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_peap_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_0')
        logger().info(f"Validating EAP frames TLS version 1.0 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.0 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_wpa2_enterprise_eap_tls_1_2_c113765(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                      radius_server, sl_collections, request, utf_constants,
                                                      net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the certificate
        is loaded using the in tls version 1.2 """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        time.sleep(5)
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_wpa2_enterprise_eap_peap_1_2_c113767(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                       radius_server, sl_collections, request, utf_constants,
                                                       net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the certificate
        is loaded using the in peap version 1.2 """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="peap", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        time.sleep(5)
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_peap_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_wpa2_enterprise_eap_ttls_1_2_c113766(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                       radius_server, sl_collections, request, utf_constants,
                                                       net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TTLS Method when the certificate
        is loaded using the in tls version 1.2 """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="ttls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.client_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.client_port,
                                       size=1460, ttl=30, throughput_type=3, qos=0, async_socket=0)
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_ttls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_wpa2_enterprise_eap_tls_1_0_c113775(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                      radius_server, sl_collections, request, utf_constants,
                                                      net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the certificate
        is loaded using the in TLs version 1.0 """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.client_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.client_port,
                                       size=1460, ttl=30, throughput_type=3, qos=0, async_socket=0)
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_0')
        logger().info(f"Validating EAP frames TLS version 1.0 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.0 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "clear_certs"])
def test_wifi_sdk_three_ssl_connection_wpa2_enterprise_eap_c113797(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                   sniffer_filter,
                                                                   radius_server, sl_collections, request, ssl_server):
    """ This test case verifies the three ssl socket connectivity in WPA2 Enterprise between the dut and the remote
        server """
    try:
        ping_count = 10
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name, http_Otaf="tls")
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        logger().info("....Pinging DUT after power-save....")
        status = ping(device_ip, ping_count)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        logger().info("PING TO DUT IS SUCCESSFULLY DONE....")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']
        ssl_server.interfaces.ssl.start_server(port=port1)
        ssl_server.interfaces.ssl.start_server(port=port2)
        ssl_server.interfaces.ssl.start_server(port=port3)
        server_ip = ssl_server.interfaces.ssl.server_ip
        for sock_count in range(0, 3):
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"Sock ID must be {sock_count} but received {sock}"
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            if sock_count == 0:
                socket_port = port1
                local_port = randint(5001, 20000)
            elif sock_count == 1:
                socket_port = port2
                local_port = randint(20001, 40000)
            else:
                socket_port = port3
                local_port = randint(40001, 60000)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)
        socket_no = [1, 2, 3]
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            for socket in socket_no:
                buffer_length = 100
                # The api returns 100 bytes of random data
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
                if socket < 4:
                    logger().info(f"Sending data {data} over socket_no->{socket - 1}")
                    # DUT sends 100 bytes of data over ssl socket
                    socket_number = socket - 1
                    wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=socket_number, data=data)
                    time.sleep(1)
                    # SSL server receives the data over ssl socket
                    server_socket_no = socket
                    data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, buffer_size=len(data))
                    logger().info(f"Data received on remote socket opened is {data_receive}")
                    assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
                    logger().info("Data sent by DUT and received on server is matching\n\n")
        for sock_count in range(0, 3):
            logger().info(f"Closing socket_id->{sock_count}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_count)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wifi_sdk_mqtt_wpa2_enterprise_c113795(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                               radius_server, sl_collections, request, utf_constants,
                                               mqtt_server, mqtt_client):
    """ This test case verifies the Mqtt connectivity in WPA2 Enterprise """
    try:
        test_name = request.node.name
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        qos = Si91xMqttQos.QOS1
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info("MQTT Client subscribes to the topic")
        time.sleep(5)
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
        time.sleep(5)
        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
        time.sleep(5)
        logger().info("DUT publishes message over the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1, timeout=20)
        time.sleep(5)
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"
        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        logger().info("Disconnecting from MQTT Server")
        wifi_dut.interfaces.wifi.mqtt_client_disconnect()
        time.sleep(1)
        logger().info("Disconnecting from DUT")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
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
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wifi_sdk_ssl_socket_connection_in_wpa2_enterprise_c113793(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                   sniffer_filter, radius_server, sl_collections,
                                                                   request, ssl_server):
    """ This test case verifies the ssl socket connectivity in WPA2 Enterprise between the dut and the remote
        server """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server(port=port1)
        server_ip = ssl_server.interfaces.ssl.server_ip
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        sock = wifi_dut.interfaces.wifi.socket()
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        socket_port = port1
        local_port = randint(5001, 20000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            buffer_length = 100
            pkt_count = 1
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
            ssl_server.interfaces.ssl.send_data(1, pkt_count, buffer_length, message=tx_buffer)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=50, async_timeout=50)
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.HTTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wifi_sdk_http_otaf_wpa2_enterprise_c113803(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client,
                                                    sniffer_filter, radius_server, sl_collections, request,
                                                    http_server):
    """ This test case verifies the http otaf in wpa2 enterprise"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        fw_version_before_upgrade = wifi_dut.interfaces.wifi.version()
        logger().info(f"*** dut fw version before upgrade = {fw_version_before_upgrade} ***")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name, http_Otaf="tls")
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("checking server stats....")
        status_http = http_server.interfaces.http.started
        assert status_http, 'Server is inactive'
        logger().info(f'http server state is {status_http}')
        logger().info("fetching server ip....")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"server ip is {host_ip}")
        wifi_dut.interfaces.wifi.firmware_upgrade(flags=0, ip_address=host_ip, port=80, host_name=host_ip)
        wifi_dut.interfaces.wifi.reset()
        time.sleep(15)
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init(mode="eap", config_required=True, load_certificate=False)
        wifi_dut.interfaces.wifi.initialize_thread()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        fw_version_after_upgrade = wifi_dut.interfaces.wifi.version()
        logger().info(f"*** dut fw version after upgrade = {fw_version_after_upgrade} ***")
        logger().info(f"\n\n ***firmware versions before otaf:{fw_version_before_upgrade}"
                      f" firmware version after loading through otaf :{fw_version_after_upgrade}")
        assert fw_version_before_upgrade != fw_version_after_upgrade, f"firmware versions should not match after loading" \
                                                                      f" firmware through otaf"
        logger().info(f"\n ***firmware versions not matched after loading"
                      f" firmware through otaf\n")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac_address,
            da_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='beacon_wpa2_entr_akms_check')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacons in sniffer'
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wifi_sdk_https_otaf_wpa2_enterprise_c113804(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client,
                                                     sniffer_filter, radius_server, sl_collections, request,
                                                     http_server):
    """ This test case verifies the https otaf in wpa2 enterprise"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        fw_version_before_upgrade = wifi_dut.interfaces.wifi.version()
        logger().info(f"*** dut fw version before upgrade = {fw_version_before_upgrade} ***")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name, http_Otaf="tls")
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("checking server stats....")
        status_http = http_server.interfaces.http.started
        assert status_http, 'Server is inactive'
        logger().info(f'http server state is {status_http}')
        logger().info("fetching server ip....")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"server ip is {host_ip}")
        time.sleep(5)
        wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=host_ip, port=443, host_name=host_ip)
        wifi_dut.interfaces.wifi.reset()
        time.sleep(15)
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init(mode="eap", config_required=True, load_certificate=False)
        wifi_dut.interfaces.wifi.initialize_thread()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        fw_version_after_upgrade = wifi_dut.interfaces.wifi.version()
        logger().info(f"*** dut fw version after upgrade = {fw_version_after_upgrade} ***")
        logger().info(f"\n\n ***firmware versions before otaf:{fw_version_before_upgrade}"
                      f" firmware version after loading through otaf :{fw_version_after_upgrade}")
        assert fw_version_before_upgrade != fw_version_after_upgrade, f"firmware versions should not match after loading" \
                                                                      f" firmware through otaf"
        logger().info(f"\n ***firmware versions not matched after loading"
                      f" firmware through otaf\n")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac_address,
            da_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='beacon_wpa2_entr_akms_check')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacons in sniffer'
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SNTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
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
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wifi_sdk_sntp_connection_wpa2_enterprise_eap_tls_c113796(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                  sniffer_filter, radius_server, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS method and checking
            the sntp functionality"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_dut.interfaces.wifi.sntp_client_start()
        ip_version, sntp_method, sntp_server_address = wifi_dut.interfaces.wifi.sntp_get_server_info()
        logger().info(f'\n\n SNTP server address = {ip_version}, \n {sntp_method},\n {sntp_server_address}\n\n')
        times, date = wifi_dut.interfaces.wifi.sntp_get_time_data()
        logger().info(f'*** Time is {times} ***')
        logger().info(f'*** Date is {date} ***')
        wifi_dut.interfaces.wifi.sntp_client_stop()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
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
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wifi_sdk_aws_connection_wpa2_enterprise_eap_tls_c113794(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                  sniffer_filter, radius_server, sl_collections, request):
    """ This test case verifies the aws connection in WPA2 Enterprise Connectivity"""
    try:
        domain_name = "a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com"
        aws_port = 8883
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        aws_server_ip = wifi_dut.interfaces.wifi.dns_get(domain_name, query_timeout=120000, timeout=30)
        server_ip = aws_server_ip.strip().decode()
        logger().info(f"aws_server_ip {server_ip}")
        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_thread.dut_addr['device_ip'], server_port=aws_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=aws_port)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)