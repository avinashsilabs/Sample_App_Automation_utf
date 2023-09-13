import re
import pytest
from utf.utils.logger import get_logger
import time
from utf.interfaces.wifi import SecurityMode, WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from utf_wiseconnect_3.devices.si91x import (Si91xCoexMode, Si91xFeatureBitMap, Si91xCustomFeatureBitMap,
                                             Si91xConfigFeatureBitMap, Si91xTCPIPFeatureBitMap, RS9116StoreConfiguration,
                                             Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap)

def logger():
    return get_logger(__name__)

""" 
This test plan aims to connect the WIFI AP in Enterprise mode
setup requirement:
        1. DUT(RS9117)
        2. Raspberry PI4
        3. Access Point(Third Party AP's) -ASUS
        4. Sniffer -NUC 
        5. Free Radius Server (For now running on NUC)
Step1: 1. Configuration of DUT in 2G mode
Step2 : Verifying EAP Connection in TLS mode
Step3 : Verifying EAP Connection in TTLS mode
Step4 : Verifying EAP Connection in PEAPv0 mode
Step5 : Verifying EAP Connection by loading wrong certificate in TLS mode
Step6 : Verifying EAP Connection by loading no certificate in TLS mode
Step7 : Verifying EAP Connection by setting expired date in TLS mode
Step8 : Verifying TLS 1.0/1.2 connectivity with different ciphers

Author: Vishakha
"""

class SnifferValidationProcess:
    def __init__(self, wifi_sniffer=None, wifi_access_point=None, dut_mac_address=None,
                 ap_mac_address=None, conn_status=True, eap_type="TLS", sniffer_filter=None):

        self.wifi_sniffer = wifi_sniffer
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_mac_address = ap_mac_address
        self.conn_status = conn_status
        self.eap_type = eap_type
        self.sniffer_filter = sniffer_filter

    def verify_sniffer_validation(self):
        if self.wifi_access_point.interfaces.wifi.security == SecurityMode.WPAEnterprise:
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                                    sa_addr=self.ap_mac_address, da_addr=self.dut_mac_address,
                                    filter_name='beacon_wpa2_entr_wfa_check')
            logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        else:
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=self.ap_mac_address,
                                                    da_addr=self.dut_mac_address, filter_name='beacon_wpa2_entr_akms_check')
            logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=self.dut_mac_address,
                                    da_addr=self.ap_mac_address, filter_name='assoc_req_resp_eapol_4_way_handshake')
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter2}\n\n")
        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=self.dut_mac_address,
                                                da_addr=self.ap_mac_address, filter_name='power_mgmt_bit')
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter3}\n\n")
        packet_filter4 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=self.ap_mac_address,
                                                da_addr=self.dut_mac_address, filter_name='null_data_powersave')
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter4}\n\n")

        if self.conn_status:
            packet_filter5 = None
            if self.eap_type == "TLS":
                packet_filter5 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=self.ap_mac_address,
                                                            sa_addr=self.dut_mac_address, filter_name='eap_type_tls_verification')
                logger().info(f"\n\n\n Sniffer Filter = {packet_filter5}\n\n")
            if self.eap_type == "TTLS":
                packet_filter5 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=self.ap_mac_address,
                                                    sa_addr=self.dut_mac_address, filter_name='eap_type_tls_verification')
                logger().info(f"\n\n\n Sniffer Filter = {packet_filter5}\n\n")
            if self.eap_type == "PEAP":
                 packet_filter5 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=self.ap_mac_address,
                                                                                                    sa_addr=self.dut_mac_address,
                                                                                                    filter_name='eap_type_peap_verification')
                 logger().info(f"\n\n\n Sniffer Filter = {packet_filter5}\n\n")
            if packet_filter5:
                logger().info(f"Validating EAP frames for the method EAP {self.eap_type} in sniffer")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
                'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        if not self.conn_status:
            packet_filter6 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=self.ap_mac_address,
                                                                sa_addr= self.dut_mac_address ,filter_name='eap_conn_4')
            logger().info(f"\n\n\n Sniffer Filter = {packet_filter6}\n\n")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
                'Unable to find EAP failure frames sent from AP in sniffer '

        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count'], 'Unable to find beacons in sniffer'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find assoc_req_resp_eapol_4_way_handshake packet in sniffer'
        assert  self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find power management bit in QOS null frames in sniffer capture'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
            'packet_count'], 'Unable to find ps polls in sniffer capture'


class EAP_Connectivity:
    def __init__(self, utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase, sl_collections,
                 passphrase="12345678", username="user1", eap_type="TLS", eap_inner_method="auth=MSCHAPV2",
                 private_key="", okc_value=0, wifi_connection_indication=1):
        super().__init__()
        self.utf_constants = utf_constants
        self.wifi_dut = wifi_dut
        self.wifi_sniffer = wifi_sniffer
        self.wifi_access_point = wifi_access_point
        self.testcase = testcase
        self.passphrase = passphrase
        self.username = username
        self.eap_type = eap_type
        self.eap_inner_method = eap_inner_method
        self.private_key = private_key
        self.okc_value = okc_value
        self.wifi_connection_indication = wifi_connection_indication
        self.sl_collections = sl_collections

    def eap_join(self, exp_error=None, error_reason=None):
        validation = True
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

        logger().info("Getting the DUT mac")
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")

        for count in range(0, self.utf_constants.get('iter_count')):

            logger().info("Setting roam parameters")
            # enable Roaming
            self.wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
            logger().info("enable rejoin")
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0,
                                                                     scan_interval=4,
                                                                     beacon_missed_count=40,
                                                                     first_time_retry_enable=0)
            # test_scan
            logger().info("scanning for AP")
            scan_fail = self.sl_collections.scan(self.wifi_dut)
            assert not scan_fail, "Scanning for AP failed"

            logger().info("Initiating join")
            logger().info("Initiate connection")
            with pytest.raises(WlanError) as exc_info:
                self.wifi_dut.interfaces.wifi.eap_join_ap(self.wifi_access_point, passphrase=self.passphrase,
                                                          timeout=40, username=self.username,
                                                          eap_type=self.eap_type, okc_value=self.okc_value,
                                                          wifi_connection_indication=self.wifi_connection_indication)
                assert exc_info.value.error_code == 0x8, "Connection should fail with error code 0x8"

            if exp_error:

                events = self.wifi_dut.interfaces.wifi.get_async_events()
                status = False
                for event in events:
                    logger().info(f"event type : {event.event_type}")
                    logger().info(f"event data : {event.event_data}")
                    rsp = event.event_data.decode('utf-8')
                    if "reason_code" in rsp:
                        y = re.search(r"reason_code-(.*)", rsp)
                        assert y, "reason code not found in event"
                        logger().info(f"reason_code : ***************{y.group(1)}****************")
                        assert int(y.group(1)) in exp_error, f"expected error code: {exp_error} but found {y.group(1)}"
                        logger().info(
                            f"expected error code found ***************{y.group(1)}****************")
                        status = True

                assert status, f"Event not found with reason code :{exp_error}-{error_reason}"

                logger().info(f"Event found with expected error :{exp_error}-{error_reason}")

            with pytest.raises(WlanError) as exc_info:
                logger().info("Initiate ip command")
                ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=20)
                assert exc_info.value.error_code == 0x21, "ip command should failed 0x21 error"

            logger().info("Initiating disconnect from DUT")
            # Wlan Disconnect
            self.wifi_dut.interfaces.wifi.leave()
            time.sleep(10)

        logger().info("stopping capture")
        self.wifi_sniffer.interfaces.capture.stop_capture()

        verify_sniffer = SnifferValidationProcess(self.wifi_sniffer, self.wifi_access_point,
                                                  dut_mac_address, ap_mac_address=ap_bssid,
                                                  conn_status=False, eap_type=self.eap_type, sniffer_filter=None)

        verify_sniffer.verify_sniffer_validation()
        return dut_mac_address, ap_bssid



class EAP_Connectivity_with_ciphers:
    def __init__(self, utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, wifi_client,
                 net_perf_client, protocol, testcase, sl_collections, eap_type="TLS", okc_value=0):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_sniffer = wifi_sniffer
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.utf_constants = utf_constants
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.eap_type = eap_type
        self.okc_value = okc_value
        self.testcase = testcase
        self.sl_collections = sl_collections
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_bssid = None
        self.host_ip = None


    def join_to_ap(self):
        validation = True
        self.ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {self.ap_bssid}")
        self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{self.host_ip}")

        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

        for count in range(0, self.utf_constants.get('iter_count')):
            self.device_ip, self.dut_mac_address = self.sl_collections.join_to_eap_network(self.wifi_dut,
                                                                                           self.wifi_access_point,
                                                                                           eap_type=self.eap_type)
            logger().info(f"device_ip, device_mac : {self.device_ip}, {self.dut_mac_address}")
            timeout = 60
            self.rs_helper.run_traffic(self.wifi_dut, self.net_perf_client, self.protocol, self.device_ip, self.host_ip,
                                       timeout, traffic_type="TX")

            logger().info("Initiating disconnect from DUT")
            # Wlan Disconnect
            self.wifi_dut.interfaces.wifi.leave()
            time.sleep(10)

        logger().info("stopping capture")
        self.wifi_sniffer.interfaces.capture.stop_capture()

        return self.device_ip, self.dut_mac_address, self.ap_bssid, self.host_ip

    def verify_cipher_sniffer(self, cipher_filter=None):
        validation = True
        verify_sniffer = SnifferValidationProcess(self.wifi_sniffer, self.wifi_dut, self.wifi_access_point,
                                                  self.dut_mac_address, eap_type=self.eap_type,
                                                  sniffer_filter = None)
        verify_sniffer.verify_sniffer_validation()

        if cipher_filter:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, cipher_filter)[
                'packet_count'], 'Unable to find EAP frames with expected ciphers'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_DHE_RSA_AES256_SHA256_TLSv12_C113821(utf_constants, radius_server, net_perf_client, protocol,
                                        wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,wifi_access_point, wifi_client,
                                                net_perf_client, protocol, testcase, eap_type="TLS", okc_value=4)
        device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

        # Validating the EAP failure frames
        packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                         f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x006b ' \
                         f'and tls.handshake.cipher_suites_length == 2'
        logger().info(f"Validating EAP frames TLS version 1.2  and cipher suit DHE-RSA-AES256-SHA256 in sniffer")
        eap_obj.verify_cipher_sniffer(packet_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_DHE_RSA_AES128_SHA256_TLSv12_C113822(utf_constants, radius_server, net_perf_client, protocol,
                                        wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request, sl_collections):
    try:
        testcase = request.node.name
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,
                                                wifi_access_point, wifi_client, net_perf_client,
                                                protocol, testcase, eap_type="TLS", okc_value=8)
        device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

        # Validating the EAP failure frames
        packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                         f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x0067 ' \
                         f'and tls.handshake.cipher_suites_length == 2'
        logger().info(f"Validating EAP frames TLS version 1.2  and cipher suit DHE-RSA-AES128-SHA256 in sniffer")
        eap_obj.verify_cipher_sniffer(packet_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_DHE_RSA_AES256_SHA_TLSv12_C113823(utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,
                                                wifi_access_point, wifi_client, net_perf_client,
                                                protocol, testcase, eap_type="TLS", okc_value=16)
        device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

        # Validating the EAP failure frames
        packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                         f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x0039 ' \
                         f'and tls.handshake.cipher_suites_length == 2'
        logger().info(f"Validating EAP frames TLS version 1.2  and cipher suit DHE-RSA-AES256-SHA in sniffer")
        eap_obj.verify_cipher_sniffer(packet_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_DHE_RSA_AES128_SHA_TLSv12_C113824(utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,
                                                wifi_access_point, wifi_client, net_perf_client,
                                                protocol, testcase, eap_type="TLS", okc_value=32)
        device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

        # Validating the EAP failure frames
        packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                         f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x0033 ' \
                         f'and tls.handshake.cipher_suites_length == 2'
        logger().info(f"Validating EAP frames TLS version 1.2  and cipher suit DHE-RSA-AES128-SHA in sniffer")
        eap_obj.verify_cipher_sniffer(packet_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_AES256_SHA256_TLSv12_C113825(utf_constants, radius_server, net_perf_client, protocol,
                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,
                                                wifi_access_point, wifi_client, net_perf_client,
                                                protocol, testcase, eap_type="TLS", okc_value=64)
        device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

        # Validating the EAP failure frames
        packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                         f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x003d ' \
                         f'and tls.handshake.cipher_suites_length == 2'
        logger().info(f"Validating EAP frames TLS version 1.2  and cipher suit AES256-SHA256 in sniffer")
        eap_obj.verify_cipher_sniffer(packet_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_AES128_SHA256_TLSv12_C113826(utf_constants, radius_server, net_perf_client, protocol, request,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,
                                                wifi_access_point, wifi_client, net_perf_client,
                                                protocol, testcase, eap_type="TLS", okc_value=128)
        device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

        # Validating the EAP failure frames
        packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                         f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x003c ' \
                         f'and tls.handshake.cipher_suites_length == 2'
        logger().info(f"Validating EAP frames TLS version 1.2  and cipher suit AES128-SHA256 in sniffer")
        eap_obj.verify_cipher_sniffer(packet_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_AES256_SHA_TLSv12_C113827(utf_constants, radius_server, net_perf_client, protocol, wifi_sniffer,
                                                     wifi_dut, wifi_client, wifi_access_point, request, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,
                                                wifi_access_point, wifi_client, net_perf_client,
                                                protocol, testcase, eap_type="TLS", okc_value=256)
        device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

        # Validating the EAP failure frames
        packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                         f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x0035 ' \
                         f'and tls.handshake.cipher_suites_length == 2'
        logger().info(f"Validating EAP frames TLS version 1.2  and cipher suit AES256_SHA in sniffer")
        eap_obj.verify_cipher_sniffer(packet_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_AES128_SHA_TLSv12_C113828(utf_constants, radius_server, net_perf_client, protocol, request,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,
                                                wifi_access_point, wifi_client, net_perf_client,
                                                protocol, testcase, eap_type="TLS", okc_value=512)
        device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

        # Validating the EAP failure frames
        packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                         f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x002f ' \
                         f'and tls.handshake.cipher_suites_length == 2'
        logger().info(f"Validating EAP frames TLS version 1.2  and cipher suit AES128_SHA in sniffer")
        eap_obj.verify_cipher_sniffer(packet_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_RSA_AES256_SHA256_and_RSA_AES256_SHA_TLSv12_C113832(utf_constants, radius_server, protocol,
                                                                               net_perf_client, wifi_sniffer, wifi_dut, wifi_client,
                                                                               wifi_access_point, request, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,
                                                wifi_access_point, wifi_client, net_perf_client,
                                                protocol, testcase, eap_type="TLS", okc_value=20)
        device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

        # Validating the EAP failure frames
        packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                         f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x006b ' \
                         f'and tls.handshake.ciphersuite == 0x0039 and tls.handshake.cipher_suites_length == 4'
        logger().info(f"Validating EAP frames TLS version 1.2 and cipher suit DHE-RSA-AES256-SHA256 and DHE-RSA-AES256-SHA in sniffer")
        eap_obj.verify_cipher_sniffer(packet_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_all_ciphers_TLSv12_C113833(utf_constants, radius_server, net_perf_client, protocol, request,
                                                wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,
                                                wifi_access_point, wifi_client, net_perf_client,
                                                protocol, testcase, eap_type="TLS", okc_value=8188)
        device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

        # Validating the EAP failure frames
        packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                         f'and eap and tls.record.version == 0x0303 ' \
                         f'and tls.handshake.cipher_suites_length == 22'
        logger().info(f"Validating EAP frames TLS version 1.2 and all cipher suits in sniffer")
        eap_obj.verify_cipher_sniffer(packet_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_non_supported_ciphers_TLSv12_C113834(utf_constants, radius_server, net_perf_client, protocol,
                                            wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity(utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase,
                                            passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                            username="user1", eap_type="TLS", eap_inner_method="auth=MSCHAPV2",
                                            private_key="", okc_value=1024, wifi_connection_indication=1)

        eap_obj.eap_join()
        logger().info("Connection should fail when non supported cipher selected")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_DHE_RSA_AES256_SHA_TLSv10_C113835(utf_constants, radius_server, net_perf_client, protocol, request,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,
                                                wifi_access_point, wifi_client, net_perf_client,
                                                protocol, testcase, eap_type="TLS", okc_value=16)
        device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

        # Validating the EAP failure frames
        packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                         f'and eap and tls.record.version == 0x0301 and tls.handshake.ciphersuite == 0x0039 ' \
                         f'and tls.handshake.cipher_suites_length == 2'
        logger().info(f"Validating EAP frames TLS version 1.0  and cipher suit DHE-RSA-AES256-SHA in sniffer")
        eap_obj.verify_cipher_sniffer(packet_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_DHE_RSA_AES128_SHA_TLSv10_C113836(utf_constants, radius_server, net_perf_client, protocol, request,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,
                                                wifi_access_point, wifi_client, net_perf_client,
                                                protocol, testcase, eap_type="TLS", okc_value=32)
        device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

        # Validating the EAP failure frames
        packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                         f'and eap and tls.record.version == 0x0301 and tls.handshake.ciphersuite == 0x0033 ' \
                         f'and tls.handshake.cipher_suites_length == 2'
        logger().info(f"Validating EAP frames TLS version 1.0  and cipher suit DHE-RSA-AES128-SHA in sniffer")
        eap_obj.verify_cipher_sniffer(packet_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_AES256_SHA_TLSv10_C113837(utf_constants, radius_server, net_perf_client, protocol, request,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,
                                                wifi_access_point, wifi_client, net_perf_client,
                                                protocol, testcase, eap_type="TLS", okc_value=256)
        device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

        # Validating the EAP failure frames
        packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                         f'and eap and tls.record.version == 0x0301 and tls.handshake.ciphersuite == 0x0035 ' \
                         f'and tls.handshake.cipher_suites_length == 2'
        logger().info(f"Validating EAP frames TLS version 1.0  and cipher suit AES256_SHA in sniffer")
        eap_obj.verify_cipher_sniffer(packet_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_AES128_SHA_TLSv10_C113838(utf_constants, radius_server, net_perf_client, protocol, request,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,
                                                wifi_access_point, wifi_client, net_perf_client,
                                                protocol, testcase, eap_type="TLS", okc_value=512)
        device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

        # Validating the EAP failure frames
        packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                         f'and eap and tls.record.version == 0x0301 and tls.handshake.ciphersuite == 0x002f ' \
                         f'and tls.handshake.cipher_suites_length == 2'
        logger().info(f"Validating EAP frames TLS version 1.0  and cipher suit AES128_SHA in sniffer")
        eap_obj.verify_cipher_sniffer(packet_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_all_ciphers_TLSv10_C113843(utf_constants, radius_server, net_perf_client, protocol, request,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,
                                                wifi_access_point, wifi_client, net_perf_client,
                                                protocol, testcase, eap_type="TLS", okc_value=8188)
        device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

        # Validating the EAP failure frames
        packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                         f'and eap and tls.record.version == 0x0301 ' \
                         f'and tls.handshake.cipher_suites_length == 22'
        logger().info(f"Validating EAP frames TLS version 1.0 and all cipher suits in sniffer")
        eap_obj.verify_cipher_sniffer(packet_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_non_supported_ciphers_TLSv10_C113844(utf_constants, radius_server, net_perf_client, protocol,
                                        wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity(utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase,
                                            passphrase=wifi_access_point.interfaces.wifi.passphrase, username="user1",
                                            eap_type="TLS", eap_inner_method="auth=MSCHAPV2", private_key="",
                                            okc_value=1024,
                                            wifi_connection_indication=1)
        logger().info("enable eap method TLS with RC4-MD5 cipher")
        eap_obj.eap_join()
        logger().info("Connection should fail when non supported cipher selected")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.skip
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_DHE_RSA_AES128_SHA256_ca_cert_1_C113845(utf_constants, radius_server, net_perf_client,
                                                                   protocol, wifi_sniffer, wifi_dut, wifi_client,
                                                                   wifi_access_point, request, sl_collections):
    try:
        testcase = request.node.name
        logger().info("Enabling ciphers DHE-RSA-AES128-SHA256 & ca_cert:1")
        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,
                                                wifi_access_point, wifi_client, net_perf_client,
                                                protocol, testcase, eap_type="TLS", okc_value=10)

        device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

        # Validating the EAP failure frames
        packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                        f'and tls.handshake.cipher_suites_length == 2 and tls.handshake.ciphersuite == 0x0067'
        logger().info(f"Validating EAP frames DHE-RSA-AES128-SHA256 cipher suits in sniffer")
        eap_obj.verify_cipher_sniffer(packet_filter)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EapConn_with_invalid_date_C113851(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point,
                                                        radius_server, request, sl_collections):
    try:
        testcase = request.node.name
        wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hour=23,
                                         month_day=1,
                                         month=1, year=1930, week_day=4)

        eap_obj = EAP_Connectivity(utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase,
                                            passphrase=wifi_access_point.interfaces.wifi.passphrase, username="user1",
                                            eap_type="TLS", eap_inner_method="auth=MSCHAPV2", private_key="",
                                            okc_value=0,
                                            wifi_connection_indication=1)
        eap_obj.eap_join(exp_error=[75], error_reason="Error-4B->CLIENT_ROOT_CA_BAD_DATE_ERR")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_Conn_TLS_when_no_cert_C113852(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point,
                                                        radius_server, request, sl_collections):
    try:
        testcase = request.node.name
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)
        eap_obj = EAP_Connectivity(utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase,
                                            passphrase=wifi_access_point.interfaces.wifi.passphrase, username="user1",
                                            eap_type="TLS", eap_inner_method="auth=MSCHAPV2", private_key="",
                                            okc_value=0, wifi_connection_indication=1)

        eap_obj.eap_join(exp_error=[43], error_reason="Error:2B->TLS_NO_CERT_PRESENT")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_TLS_conn_with_wrong_cert_C113850(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point,
                                                            radius_server, request, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity(utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase,
                                            passphrase=wifi_access_point.interfaces.wifi.passphrase, username="user1",
                                            eap_type="TLS", eap_inner_method="auth=MSCHAPV2", private_key="",
                                            okc_value=0, wifi_connection_indication=1)

        eap_obj.eap_join(exp_error=[83], error_reason="Error:53->PEM_ERROR")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_conn_with_wrong_pwd_C113848(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point,
                                                    radius_server, request, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity(utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase,
                                    passphrase="test123", username="user1", eap_type="TTLS",
                                    eap_inner_method="auth=MSCHAPV2", private_key="",
                                    okc_value=0, wifi_connection_indication=1)
        eap_obj.eap_join(exp_error=[71, 151], error_reason="Error:47->EAP_FAILURE_RECEIVED")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_conn_with_wrong_useridentity_C113849(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point,
                                                                radius_server, request, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity(utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase,
                                            passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                            username="user2", eap_type="TTLS", eap_inner_method="auth=MSCHAPV2",
                                            private_key="", okc_value=0, wifi_connection_indication=1)

        eap_obj.eap_join(exp_error=[71, 151], error_reason="Error:47->EAP_FAILURE_RECEIVED")
        logger().info("EAP connection should fail with error code:71")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_WPA2_EAP_conn_with_wrong_eapmethod_C113853(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point,
                                                            radius_server, request, sl_collections):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity(utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase,
                                            passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                            username="user1", eap_type="FAST", eap_inner_method="auth=MSCHAPV2",
                                            private_key="", okc_value=0, wifi_connection_indication=1)

        eap_obj.eap_join(exp_error=[71, 151], error_reason="Error:47->EAP_FAILURE_RECEIVED")
        logger().info("EAP connection should fail with error code:71")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_WPA2_EAP_conn_with_fast_psp_C113864(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point, sl_collections,
                                                      radius_server, wifi_client, net_perf_client, protocol, request):
    try:
        testcase = request.node.name
        eap_obj = EAP_Connectivity_with_ciphers(utf_constants, wifi_dut, wifi_sniffer,
                                                wifi_access_point, wifi_client, net_perf_client,
                                                protocol, testcase, eap_type="TTLS")
        eap_obj.join_to_ap()
        eap_obj.verify_cipher_sniffer()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.skip
@pytest.mark.store_config
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disable_store_config", "disassociated", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_WPA2_EAP_conn_when_auto_join_C113847(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point,
                                              radius_server, wifi_client, request, protocol, net_perf_client,
                                              sl_collections, mode='power_save_low_latency', ping_count=10,
                                              power_save=True, ping_after_power_save=False):
    try:
        testcase = request.node.name
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        for count in range(0, utf_constants.get('iter_count')):

            logger().info("enable eap method")
            self.device_ip, self.dut_mac_address = self.sl_collections.join_to_eap_network(self.wifi_dut,
                                                                                           self.wifi_access_point,
                                                                                           eap_type=self.eap_type)
            logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

            logger().info("Enable Auto Configuration")
            # Save the wireless configuration in the flash
            wifi_dut.interfaces.wifi.config_save()
            # Enable the wireless configuration in the flash
            wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

            for i in range(0, 3):
                logger().info("Initiating wireless de init")
                wifi_dut.interfaces.wifi.wireless_deinit()
                time.sleep(2)
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Initializing the DUT")
                    wifi_dut.interfaces.wifi.dut_init(oper_mode=2, coex_mode=9, retries=0)
                if exc_info.value.error_code == 0x5A5A:
                    status = True
                    break
                else:
                    logger().info("retrying for 3 times")
                    status = False
                    continue
            assert status, f"Wrong error code found"
            time.sleep(10)
            wifi_dut.interfaces.wifi.associated = True

            logger().info("getting wireless info")
            result = wifi_dut.interfaces.wifi.get_wireless_info()
            assert wifi_access_point.interfaces.wifi.ssid in result, "AP ssid not found in the get wireless info"

            if power_save:
                logger().info(f"....Applying performance profile mode : {mode}")
                wifi_dut.interfaces.wifi.set_performance_profile(mode)
                if ping_after_power_save:
                    logger().info("....Pinging DUT after power-save....")
                    status = ping(device_ip=dut_add_dict['device_ip'], ping_count=ping_count)
                    assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
            return dut_add_dict

            time.sleep(5)
            logger().info("Pinging to DUT after power save")
            status = ping(device_ip, utf_constants.get("ping_count"))
            assert status, "DUT not responding for ping request......"
            logger().info("ping to DUT is successful....")

            timeout = 60
            rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")
            logger().info("Initiating disconnect from DUT")

            # Wlan Disconnect
            wifi_dut.interfaces.wifi.leave()
            time.sleep(10)

            wifi_dut.interfaces.wifi.inited = True
            logger().info("Disable store configuration")
            # Enable the wireless configuration in the flash
            wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_access_point, dut_mac_address,
                                                  ap_mac_address = ap_bssid, eap_type = eap_type, sniffer_filter = None)
        verify_sniffer.verify_sniffer_validation()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

