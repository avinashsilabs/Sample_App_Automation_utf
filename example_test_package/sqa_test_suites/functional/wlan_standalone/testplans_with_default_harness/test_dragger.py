import re
import pytest
from utf_wiseconnect.devices.rs911x import (RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap,
                            RS9116CustomFeatureBitMap,
                            RS9116ConfigFeatureBitMap,
                            RS9116TCPIPFeatureBitMap,
                            RS9116ExtCustomFeatureBitMap,
                            RS9116ExtTCPIPFeatureBitMap,
                            RS9116CertificateType,
                            RS9116SecurityMode, RS9116PowerSaveProcedureTypes, RS9116JoinFeatureBitMap,
                            RS9116AsyncEventType,RS9116StoreConfiguration
                            )
from utf.utils.logger import get_logger
import time
from utf.interfaces.wifi import SecurityMode, WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from test_wlan_sta_enterprise import SnifferValidationProcess


def logger():
    return get_logger(__name__)

""" 
This test plan aims to connect the WIFI AP in Enterprise mode
setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's) -ASUS
        5. Sniffer -NUC 
        6. Free Radius Server (For now running on NUC)
Step1: 1. Configuration of DUT in 2G mode
Step2 : Verifying EAP Connection in TLS mode
Step3 : Verifying EAP Connection in TTLS mode
Step4 : Verifying EAP Connection in PEAPv0 mode
Step5 : Verifying EAP Connection by loading wrong certificate in TLS mode
Step6 : Verifying EAP Connection by loading no certificate in TLS mode
Step7 : Verifying EAP Connection by setting expired date in TLS mode
Step8 : Verifying TLS 1.0/1.2 connectivity with different ciphers

Author: swathi.pathuri
"""



class EAP_Connectivity_negative:

    def __init__(self, utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase, passphrase="12345678",
                 username="user1", eap_method="TLS", eap_inner_method="auth=MSCHAPV2", private_key="", okc_value=0,
                 wifi_connection_indication=1):
        super().__init__()
        self.utf_constants = utf_constants
        self.wifi_dut = wifi_dut
        self.wifi_sniffer = wifi_sniffer
        self.wifi_access_point = wifi_access_point
        self.testcase = testcase
        self.passphrase = passphrase
        self.username = username
        self.eap_method = eap_method
        self.eap_inner_method = eap_inner_method
        self.private_key = private_key
        self.okc_value = okc_value
        self.wifi_connection_indication = wifi_connection_indication

    def eap_join(self, exp_error=None):

        validation = True
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

        for count in range(0, self.utf_constants.get('iter_count')):

            logger().info("Setting roam parameters")
            # enable Roaming
            self.wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)
            logger().info("enable rejoin")
            self.wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

            logger().info("scanning for AP")
            # test_scan
            scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            logger().info(scan_results)

            logger().info("Getting the DUT mac")
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {dut_mac_address}")

            ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP bssid {ap_bssid}")

            logger().info("Initiating join")
            logger().info("Initiate connection")
            with pytest.raises(WlanError) as exc_info:
                self.wifi_dut.interfaces.wifi.eap_join_ap(self.wifi_access_point, passphrase=self.passphrase,
                                                          timeout=40, username=self.username,
                                                          eap_method=self.eap_method, okc_value=self.okc_value,
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
                        assert int(y.group(1)) == exp_error, f"expected error code: {exp_error} but found {y.group(1)}"
                        logger().info(
                            f"expected error code found ***************{y.group(1)}****************")
                        status = True

                assert status, "Event not found with reason code"

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

        verify_sniffer = SnifferValidationProcess(self.wifi_sniffer, self.wifi_dut, self.wifi_access_point,
                                                  dut_mac_address, ap_bssid, conn_status=False)
        verify_sniffer.verify_sniffer_validation()

        return dut_mac_address, ap_bssid






class EAP_Connectivity_with_ciphers:
    def __init__(self, utf_constants, rs_helper, wifi_dut, wifi_sniffer, wifi_access_point, wifi_client,
                 net_perf_client, protocol, testcase, eap_type="TLS", okc_value=0):
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
        self.rs_helper = rs_helper
        self.testcase = testcase
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
            logger().info("enable eap method TLS with cipher DHE-RSA-AES256-SHA256")
            self.device_ip, self.dut_mac_address = self.rs_helper.check_eap_connectivity(self.utf_constants, self.wifi_dut,\
                                                                               self.wifi_access_point,
                                                                               eap_type=self.eap_type,
                                                                               okc_value=self.okc_value)
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
                                                  self.dut_mac_address, self.ap_bssid, eap_type=self.eap_type)
        verify_sniffer.verify_sniffer_validation()

        if cipher_filter:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, cipher_filter)[
                'packet_count'], 'Unable to find EAP frames with expected ciphers'




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_DHE_RSA_AES256_SHA256_TLSv12_C113821(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):
    testcase = request.node.name

    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TLS", okc_value=4)
    device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

    # Validating the EAP failure frames
    packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x006b ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit DHE-RSA-AES256-SHA256 in sniffer"
    )
    eap_obj.verify_cipher_sniffer(packet_filter)




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_DHE_RSA_AES128_SHA256_TLSv12_C113822(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):
    testcase = request.node.name
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TLS", okc_value=8)
    device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

    # Validating the EAP failure frames
    packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x0067 ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit DHE-RSA-AES128-SHA256 in sniffer"
    )
    eap_obj.verify_cipher_sniffer(packet_filter)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_DHE_RSA_AES256_SHA_TLSv12_C113823(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point,request):
    testcase = request.node.name

    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TLS", okc_value=16)

    device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

    # Validating the EAP failure frames
    packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x0039 ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit DHE-RSA-AES256-SHA in sniffer"
    )
    eap_obj.verify_cipher_sniffer(packet_filter)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_DHE_RSA_AES128_SHA_TLSv12_C113824(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):
    testcase = request.node.name

    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TLS", okc_value=32)
    device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

    # Validating the EAP failure frames
    packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x0033 ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit DHE-RSA-AES128-SHA in sniffer"
    )
    eap_obj.verify_cipher_sniffer(packet_filter)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_AES256_SHA256_TLSv12_C113825(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):
    testcase = request.node.name

    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TLS", okc_value=64)
    device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

    # Validating the EAP failure frames
    packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x003d ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit AES256-SHA256 in sniffer"
    )
    eap_obj.verify_cipher_sniffer(packet_filter)




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_AES128_SHA256_TLSv12_C113826(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):
    testcase = request.node.name

    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TLS", okc_value=128)
    device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

    # Validating the EAP failure frames
    packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x003c ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit AES128-SHA256 in sniffer"
    )
    eap_obj.verify_cipher_sniffer(packet_filter)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_AES256_SHA_TLSv12_C113827(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):
    testcase = request.node.name

    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TLS", okc_value=256)
    device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

    # Validating the EAP failure frames
    packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x0035 ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit AES256_SHA in sniffer"
    )
    eap_obj.verify_cipher_sniffer(packet_filter)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_AES128_SHA_TLSv12_C113828(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):
    testcase = request.node.name

    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TLS", okc_value=512)
    device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

    # Validating the EAP failure frames
    packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x002f ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit AES128_SHA in sniffer"
    )
    eap_obj.verify_cipher_sniffer(packet_filter)




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_AES256_SHA256_and_AES256_SHA_TLSv12_C113832(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):
    testcase = request.node.name

    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TLS", okc_value=20)
    device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

    # Validating the EAP failure frames
    packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x006b ' \
                     f'and tls.handshake.ciphersuite == 0x0039 and tls.handshake.cipher_suites_length == 4'
    logger().info(
        f"Validating EAP frames TLS version 1.2 and cipher suit DHE-RSA-AES256-SHA256 and DHE-RSA-AES256-SHA in sniffer"
    )
    eap_obj.verify_cipher_sniffer(packet_filter)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_all_ciphers_TLSv12_C113833(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):
    testcase = request.node.name

    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TLS", okc_value=8188)
    device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

    # Validating the EAP failure frames
    packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 ' \
                     f'and tls.handshake.cipher_suites_length == 22'
    logger().info(
        f"Validating EAP frames TLS version 1.2 and all cipher suits in sniffer"
    )
    eap_obj.verify_cipher_sniffer(packet_filter)




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_non_supported_ciphers_TLSv12_C113834(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):

    testcase = request.node.name
    eap_obj = EAP_Connectivity_negative(utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase,
                                        passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                        username="user1", eap_method="TLS", eap_inner_method="auth=MSCHAPV2",
                                        private_key="", okc_value=1024, wifi_connection_indication=1)

    eap_obj.eap_join()
    logger().info("Connection should fail when non supported cipher selected")




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_DHE_RSA_AES256_SHA_TLSv10_C113835(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):
    testcase = request.node.name

    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TLS", okc_value=16)
    device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

    # Validating the EAP failure frames
    packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0301 and tls.handshake.ciphersuite == 0x0039 ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.0  and cipher suit DHE-RSA-AES256-SHA in sniffer"
    )
    eap_obj.verify_cipher_sniffer(packet_filter)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_DHE_RSA_AES128_SHA_TLSv10_C113836(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):
    testcase = request.node.name

    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TLS", okc_value=32)
    device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

    # Validating the EAP failure frames
    packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0301 and tls.handshake.ciphersuite == 0x0033 ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.0  and cipher suit DHE-RSA-AES128-SHA in sniffer"
    )
    eap_obj.verify_cipher_sniffer(packet_filter)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_AES256_SHA_TLSv10_C113837(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):
    testcase = request.node.name

    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TLS", okc_value=256)
    device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

    # Validating the EAP failure frames
    packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0301 and tls.handshake.ciphersuite == 0x0035 ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.0  and cipher suit AES256_SHA in sniffer"
    )
    eap_obj.verify_cipher_sniffer(packet_filter)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_AES128_SHA_TLSv10_C113838(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):
    testcase = request.node.name

    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TLS", okc_value=512)
    device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

    # Validating the EAP failure frames
    packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0301 and tls.handshake.ciphersuite == 0x002f ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.0  and cipher suit AES128_SHA in sniffer"
    )
    eap_obj.verify_cipher_sniffer(packet_filter)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_all_ciphers_TLSv10_C113843(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):
    testcase = request.node.name

    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TLS", okc_value=8188)
    device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

    # Validating the EAP failure frames
    packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0301 ' \
                     f'and tls.handshake.cipher_suites_length == 22'
    logger().info(
        f"Validating EAP frames TLS version 1.0 and all cipher suits in sniffer"
    )
    eap_obj.verify_cipher_sniffer(packet_filter)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_non_supported_ciphers_TLSv10_C113844(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):
    testcase = request.node.name
    eap_obj = EAP_Connectivity_negative(utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase,
                                        passphrase=wifi_access_point.interfaces.wifi.passphrase, username="user1",
                                        eap_method="TLS", eap_inner_method="auth=MSCHAPV2", private_key="",
                                        okc_value=1024,
                                        wifi_connection_indication=1)
    logger().info("enable eap method TLS with RC4-MD5 cipher")
    eap_obj.eap_join()
    logger().info("Connection should fail when non supported cipher selected")





@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_DHE_RSA_AES128_SHA256_ca_cert_1_C113845(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request):
    testcase = request.node.name

    logger().info("Enabling ciphers DHE-RSA-AES128-SHA256 & ca_cert:1")
    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TLS", okc_value=10)

    device_ip, dut_mac_address, ap_bssid, host_ip = eap_obj.join_to_ap()

    # Validating the EAP failure frames
    packet_filter = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                    f'and tls.handshake.cipher_suites_length == 2 and tls.handshake.ciphersuite == 0x0067'
    logger().info(
        f"Validating EAP frames DHE-RSA-AES128-SHA256 cipher suits in sniffer"
    )
    eap_obj.verify_cipher_sniffer(packet_filter)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid
        | RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
        | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EapConn_with_invalid_date_C113851(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point,
                                                radius_server, request):
    testcase = request.node.name
    testcase = "test_WPA2_EapConn_with_invalid_date_C113851"

    wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hour=23,
                                     month_day=1,
                                     month=1, year=1930, week_day=4)

    eap_obj = EAP_Connectivity_negative(utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase,
                                        passphrase=wifi_access_point.interfaces.wifi.passphrase, username="user1",
                                        eap_method="TLS", eap_inner_method="auth=MSCHAPV2", private_key="",
                                        okc_value=0,
                                        wifi_connection_indication=1)
    eap_obj.eap_join(exp_error=75)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_Conn_TLS_when_no_cert_C113852(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point,
                                                radius_server, request):
    testcase = request.node.name
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)

    eap_obj = EAP_Connectivity_negative(utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase,
                                        passphrase=wifi_access_point.interfaces.wifi.passphrase, username="user1",
                                        eap_method="TLS", eap_inner_method="auth=MSCHAPV2", private_key="",
                                        okc_value=0,
                                        wifi_connection_indication=1)

    eap_obj.eap_join(exp_error=43)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_TLS_conn_with_wrong_cert_C113850(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point,
                                                   radius_server, request):
    testcase = request.node.name
    eap_obj = EAP_Connectivity_negative(utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase,
                                        passphrase=wifi_access_point.interfaces.wifi.passphrase, username="user1",
                                        eap_method="TLS", eap_inner_method="auth=MSCHAPV2", private_key="",
                                        okc_value=0,
                                        wifi_connection_indication=1)

    eap_obj.eap_join(exp_error=83)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_conn_with_wrong_pwd_C113848(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point,
                                              radius_server, request):
    testcase = request.node.name
    eap_obj = EAP_Connectivity_negative(utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase,
                                       passphrase="test123", username="user1",
                                       eap_method="TTLS", eap_inner_method="auth=MSCHAPV2", private_key="",
                                       okc_value=0,
                                       wifi_connection_indication=1)

    eap_obj.eap_join(exp_error=71)




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_conn_with_wrong_useridentity_C113849(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point,
                                                       radius_server, request):
    testcase = request.node.name
    eap_obj = EAP_Connectivity_negative(utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase,
                                        passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                        username="user2",
                                        eap_method="TTLS", eap_inner_method="auth=MSCHAPV2", private_key="",
                                        okc_value=0,
                                        wifi_connection_indication=1)

    eap_obj.eap_join(exp_error=71)
    logger().info("EAP connection should fail with error code:71")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WPA2_EAP_conn_with_wrong_eapmethod_C113853(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point,
                                                    radius_server, request):
    testcase = request.node.name

    eap_obj = EAP_Connectivity_negative(utf_constants, wifi_dut, wifi_sniffer, wifi_access_point, testcase,
                                        passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                        username="user1", eap_method="FAST", eap_inner_method="auth=MSCHAPV2",
                                        private_key="", okc_value=0, wifi_connection_indication=1)

    eap_obj.eap_join(exp_error=71)
    logger().info("EAP connection should fail with error code:71")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_WPA2_EAP_conn_with_fast_psp_C113864(utf_constants, rs_helper, wifi_sniffer, wifi_dut,
                                             wifi_access_point, radius_server,
                                             wifi_client, net_perf_client, protocol,
                                             request):
    testcase = request.node.name
    eap_obj = EAP_Connectivity_with_ciphers(utf_constants, rs_helper, wifi_dut, wifi_sniffer,
                                            wifi_access_point, wifi_client, net_perf_client,
                                            protocol, testcase, eap_type="TTLS")
    eap_obj.join_to_ap()
    eap_obj.verify_cipher_sniffer()





@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.store_config
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disable_store_config", "disassociated", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_WPA2_EAP_conn_when_auto_join_C113847(utf_constants, rs_helper, wifi_sniffer, wifi_dut,
                                              wifi_access_point, radius_server,
                                              wifi_client, net_perf_client, protocol, request):
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
            device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                          eap_type="TLS", power_save=False)
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

            logger().info(f"Initiating power save")
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)
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

        verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
        verify_sniffer.verify_sniffer_validation()

    except Exception as e:
        rs_helper.recovery_store_config(wifi_dut)
        raise
