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

Author: swathi.pathuri
"""


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
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_DHE_RSA_AES256_SHA256_TLSv12_C113821"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        logger().info("enable eap method TLS with cipher DHE-RSA-AES256-SHA256")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS", okc_value=4)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x006b ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit DHE-RSA-AES256-SHA256 in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.2 & cipher suit DHE-RSA-AES256-SHA256 in sniffer'





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
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_DHE_RSA_AES128_SHA256_TLSv12_C113822"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        logger().info("enable eap method TLS with cipher DHE-RSA-AES128-SHA256")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS", okc_value=8)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x0067 ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit DHE-RSA-AES128-SHA256 in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.2 & cipher suit DHE-RSA-AES128-SHA256 in sniffer'



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
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_DHE_RSA_AES256_SHA_TLSv12_C113823"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        logger().info("enable eap method TLS with cipher DHE-RSA-AES256-SHA")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS", okc_value=16)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x0039 ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit DHE-RSA-AES256-SHA in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.2 & cipher suit DHE-RSA-AES256-SHA in sniffer'



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
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_DHE_RSA_AES128_SHA_TLSv12_C113824"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        logger().info("enable eap method TLS with cipher DHE-RSA-AES128-SHA")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS", okc_value=32)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x0033 ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit DHE-RSA-AES128-SHA in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.2 & cipher suit DHE-RSA-AES128-SHA in sniffer'




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
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_AES256_SHA256_TLSv12_C113825"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        logger().info("enable eap method TLS with cipher AES256-SHA256")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS", okc_value=64)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x003d ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit AES256-SHA256 in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.2 & cipher suit AES256-SHA256 in sniffer'





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
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_AES128_SHA256_TLSv12_C113826"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        logger().info("enable eap method TLS with cipher AES128-SHA256")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS", okc_value=128)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x003c ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit AES128-SHA256 in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.2 & cipher suit AES128-SHA256 in sniffer'




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
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_AES256_SHA_TLSv12_C113827"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        logger().info("enable eap method TLS with cipher AES256_SHA")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS", okc_value=256)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x0035 ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit AES256_SHA in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.2 & cipher suit AES256_SHA in sniffer'




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
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_AES128_SHA_TLSv12_C113828"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        logger().info("enable eap method TLS with cipher AES128_SHA")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS", okc_value=512)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x002f ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit AES128_SHA in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.2 & cipher suit AES128_SHA in sniffer'





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
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_AES256_SHA256_and_AES256_SHA_TLSv12_C113832"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        logger().info("enable eap method TLS with cipher DHE-RSA-AES256-SHA256 and DHE-RSA-AES256-SHA")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS", okc_value=20)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 and tls.handshake.ciphersuite == 0x006b ' \
                     f'and tls.handshake.ciphersuite == 0x0039 and tls.handshake.cipher_suites_length == 4'
    logger().info(
        f"Validating EAP frames TLS version 1.2 and cipher suit DHE-RSA-AES256-SHA256 and DHE-RSA-AES256-SHA in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.2 & cipher suit DHE-RSA-AES256-SHA256' \
                         ' and DHE-RSA-AES256-SHA in sniffer'




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
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_all_ciphers_TLSv12_C113833"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        logger().info("enable eap method TLS with cipher all ciphers")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS", okc_value=8188)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0303 ' \
                     f'and tls.handshake.cipher_suites_length == 22'
    logger().info(
        f"Validating EAP frames TLS version 1.2 and all cipher suits in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.2 & all cipher suits in sniffer'




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
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_non_supported_ciphers_TLSv12_C113834"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        # enable Roaming
        wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)
        logger().info("enable rejoin")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

        logger().info("scanning for AP")
        # test_scan
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        logger().info(scan_results)

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("enable eap method TLS with RC4-MD5 cipher")

        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, eap_method="TLS", okc_value=1024, timeout=40,
                                                 wifi_connection_indication=1)
            assert exc_info.value.error_code == 0x8, "Connection should fail when non supported cipher selected"

        logger().info("Connection will fail when non supported cipher selected")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid,
                                              conn_status=False)
    verify_sniffer.verify_sniffer_validation()




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
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_DHE_RSA_AES256_SHA_TLSv10_C113835"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        logger().info("enable eap method TLS with cipher DHE-RSA-AES256-SHA")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS", okc_value=16)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0301 and tls.handshake.ciphersuite == 0x0039 ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.0  and cipher suit DHE-RSA-AES256-SHA in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.0 & cipher suit DHE-RSA-AES256-SHA in sniffer'



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
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_DHE_RSA_AES128_SHA_TLSv10_C113836"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        logger().info("enable eap method TLS with cipher DHE-RSA-AES128-SHA")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS", okc_value=32)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0301 and tls.handshake.ciphersuite == 0x0033 ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.0  and cipher suit DHE-RSA-AES128-SHA in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.0 & cipher suit DHE-RSA-AES128-SHA in sniffer'




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
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_AES256_SHA_TLSv10_C113837"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        logger().info("enable eap method TLS with cipher AES256_SHA")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS", okc_value=256)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0301 and tls.handshake.ciphersuite == 0x0035 ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.2  and cipher suit AES256_SHA in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.0 & cipher suit AES256_SHA in sniffer'




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
def test_WPA2_EAP_AES128_SHA_TLSv12_C113838(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_AES128_SHA_TLSv12_C113838"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        logger().info("enable eap method TLS with cipher AES128_SHA")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS", okc_value=512)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0301 and tls.handshake.ciphersuite == 0x002f ' \
                     f'and tls.handshake.cipher_suites_length == 2'
    logger().info(
        f"Validating EAP frames TLS version 1.0  and cipher suit AES128_SHA in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.0 & cipher suit AES128_SHA in sniffer'




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
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_all_ciphers_TLSv10_C113843"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        logger().info("enable eap method TLS with cipher all ciphers")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS", okc_value=8188)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0301 ' \
                     f'and tls.handshake.cipher_suites_length == 22'
    logger().info(
        f"Validating EAP frames TLS version 1.0 and all cipher suits in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.0 & all cipher suits in sniffer'



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
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WPA2_EAP_non_supported_ciphers_TLSv10_C113844"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    for count in range(0, utf_constants.get('iter_count')):

        # enable Roaming
        wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)
        logger().info("enable rejoin")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

        logger().info("scanning for AP")
        # test_scan
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        logger().info(scan_results)

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("enable eap method TLS with RC4-MD5 cipher")
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, eap_method="TLS", okc_value=1024, timeout=40,
                                                 wifi_connection_indication=1)
            assert exc_info.value.error_code == 0x8, "Connection should fail when non supported cipher selected"

        logger().info("Connection will fail when non supported cipher selected")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid,
                                              conn_status=False)
    verify_sniffer.verify_sniffer_validation()




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
                                                radius_server):
    testcase = "test_WPA2_EapConn_with_invalid_date_C113851"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    for count in range(0, utf_constants.get('iter_count')):
        wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hour=23,
                                         month_day=1,
                                         month=1, year=1930, week_day=4)

        logger().info("scanning for AP")
        # test_scan
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        logger().info(scan_results)

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")

        logger().info("Initiate connection")
        with pytest.raises(WlanError) as exc_info:
            logger().info("Initiating join")
            wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, eap_method="TLS", timeout=40,
                                                 wifi_connection_indication=1)
            assert exc_info.value.error_code == 0x8, "Connection should failed with expired certs"

        events = wifi_dut.interfaces.wifi.get_async_events()
        status = False
        for event in events:
            logger().info(f"event type : {event.event_type}")
            logger().info(f"event data : {event.event_data}")
            rsp = event.event_data.decode('utf-8')
            if "reason_code" in rsp:
                y = re.search(r"reason_code-(.*)", rsp)
                assert y, "reason code not found in event"
                logger().info(f"reason_code : ***************{y.group(1)}****************")
                assert int(y.group(1)) == 75, f"expected error code: 75 but found {y.group(1)}"
                logger().info(f"expected error code found :******{y.group(1)}:CLIENT_ROOT_CA_BAD_DATE_ERR:75 or 4B(hex)"
                              f"**********")
                status = True

        assert status, "Event not found with reason code"

        with pytest.raises(WlanError) as exc_info:
            logger().info("Initiate ip command")
            ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=20)
            assert exc_info.value.error_code == 0x21, "ip command should failed 0x21 error"

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid,
                                                conn_status=False)
    verify_sniffer.verify_sniffer_validation()




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
def test_WPA2_EAP_Conn_TLS_when_no_cert_C113852(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point, radius_server):
    testcase = "test_WPA2_EAP_Conn_TLS_when_no_cert_C113852"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)

    for count in range(0, utf_constants.get('iter_count')):
        logger().info("Setting roam parameters")
        # enable Roaming
        wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)
        logger().info("enable rejoin")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

        logger().info("scanning for AP")
        # test_scan
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        logger().info(scan_results)

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")

        logger().info("Initiating join")
        logger().info("Initiate connection")
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, eap_method="TLS", timeout=40,
                                                 wifi_connection_indication=1)
            assert exc_info.value.error_code == 0x8, "Connection should fail when no certs loaded"

        events = wifi_dut.interfaces.wifi.get_async_events()
        status = False
        for event in events:
            logger().info(f"event type : {event.event_type}")
            logger().info(f"event data : {event.event_data}")
            rsp = event.event_data.decode('utf-8')
            if "reason_code" in rsp:
                y = re.search(r"reason_code-(.*)", rsp)
                assert y, "reason code not found in event"
                logger().info(f"reason_code : ***************{y.group(1)}****************")
                assert int(y.group(1)) == 43, f"expected error code: 43 but found {y.group(1)}"
                logger().info(f"expected error code found ***************{y.group(1)} :TLS_NO_CERT_PRESENT -> 43 or 2B(hex)"
                              f"****************")
                status = True

        assert status, "Event not found with reason code"
        logger().info("Connection failed when no certs loaded")

        with pytest.raises(WlanError) as exc_info:
            logger().info("Initiate ip command")
            ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=20)
            assert exc_info.value.error_code == 0x21, "ip command should failed 0x21 error"

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address,
                                              ap_bssid, conn_status=False)
    verify_sniffer.verify_sniffer_validation()


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
def test_WPA2_EAP_TLS_conn_with_wrong_cert_C113850(wifi_sniffer, wifi_dut, wifi_access_point, radius_server):
    testcase = "test_WPA2_EAP_TLS_conn_with_wrong_cert_C113850"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    logger().info("Setting roam parameters")
    # enable Roaming
    wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)
    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    logger().info("scanning for AP")
    # test_scan
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    logger().info(scan_results)

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    logger().info("Initiating join")
    logger().info("Initiate connection")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, eap_method="TLS", timeout=40,
                                             wifi_connection_indication=1)
        assert exc_info.value.error_code == 0x8, "Connection should fail when no certs loaded"

    events = wifi_dut.interfaces.wifi.get_async_events()
    status = False
    for event in events:
        logger().info(f"event type : {event.event_type}")
        logger().info(f"event data : {event.event_data}")
        rsp = event.event_data.decode('utf-8')
        if "reason_code" in rsp:
            y = re.search(r"reason_code-(.*)", rsp)
            assert y, "reason code not found in event"
            logger().info(f"reason_code : ***************{y.group(1)}****************")
            assert int(y.group(1)) == 83, f"expected error code: 43 but found {y.group(1)}"
            logger().info(f"expected error code found ***************{y.group(1)} :PEM_ERROR 83 or 53(hex)"
                          f"****************")
            status = True

    assert status, "Event not found with reason code"
    logger().info("Connection failed when no certs loaded")
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address,
                                              ap_bssid, conn_status=False)
    verify_sniffer.verify_sniffer_validation()




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
def test_WPA2_EAP_conn_with_wrong_pwd_C113848(wifi_sniffer, wifi_dut, wifi_access_point, radius_server):
    testcase = "test_WPA2_EAP_conn_with_wrong_pwd_C113848"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    logger().info("Setting roam parameters")
    # enable Roaming
    wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)
    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    logger().info("scanning for AP")
    # test_scan
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    logger().info(scan_results)

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    logger().info("Initiating join")
    logger().info("Initiate connection")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, passphrase="test123", eap_method="TTLS", timeout=40,
                                             wifi_connection_indication=1)
        assert exc_info.value.error_code == 0x8, "Connection should fail with wrong password"

    events = wifi_dut.interfaces.wifi.get_async_events()
    status = False
    for event in events:
        logger().info(f"event type : {event.event_type}")
        logger().info(f"event data : {event.event_data}")
        rsp = event.event_data.decode('utf-8')
        if "reason_code" in rsp:
            y = re.search(r"reason_code-(.*)", rsp)
            assert y, "reason code not found in event"
            logger().info(f"reason_code : ***************{y.group(1)}****************")
            assert int(y.group(1)) == 71, f"expected error code: 71 but found {y.group(1)}"
            logger().info(f"expected error code found ***************{y.group(1)} :EAP_FAILURE_RECEIVED -> 71 or 47(hex)"
                          f"****************")
            status = True

    assert status, "Event not found with reason code"
    logger().info("Connection failed when no certs loaded")

    with pytest.raises(WlanError) as exc_info:
        logger().info("Initiate ip command")
        ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=20)
        assert exc_info.value.error_code == 0x21, "ip command should failed 0x21 error"

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address,
                                              ap_bssid, conn_status=False)
    verify_sniffer.verify_sniffer_validation()




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
def test_WPA2_EAP_conn_with_wrong_useridentity_C113849(wifi_sniffer, wifi_dut, wifi_access_point, radius_server):
    testcase = "test_WPA2_EAP_conn_with_wrong_useridentity_C113849"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    logger().info("Setting roam parameters")
    # enable Roaming
    wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)
    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    logger().info("scanning for AP")
    # test_scan
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    logger().info(scan_results)

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    logger().info("Initiating join")
    logger().info("Initiate connection")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, username="user2", eap_method="TTLS", timeout=40,
                                             wifi_connection_indication=1)
        assert exc_info.value.error_code == 0x8, "Connection should fail with wrong useridentity"

    events = wifi_dut.interfaces.wifi.get_async_events()
    status = False
    for event in events:
        logger().info(f"event type : {event.event_type}")
        logger().info(f"event data : {event.event_data}")
        rsp = event.event_data.decode('utf-8')
        if "reason_code" in rsp:
            y = re.search(r"reason_code-(.*)", rsp)
            assert y, "reason code not found in event"
            logger().info(f"reason_code : ***************{y.group(1)}****************")
            assert int(y.group(1)) == 71, f"expected error code: 71 but found {y.group(1)}"
            logger().info(f"expected error code found ***************{y.group(1)} :EAP_FAILURE_RECEIVED -> 71 or 47(hex)"
                          f"****************")
            status = True

    assert status, "Event not found with reason code"
    logger().info("Connection failed when no certs loaded")

    with pytest.raises(WlanError) as exc_info:
        logger().info("Initiate ip command")
        ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=20)
        assert exc_info.value.error_code == 0x21, "ip command should failed 0x21 error"

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address,
                                              ap_bssid, conn_status=False)
    verify_sniffer.verify_sniffer_validation()


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
def test_WPA2_EAP_conn_with_wrong_eapmethod_C113853(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point, radius_server):
    testcase = "test_WPA2_EAP_conn_with_wrong_eapmethod_C113853"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    for count in range(0, utf_constants.get('iter_count')):

        logger().info("Setting roam parameters")
        # enable Roaming
        wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)
        logger().info("enable rejoin")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

        logger().info("scanning for AP")
        # test_scan
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        logger().info(scan_results)

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")

        logger().info("Initiating join")
        logger().info("Initiate connection")
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, eap_method="FAST", timeout=40,
                                                 wifi_connection_indication=1)
            assert exc_info.value.error_code == 0x8, "Connection should fail with wrong useridentity"

        events = wifi_dut.interfaces.wifi.get_async_events()
        status = False
        for event in events:
            logger().info(f"event type : {event.event_type}")
            logger().info(f"event data : {event.event_data}")
            rsp = event.event_data.decode('utf-8')
            if "reason_code" in rsp:
                y = re.search(r"reason_code-(.*)", rsp)
                assert y, "reason code not found in event"
                logger().info(f"reason_code : ***************{y.group(1)}****************")
                assert int(y.group(1)) == 71, f"expected error code: 71 but found {y.group(1)}"
                logger().info(f"expected error code found ***************{y.group(1)} :EAP_FAILURE_RECEIVED -> 71 or 47(hex)"
                              f"****************")
                status = True

        assert status, "Event not found with reason code"
        logger().info("Connection failed when no certs loaded")

        with pytest.raises(WlanError) as exc_info:
            logger().info("Initiate ip command")
            ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=20)
            assert exc_info.value.error_code == 0x21, "ip command should failed 0x21 error"

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address,
                                              ap_bssid, conn_status=False)
    verify_sniffer.verify_sniffer_validation()




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
                                                            wifi_client, net_perf_client, protocol):
    testcase = "test_WPA2_EAP_conn_with_fast_psp_C113864"
    validation = True
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
                                                                      eap_type="TTLS")
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")
        logger().info("Initiating disconnect from DUT")

        # Wlan Disconnect
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()





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
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disable_store_config", "disassociated", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_WPA2_EAP_conn_when_auto_join_C113847(utf_constants, rs_helper, wifi_sniffer, wifi_dut,
                                                            wifi_access_point, radius_server,
                                                            wifi_client, net_perf_client, protocol):
    try:
        testcase = "test_WPA2_EAP_conn_when_auto_join_C113847"
        validation = True
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
