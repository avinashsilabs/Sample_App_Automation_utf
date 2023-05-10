import datetime
from datetime import datetime
import re
from random import randint
import uuid
import pytest
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import (RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap,
                            RS9116CustomFeatureBitMap,
                            RS9116ConfigFeatureBitMap,
                            RS9116TCPIPFeatureBitMap,
                            RS9116ExtCustomFeatureBitMap,
                            RS9116ExtTCPIPFeatureBitMap,
                            RS9116CertificateType,
                            RS9116SecurityMode, RS9116PowerSaveProcedureTypes, RS9116JoinFeatureBitMap,
                            RS9116AsyncEventType,
                            SocketOptions,
                            SocketType,
                            Cipher,
                            )

from utf.utils.logger import get_logger
from typing import Union
import time
import random
import string
from utf.interfaces.wifi import SecurityMode, WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from test_wlan_sta_enterprise import SnifferValidationProcess

timeout = 60

def logger():
    return get_logger(__name__)

def text_generator(size=50):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


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
def test_connectivity_in_WPA2_EAP_TLS_v_1_2_C113765(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_connectivity_in_WPA2_EAP_TLS_v_1_2_C113765"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    logger().info("enable eap method")
    device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                  eap_type="TLS")
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
                     f'and eap and tls.record.version == 0x0303'

    logger().info(
        f"Validating EAP frames TLS version 1.2 in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.2 sent'



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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_connectivity_in_WPA2_EAP_TTLS_v_1_2_C113766(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_connectivity_in_WPA2_EAP_TLS_v_1_2_C113766"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    logger().info("enable eap method")
    device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                  eap_type="TTLS")
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
    timeout = 60
    rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="RX")

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
                     f'and eap and tls.record.version == 0x0303'

    logger().info(
        f"Validating EAP frames TLS version 1.2 in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.2 sent'




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
def test_connectivity_in_WPA2_EAP_PEAPV0_v_1_2_C113767(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_connectivity_in_WPA2_EAP_PEAPV0_v_1_2_C113767"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    logger().info("enable eap method")
    device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                  eap_type="PEAP")
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
                     f'and eap and tls.record.version == 0x0303'

    logger().info(
        f"Validating EAP frames TLS version 1.2 in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.2 sent'





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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_connectivity_in_WPA2_EAP_TLS_v_1_0_C113775(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_connectivity_in_WPA2_EAP_TLS_v_1_0_C113775"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    logger().info("enable eap method")
    device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                  eap_type="TLS")
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
    timeout = 60
    rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="RX")

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
                     f'and eap and tls.record.version == 0x0301'

    logger().info(
        f"Validating EAP frames TLS version 1.0 in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.0 sent'



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
def test_connectivity_in_WPA2_EAP_TTLS_v_1_0_C113776(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_connectivity_in_WPA2_EAP_TTLS_v_1_0_C113776"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

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

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0301'

    logger().info(
        f"Validating EAP frames TLS version 1.0 in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.0 sent'




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
def test_connectivity_in_WPA2_EAP_PEAPV0_v_1_0_C113777(rs_helper, utf_constants, radius_server, net_perf_client, protocol,
                                                    wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_connectivity_in_WPA2_EAP_PEAPV0_v_1_0_C113777"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    logger().info("enable eap method")
    device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                  eap_type="PEAP")
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
                     f'and eap and tls.record.version == 0x0301'

    logger().info(
        f"Validating EAP frames TLS version 1.0 in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.0 sent'





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
#EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_connectivity_in_WPA2_EAP_TLS_when_no_cert_C113779(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point, radius_server):
    testcase = "test_connectivity_in_WPA2_EAP_TLS_when_no_cert_C113779"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)
    logger().info("Setting roam parameters")
    # enable Roaming
    wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)
    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    for count in range(0, utf_constants.get('iter_count')):

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
            wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, eap_method="TLS", timeout=40)
            assert exc_info.value.error_code == 0x8, "Connection should failed with no certs"

        logger().info("Connection failed when expired certs loaded")

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
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_connectivity_in_WPA2_EAP_TTLS_when_no_cert_C113780(utf_constants, rs_helper, wifi_sniffer, wifi_dut,
                                                            wifi_access_point, radius_server,
                                                            wifi_client, net_perf_client, protocol):
    testcase = "test_connectivity_in_WPA2_EAP_TLS_when_no_cert_C113780"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    logger().info("enable eap method")
    device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                  eap_type="TTLS")
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
    timeout = 60
    rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="RX")

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
    }
)
 #EAP Connection in PEAP mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_connectivity_in_WPA2_EAP_PEAP_when_no_cert_C113781(utf_constants, rs_helper, wifi_sniffer, wifi_dut,
                                                            wifi_access_point, radius_server,
                                                            wifi_client, net_perf_client, protocol):
    testcase = "test_connectivity_in_WPA2_EAP_PEAP_when_no_cert_C113781"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    logger().info("enable eap method")
    device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                  eap_type="PEAP")
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
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
        | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
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
def test_connectivity_with_WPA2_EAP_with_expired_Date_TLS_C113771(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point,
                                                                 radius_server):
    testcase = "test_connectivity_with_WPA2_EAP_with_expired_Date_TLS_C113771"
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
            wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, eap_method="TLS", timeout=40)
            assert exc_info.value.error_code == 0x8, "Connection should failed with expired certs"

        logger().info("Connection failed when expired certs loaded")

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
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
        | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
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
def test_connectivity_with_WPA2_EAP_with_expired_Date_TTLS_C113772(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point,
                                                                 radius_server):
    testcase = "test_connectivity_with_WPA2_EAP_with_expired_Date_TTLS_C113772"
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
            wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, eap_method="TTLS", timeout=40)
            assert exc_info.value.error_code == 0x8, "Connection should failed with expired certs"

        logger().info("Connection failed when expired certs loaded")

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
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
        | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
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
def test_connectivity_with_WPA2_EAP_with_expired_Date_PEAP_C113773(utf_constants, wifi_sniffer, wifi_dut, wifi_access_point,
                                                                 radius_server):
    testcase = "test_connectivity_with_WPA2_EAP_with_expired_Date_PEAP_C113773"
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
            wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, eap_method="PEAP", timeout=40)
            assert exc_info.value.error_code == 0x8, "Connection should failed with expired certs"

        logger().info("Connection failed when expired certs loaded")

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
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_WLAN_Get_Stats_in_WPA2_EAP_C113800(rs_helper, utf_constants, radius_server, net_perf_client,
                                            wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_WLAN_Get_Stats_in_WPA2_EAP_C113800"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    logger().info("enable eap method")
    device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                  eap_type="TLS")
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    logger().info(f"there is an RSC-12527 for this failure")
    wifi_dut.interfaces.wifi.wlan_get_stats()

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
    wifi={
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
                              | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    },
)
@pytest.mark.skip("Need to get the steps")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_HTTP_Otaf_in_WPA2_Enterprise_C113803(rs_helper, utf_constants, http_server, radius_server, wifi_dut,
                                              wifi_access_point,
                                              wifi_sniffer):
    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat, "server is inactive"
    logger().info(f'http server state is {server_stat}')

    logger().info("fetching server ip....")
    host_ip = get_host_ip()
    logger().info(f"server ip is {host_ip}")

    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "failed to ping server"

    testcase = "test_HTTP_Otaf_in_WPA2_Enterprise_C113803"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    logger().info("dut fw version before upgrade...")
    wifi_dut.interfaces.wifi.version()

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")


    logger().info("enable eap method")
    device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                  eap_type="TLS")
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
    # timeout = 60
    # rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

    start_time = time.perf_counter_ns()
    async_timestamp = 0
    time.sleep(2)

    logger().info("performing firmware upgrade on dut....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)
    time.sleep(120)

    logger().info("fetching the otaf uprade status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    logger().info("fetching the otaf async events after the upgrade....")
    events = wifi_dut.interfaces.wifi.get_async_events()
    if len(events):
        for event in events:
            if event.event_type == RS9116AsyncEventType.HTTP_OTAF_STATUS:
                async_timestamp = event.timestamp

    if not async_timestamp:
        logger().info(f"Asynchronous message is not received after otaf over http")
    else:
        time_duration = (async_timestamp - start_time) / 1000000000

    if time_duration > 40:
        logger().warning(f"TOOK TOO LONG TIME TO DOWNLOAD FW {time_duration}")
    else:
        logger().info(f"time taken to upgrade firmware using http otaf {time_duration} seconds")

    logger().info("resetting DUT....")
    wifi_dut.interfaces.wifi.wireless_deinit(timeout=60)
    time.sleep(2)

    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.dut_init()

    logger().info("fetching dut version after init....")
    wifi_dut.interfaces.wifi.version()
    time.sleep(2)

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(5)

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()


@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 2,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V2,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
                              | RS9116TCPIPFeatureBitMap.SNTPClient
                              | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                                  | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                                   | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "band": 0,
            "eap_cert": "wifi-user.pem"
        },
    )
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "clear_certs"])
def test_sntp_connection_wpa2_enterprise_C113796(wifi_access_point, wifi_sniffer, wifi_client, wifi_dut, utf_constants, rs_helper, radius_server):
      testcase = "test_sntp_connection_in_WPA2_EAP_C113796"
      try:
            logger().info("configuring the Sniffer with the channel")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            logger().info("start capturing with Sniffer by giving the test case name as filename")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP bssid {ap_bssid}")
            host_ip = wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"Remote device ip :{host_ip}")
            logger().info("enable eap method")
            device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                  eap_type="TLS")
            sntp_server_address = wifi_dut.interfaces.wifi.get_sntp_server_ip()
            sntp_event = None
            wifi_dut.interfaces.wifi.sntp_create(server_ip=sntp_server_address)
            logger().info("wait for 10 seconds to receive SNTP asynchronous messages")
            time.sleep(10)
            asynchronous_request_time = 0
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=asynchronous_request_time)
            for event in events:
               if event.event_type == RS9116AsyncEventType.SNTP_EVENT:
                  sntp_event = event.event_data
                  asynchronous_request_time = event.timestamp + 1
               else:
                  assert 1, f"SNTP asynchronous event is not received by DUT after connection request was sent to SNTP server"
            sntp_event_status = int(sntp_event.split(b":")[1])
            command_type, sntp_time = wifi_dut.interfaces.wifi.get_sntp_time()
            command_type1, sntp_date_time = wifi_dut.interfaces.wifi.get_sntp_timedate()
            sntp_date_time_response = sntp_date_time.decode().split('.')[0]
            command_type2, ip_version, server_ip = wifi_dut.interfaces.wifi.get_sntp_server_info()
            sntp_status = {1: "SNTP status received in asynchronous message for SNTP connection request is wrong expected is 1 ", 2: "Command type received for the body of get_sntp_time response is wrong, expected is 2",  3 : "Command type received for the body of get_sntp_timedate response is wrong, expected is 3", 4: "Command type received for the body of get_sntp_server_info response is wrong, expected ",
                           5: "Ip version received for the body of get_sntp_server_info response is wrong, expected ",  6:  f"SNTP server ip address received for the body of get_sntp_server_info " \
                                             f"response is wrong, expected " \
                                             "is {sntp_server_address}"}
            assert sntp_event_status == 1, f"{sntp_status[1]}"
            assert command_type == 2, f"{sntp_status[2]}"
            assert command_type1 == 3, f"{sntp_status[3]}"
            assert command_type2 == 6, f"{sntp_status[4]}"
            assert ip_version == 4, f"{sntp_status[5]}"
            assert server_ip == sntp_server_address, f"{sntp_status[6]}"

            wifi_dut.interfaces.wifi.sntp_delete()
            logger().info("wait for 5 seconds to receive SNTP asynchronous messages")
            time.sleep(5)
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=asynchronous_request_time)
            for event in events:
              if event.event_type == RS9116AsyncEventType.SNTP_EVENT:
                 sntp_event = event.event_data
              else:
                 assert 1, f"SNTP asynchronous event is not received by DUT after SNTP delete is initiated"
            sntp_status = int(sntp_event.split(b":")[1])
            assert sntp_status == 1, "SNTP status received in asynchronous message for SNTP delete request is wrong expected " \
                             "is 1 "
            time.sleep(2)
            wifi_dut.interfaces.wifi.leave(timeout=30)
            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info(f"Date and time sent by DUT {sntp_date_time_response}")
            verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
            verify_sniffer.verify_sniffer_validation()

      except Exception as err:
         logger().info(f"Testcases failed with : {err}")
         raise err

      finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("\n******Disabling powersave******")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)


class WebsocketEventHandler:
    def __init__(self):
        self.client_connected = False
        self.client_disconnected = False
        self.message_received = ""

    def on_ws_client_connected(self, client: dict):
        self.client_connected = True

    def on_ws_client_disconnected(self, client: dict):
        self.client_disconnected = True

    def on_ws_message_received(self, client: dict, message: Union[str, bytes]):
        logger().info(f"what is the message getting received {message} ")
        self.message_received = message
        logger().info(f"received message {len(self.message_received)}")


@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 2,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
                              | RS9116TCPIPFeatureBitMap.SSL
                              | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                                  | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                                   | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "band": 0,
            "eap_cert": "wifi-user.pem",
            "ca_cert": "ca-chain.cert.pem",
            "set_send_feature_frame": True,
        },
    )
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "clear_certs"])
def test_web_socket_over_ssl_in_wpa2_enterprise_C113802(wifi_sniffer, wifi_access_point, wifi_client, utf_constants, rs_helper, wifi_dut, http_server, radius_server):
       try:
           testcase = "test_WLAN_in_WPA2_EAP_C113802"
           logger().info("configuring the Sniffer with the channel")
           wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

           logger().info("start capturing with Sniffer by giving the test case name as filename")
           wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

           ap_bssid = wifi_access_point.interfaces.wifi.bssid
           logger().info(f"AP bssid {ap_bssid}")
           host_ip = wifi_client.interfaces.wifi.get_ip_address()
           logger().info(f"Remote device ip :{host_ip}")
           logger().info("enable eap method")
           device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                  eap_type="TLS")
           ws_handler = WebsocketEventHandler()
           http_server.interfaces.http.set_fn_on_websocket_client_connected(
             ws_handler.on_ws_client_connected
            )
           http_server.interfaces.http.set_fn_on_websocket_client_disconnected(
             ws_handler.on_ws_client_disconnected
           )
           http_server.interfaces.http.set_fn_on_websocket_message_received(
            ws_handler.on_ws_message_received
             )
           wifi_dut.interfaces.wifi.connect_to_websocket_server(0, http_server.interfaces.http, server_port=80,
                                                         local_port=5001)
           logger().info("connect_to_websocket_server")
           time.sleep(0.1)
           assert ws_handler.client_connected
           iter_count = 30
           data = []
           for i in range(iter_count):
               data.append(text_generator(size=5))
               data_final = "".join(data)
               wifi_dut.interfaces.wifi.send_data_over_websocket(0, opcode=129, message=data_final)
               logger().info("send_data_over_websocket")
               time.sleep(2)
               assert ws_handler.message_received == data_final
           wifi_dut.interfaces.wifi.websocket_close(0)
           logger().info("websocket_close")
           time.sleep(2)
           assert ws_handler.client_disconnected
           logger().info("Initiating wlan_disconnect from DUT")
           wifi_dut.interfaces.wifi.leave()
           logger().info("Stop Sniffer finally")
           time.sleep(5)
           wifi_sniffer.interfaces.capture.stop_capture()
           verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
           verify_sniffer.verify_sniffer_validation()

       except Exception as e:
           logger().info(f"\n******Testcase failed with  {e}******")
           raise e
       finally:
           logger().info("\n******Stop Sniffer finally******")
           wifi_sniffer.interfaces.capture.stop_capture()

           logger().info("\n******Disabling powersave******")
           wifi_dut.interfaces.wifi.power_save(0, 0)
           wifi_dut.interfaces.wifi.bt_power_save(0, 0)



@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 2,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL
                              | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.FeatureLowPower
                                   | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "band": 0,
            "eap_cert": "wifi-user.pem",
            "ca_cert": "ca-chain.cert.pem",
            "set_send_feature_frame": True,
        },
    )
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable","disassociated", "clear_certs"])
def test_ssl_socket_connection_in_wpa2_enterprise_C113793(wifi_sniffer, wifi_access_point, wifi_client, utf_constants, wifi_dut, rs_helper, ssl_server, radius_server):
       try:
           testcase = "test_ssl_connection_in_WPA2_EAP_C113793"
           pkt_count = ssl_server.interfaces.ssl.config["no_of_pkts"]
           buffer_length = ssl_server.interfaces.ssl.config["buffer_length"]
           port1 = ssl_server.interfaces.ssl.config["device_port1"]
           logger().info("configuring the Sniffer with the channel")
           wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

           logger().info("start capturing with Sniffer by giving the test case name as filename")
           wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

           ap_bssid = wifi_access_point.interfaces.wifi.bssid
           logger().info(f"AP bssid {ap_bssid}")
           host_ip = wifi_client.interfaces.wifi.get_ip_address()
           logger().info(f"Remote device ip :{host_ip}")
           logger().info("enable eap method")
           device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                     eap_type="TLS")

           logger().info(f"Open ssl server socket in remote device(Raspberry pi or static device")
           ssl_server.interfaces.ssl.start_server()
           logger().info(f"Open ssl client socket in the DUT")
           sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
           assert sock == 0, "Socket id received is wrong. expected is 0"
           logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
           logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
           logger().info(f"Enable ssl option for socket opened")
           wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

           local_port = randint(5001, 60000)
           logger().info(f"Socket binds at (device_ip, 5001) in DUT")
           wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
           logger().info(f"ssl socket opened in DUT connects to the server")
           wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

           logger().info(f"The api returns 100 bytes of random data")
           data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
           data_length = len(data_sent)
           logger().info(f"Sending data {data_sent} over socket_no->{sock}")
           logger().info(f"DUT sends 100 bytes of data over ssl socket")
           wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
           server_socket_no = 1
           logger().info(f"SSL server receives the data over ssl socket")
           data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
           logger().info(f"Data received on remote socket opened is {data_receive}")
           assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
           logger().info("Data sent by DUT and received on server is matching")

           if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
             ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
           result = wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
           logger().info(f"Number of bytes sent by dut {result}")
           bytes_sent = result
           assert_packet_check = (0.95 * float(bytes_sent))
           logger().info(f"Number of bytes sent by dut {assert_packet_check}")
           bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
           assert bytes_received >= int(
              assert_packet_check), f"Number of bytes sent by DUT and received on the remote peer are" \
                                  f"not matched on socket {server_socket_no} "
           logger().info(
            f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
           result = wifi_dut.interfaces.wifi.close_socket(sock)
           assert b"success" in result, "unable to close opened ssl socket in the dut"
           logger().info("Successfully closed opened socket in the DUT")
           logger().info("Stop Sniffer finally")
           wifi_sniffer.interfaces.capture.stop_capture()
           verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
           verify_sniffer.verify_sniffer_validation()

       except Exception as e:
           logger().info(f"***************testcase failed with {e}")
           raise e

       finally:
           logger().info("\n******Stop Sniffer finally******")
           wifi_sniffer.interfaces.capture.stop_capture()
           logger().info("\n******Disabling powersave******")
           wifi_dut.interfaces.wifi.power_save(0, 0)
           wifi_dut.interfaces.wifi.bt_power_save(0, 0)



@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 2,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
            "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL
                              | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features":  RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                                  | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
            "ext_custom_features":  RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.FeatureLowPower
                                   | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 ,
            "band": 0,
            "eap_cert": "wifi-user.pem",
            "ca_cert": ["ca-chain.cert.pem", "ca-chain.cert.pem", "ca-chain.cert.pem"],
        },
    )
@pytest.mark.parametrize("cert1, cert2,cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]
                              )
                         ]
                         )
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "clear_certs"])
def test_three_ssl_connection_in_wpa2_enterprise_C113797(utf_constants, ssl_server, wifi_access_point, wifi_sniffer, wifi_client, wifi_dut, rs_helper, cert1, cert2, cert3, radius_server):
       try:
           testcase = "test_WLAN_3_ssl_connection_in_WPA2_EAP_C113797"
           logger().info("configuring the Sniffer with the channel")
           wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

           logger().info("start capturing with Sniffer by giving the test case name as filename")
           wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

           ap_bssid = wifi_access_point.interfaces.wifi.bssid
           logger().info(f"AP bssid {ap_bssid}")
           host_ip = wifi_client.interfaces.wifi.get_ip_address()
           logger().info(f"Remote device ip :{host_ip}")
           logger().info("enable eap method")
           device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                     eap_type="TLS")
           port1 = 5001
           port2 = 5003
           port3 = 5005
           logger().info(f"Open ssl server socket in remote device(Raspberry pi or static device")
           ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
           logger().info(f"Open ssl server socket in remote device(Raspberry pi or static device")
           ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
           logger().info(f"Open ssl server socket in remote device(Raspberry pi or static device")
           ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

           for sock_count in range(0, 3):
                logger().info(f"Open ssl client socket in the DUT")
                sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)

                if sock_count == 0:
                    assert sock == 0, f"socket id received is wrong, expected is 0"
                elif sock_count == 1:
                     assert sock == 1, f"socket id received is wrong, expected is 1"
                else:
                     assert sock == 2, f"socket id received is wrong, expected is 2"

                logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                logger().info(f"Enable ssl option for socket opened")
                wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
                logger().info(
                f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
                wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)
                if sock_count == 0:
                    cert_index = SocketOptions.CERT_INDEX0
                elif sock_count == 1:
                   cert_index = SocketOptions.CERT_INDEX1

                else:
                    cert_index = SocketOptions.CERT_INDEX2

                logger().info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
                wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       cert_index)
                if sock_count == 0:
                   socket_port = port1
                elif sock_count == 1:
                   socket_port = port2
                else:
                   socket_port = port3

                logger().info(f"Socket binds at (device_ip, 5001) in DUT")
                wifi_dut.interfaces.wifi.bind(sock, device_ip, socket_port)
                logger().info(f"ssl socket opened in DUT connects to the server")
                wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

           socket_no = [1, 2, 3]

           for iteration in range(1, 101):
               for socket in socket_no:
                buffer_length = 100
                pkt_count = 1
                tx_buffer = "".join(
                    random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
                )
                if socket < 3:
                    data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                    data_length = len(data_sent)
                    logger().info(f"Sending data {data_sent} over socket_no->{socket - 1}")
                    wifi_dut.interfaces.wifi.send_data(socket - 1, data_length, data_sent)
                    server_socket_no = socket
                    data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
                    logger().info(f"Data received on remote socket opened is {data_receive}")
                    assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
                    logger().info("Data sent by DUT and received on server is matching")
                else:
                    ssl_server.interfaces.ssl.send_data(socket, pkt_count, buffer_length, message=tx_buffer)
                    socket_id = (socket - 1)
                    buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=socket_id,
                                                                                        data_len=buffer_length)
                    if not (buffer_length == buffer_length_rx):
                        logger().info(
                            f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is "
                            f"not matched on socket_id->{socket_id}")
                    else:
                        logger().info(
                            f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is "
                            f"matched on socket_id->{socket_id}")
                    assert buffer_length == buffer_length_rx, f"buffer length sent by remote peer and received on the " \
                                                              f"socket id {sock} opened in the DUT is not matched "
                    if not (tx_buffer.encode() == buffer_rx):
                        logger().info(
                            f"contents of data sent by remote peer and received on the socket id {sock} opened in the DUT "
                            f"is not matched on socket_id->{socket_id}")
                    else:
                        logger().info(
                            f"contents of data sent by remote peer and received on the socket id {sock} opened in the DUT "
                            f"is matched on socket_id->{socket_id}")
                    assert tx_buffer.encode() == buffer_rx, f"contents of data sent by remote peer and received on the " \
                                                            f"socket " \
                                                            f"id {sock} opened in the DUT is not matched on socket_id->{socket_id} "


           for sock_count in range(0, 3):
              logger().info(f"Closing socket_id->{sock_count}")
              result = wifi_dut.interfaces.wifi.close_socket(sock_count)
              assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
              logger().info(f"Successfully closed socket_id->{sock_count}")
              wifi_sniffer.interfaces.capture.stop_capture()
              verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
              verify_sniffer.verify_sniffer_validation()

       except Exception as e:
          logger().info(f"\n******Testcase failed with : {e}******")
          raise e

       finally:
         logger().info("\n******Stop Sniffer finally******")
         wifi_sniffer.interfaces.capture.stop_capture()
         logger().info("\n******Disabling powersave******")
         wifi_dut.interfaces.wifi.power_save(0, 0)
         wifi_dut.interfaces.wifi.bt_power_save(0, 0)



@pytest.mark.config(
    "wifi_dut",
    wifi={
            "oper_mode": 2,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL
                              | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features":  RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose |RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.FeatureLowPower
                                   | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "band": 0,
            "ca_cert": "ca-chain.cert.pem",
            "eap_cert": "wifi-user.pem",
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "clear_certs"])
def test_https_client_connection_wpa2_enterprise_C113805(http_server, wifi_sniffer, wifi_dut, http_client, wifi_access_point,
                                        index_path, rs_helper, utf_constants, radius_server):
    try:
        file_name = 'test_https_put_functionality_C113805'
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
        logger().info("enable eap method")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                  eap_type="TLS")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

        logger().info("Creating of HTTP PUT ")
        wifi_dut.interfaces.http.http_put_create()

        logger().info("Creating of HTTP PUT ")
        wifi_dut.interfaces.http.http_put(http_server.interfaces.http, index_path)

        logger().info(f"Delete https client")
        wifi_dut.interfaces.http.http_client_put_delete()


        logger().info("Giving http get command")
        wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)

        logger().info("Giving http post command")
        wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                           post_data="hellothisiaatestcaseforget")

        logger().info(f"DUT going to leave")
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        logger().info("Sniffer going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
        verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
        verify_sniffer.verify_sniffer_validation()

    except Exception as e:
        logger().info(f"\n******Assertion {e}******")
        raise e

    finally:
        logger().info("\n******Disabling powersave******")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)



@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 2,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
                              | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features":  RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose |RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.FeatureLowPower
                                   | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "band": 0,
            "eap_cert": "wifi-user.pem",
        },
    )
@pytest.mark.skip("Enhancements required")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "clear_certs"])
def test_pmk_caching_wpa2_enterprise_C113790(rs_helper, wifi_sniffer, wifi_access_point,
                                                                    wifi_dut, wifi_client, utf_constants, radius_server, switches):
    testcase = "test_pmk_caching_in_WPA2_EAP_C113790"
    try:
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        logger().info('******* Turn on Access point **********')
        switches[0].interfaces.pdu_switch.turn_on(delay=60)
        logger().info("enable eap method")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS")
        switches[1].interfaces.pdu_switch.turn_on(delay=60)
        switches[0].interfaces.pdu_switch.turn_off(delay=10)
        logger().info("pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")
        wifi_dut.interfaces.wifi.leave(timeout=30)
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()
        verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
        verify_sniffer.verify_sniffer_validation()

    except Exception as e:
        logger().info(f"\n******Assertion {e}******")
        raise e

    finally:
        switches[1].interfaces.pdu_switch.turn_on(delay=10)
        logger().info("\n******Disabling powersave******")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)


@pytest.mark.config(
    "wifi_dut",
    wifi={
            "oper_mode": 2,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient
                              | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features":  RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose |RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.FeatureLowPower
                                   | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "band": 0,
            "eap_cert": "wifi-user.pem",
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "clear_certs"])
def test_http_client_connection_wpa2_enterprise_C113806(http_server, wifi_sniffer, wifi_dut, http_client, wifi_access_point,
                                        index_path, rs_helper, utf_constants, radius_server):
    try:
        file_name = 'test_https_put_functionality_C113806'
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
        logger().info("enable eap method")
        device_ip, dut_mac_address = rs_helper.check_eap_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                      eap_type="TLS")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

        logger().info("Creating of HTTP PUT ")
        wifi_dut.interfaces.http.http_put_create()

        logger().info("Creating of HTTP PUT ")
        wifi_dut.interfaces.http.http_put(http_server.interfaces.http, index_path)

        logger().info(f"Delete https client")
        wifi_dut.interfaces.http.http_client_put_delete()

        logger().info("Giving http get command")
        wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)

        logger().info("Giving http post command")
        wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                           post_data="hellothisiaatestcaseforget")

        logger().info(f"DUT going to leave")
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        logger().info("Sniffer going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
        verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
        verify_sniffer.verify_sniffer_validation()

    except Exception as e:
        logger().info(f"\n******Assertion {e}******")
        raise e

    finally:
        logger().info("\n******Disabling powersave******")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)






