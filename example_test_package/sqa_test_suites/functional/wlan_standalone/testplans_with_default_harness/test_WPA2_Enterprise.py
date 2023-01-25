import pytest
from utf_wiseconnect.devices.rs911x import (RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap,
                            RS9116CustomFeatureBitMap,
                            RS9116ConfigFeatureBitMap,
                            RS9116TCPIPFeatureBitMap,
                            RS9116ExtCustomFeatureBitMap,
                            RS9116ExtTCPIPFeatureBitMap,
                            RS9116CertificateType,
                            RS9116SecurityMode, RS9116PowerSaveProcedureTypes, RS9116JoinFeatureBitMap,
                            RS9116AsyncEventType
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
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
        RS9116TCPIPFeatureBitMap.TCPIPBypass,
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
@pytest.mark.skip("Need to get the proper error code")
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_connectivity_in_WPA2_EAP_TLS_when_no_cert_C113779(wifi_sniffer, wifi_dut, wifi_access_point, radius_server):
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
        wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, eap_method="TLS", timeout=40)
        assert exc_info.value.error_code == 0x8, "Connection should fail when no certs loaded"

    logger().info("Connection failed when no certs loaded")
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
@pytest.mark.skip("Need to get the proper error code")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_connectivity_with_WPA2_EAP_with_expired_Date_TLS_C113771(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                 radius_server):
    testcase = "test_connectivity_with_WPA2_EAP_with_expired_Date_TLS_C113771"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

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
    events = wifi_dut.interfaces.wifi.get_async_events()
    for event in events:
        logger().info(f"event {event.event_type}")

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("Connection should failed with expired certs")
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
@pytest.mark.skip("Need to get the proper error code")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_connectivity_with_WPA2_EAP_with_expired_Date_TTLS_C113772(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                 radius_server):
    testcase = "test_connectivity_with_WPA2_EAP_with_expired_Date_TTLS_C113772"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

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

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("Connection should failed with expired certs")
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
@pytest.mark.skip("Need to get the proper error code")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_connectivity_with_WPA2_EAP_with_expired_Date_PEAP_C113773(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                 radius_server):
    testcase = "test_connectivity_with_WPA2_EAP_with_expired_Date_PEAP_C113773"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

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

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("Connection should failed with expired certs")
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid,
                                                conn_status=False)
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

