from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict, logger

from utf.interfaces.wifi import WlanError
import sys
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116PowerSaveModes, \
    RS9116TCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from typing import Dict
from utf_wiseconnect.devices.rs911x import RS9116JoinFeatureBitMap

"""This function runs below test steps for DUT-RS9116
        1. Configuration of DUT in 2G : BGN
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        6. Enable the power save mode in DUT
        7. Stop the sniffer  
        8. Analyzing all sniffer capture packets for WPA3 Security

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)

    Author: Benazeer K
"""


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)

ping_count = 10


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower |RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_scan_c34503_04_05_07(wifi_sniffer, wifi_dut, wifi_access_point):
    logger().info(f"********this test_case to validate DNS_SERVER WITH DHCP********")
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_scan_c34503_04_05_07')
    time.sleep(2)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger().info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
            scan_fail = 0
            break
        except:
            logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger().info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"

    time.sleep(2)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger().info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None, channel=11)
            scan_fail = 0
            break
        except:
            logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger().info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"

    time.sleep(2)

    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger().info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid='Azeez123', channel=11)
            scan_fail = 0
            break
        except:
            logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger().info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)
    time.sleep(1)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                     f'and wlan.sa == {dut_mac_address} and wlan.fc.type_subtype == 0x0004 ' \
                     f'and wlan.da == ff:ff:ff:ff:ff:ff'

    packet_filter3 = f'(wlan.fixed.sae_message_type == 1) || (wlan.fixed.sae_message_type == 2)' \
                     f' && wlan.addr == {dut_mac_address}'

    packet_filter4 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    time.sleep(2)
    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()
    logger().info("Sniffer Validation for Probe request packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    logger().info("Sniffer Validation for Authentication packets of COMMIT & CONFIRM")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']
    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count']

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower |RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_tcp_data_tx_with_wpa3_c34512(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                            protocol):

    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_tcp_data_tx_with_wpa3_c34512')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1,"fail to ping host"
    logger().info("ping successful to host")

    time.sleep(2)
    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(5)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF TX, TCP traffic for all Qos services ********************\n\n')

    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    logger().info(f"***** starting iperf ******")
    net_perf_client.interfaces.net_perf.start()

    logger().info(f"***** open socket and send traffic  ******")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info(f"***** get and print throughput ******")
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)
    time.sleep(5)

    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']



@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower |RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_udp_data_tx_with_wpa3_c34514(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                            protocol):

    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_udp_data_tx_with_wpa3_c34514')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1,"fail to ping host"
    logger().info("ping successful to host")

    time.sleep(2)
    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(5)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF TX, TCP traffic for all Qos services ********************\n\n')

    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    logger().info(f"***** starting iperf ******")
    net_perf_client.interfaces.net_perf.start()

    logger().info(f"***** open socket and send traffic  ******")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info(f"***** get and print throughput ******")
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)
    time.sleep(5)

    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower |RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_tcp_data_rx_with_wpa3_c34513(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                            protocol):

    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_tcp_data_rx_with_wpa3_c34513')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1,"fail to ping host"
    logger().info("ping successful to host")

    time.sleep(2)
    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(5)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF RX ********************\n\n')

    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    logger().info(f"***** open socket and start listening ******")
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        logger().info(f"***** start iperf  ******")
        net_perf_client.interfaces.net_perf.start()

        logger().info(f"***** capture device output  ******")
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

    logger().info(f"***** get and print throughput   ******")
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    time.sleep(5)
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)
    time.sleep(5)

    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower |RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_udp_data_rx_with_wpa3_c34515(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                            protocol):

    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_udp_data_rx_with_wpa3_c34515')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1,"fail to ping host"
    logger().info("ping successful to host")

    time.sleep(2)
    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(5)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF RX ********************\n\n')

    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    logger().info(f"***** open socket and start listening ******")
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        logger().info(f"***** start iperf  ******")
        net_perf_client.interfaces.net_perf.start()

        logger().info(f"***** capture device output  ******")
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

    logger().info(f"***** get and print throughput   ******")
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)
    time.sleep(5)

    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower |RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,
        "band": 2,
    }
)
def test_tcp_data_tx_with_wpa3_5g_c34516(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                            protocol):

    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_tcp_data_tx_with_wpa3_5g_c34516')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1,"fail to ping host"
    logger().info("ping successful to host")

    time.sleep(2)
    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(5)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF TX, TCP traffic for all Qos services ********************\n\n')

    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    logger().info(f"***** starting iperf ******")
    net_perf_client.interfaces.net_perf.start()

    logger().info(f"***** open socket and send traffic  ******")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info(f"***** get and print throughput ******")
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)
    time.sleep(5)

    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']



@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower |RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,
        "band": 2,
    }
)
def test_udp_data_tx_with_wpa3_5g_c34518(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                            protocol):

    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_udp_data_tx_with_wpa3_5g_c34518')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1,"fail to ping host"
    logger().info("ping successful to host")

    time.sleep(2)
    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(5)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF TX, TCP traffic for all Qos services ********************\n\n')

    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    logger().info(f"***** starting iperf ******")
    net_perf_client.interfaces.net_perf.start()

    logger().info(f"***** open socket and send traffic  ******")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info(f"***** get and print throughput ******")
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)
    time.sleep(5)

    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower |RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,
        "band": 2,
    }
)
def test_tcp_data_rx_with_wpa3_5g_c34517(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                            protocol):

    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_tcp_data_rx_with_wpa3_5g_c34517')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1,"fail to ping host"
    logger().info("ping successful to host")

    time.sleep(2)
    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(5)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF RX ********************\n\n')

    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    logger().info(f"***** open socket and start listening ******")
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        logger().info(f"***** start iperf  ******")
        net_perf_client.interfaces.net_perf.start()

        logger().info(f"***** capture device output  ******")
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

    logger().info(f"***** get and print throughput   ******")
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    time.sleep(5)
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)
    time.sleep(5)

    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower |RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,
        "band": 2,

    }
)
def test_udp_data_rx_with_wpa3_5g_c34519(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                            protocol):

    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_udp_data_rx_with_wpa3_5g_c34519')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1,"fail to ping host"
    logger().info("ping successful to host")
    time.sleep(2)
    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(5)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF RX ********************\n\n')

    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    logger().info(f"***** open socket and start listening ******")
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        logger().info(f"***** start iperf  ******")
        net_perf_client.interfaces.net_perf.start()

        logger().info(f"***** capture device output  ******")
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

    logger().info(f"***** get and print throughput   ******")
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)
    time.sleep(5)

    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']
