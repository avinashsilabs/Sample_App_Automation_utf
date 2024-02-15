import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xPowerSaveModes, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.sl_status import SLStatus
import time

def logger():
    return get_logger(__name__)


"""
setup requirement:
        1. DUT(SiWG917) - 1
        2. Si-MB4002A -1
        3. Raspberry PI4 - 1
        4. Access Point(Third Party AP's) - 1
        5. NUC

    Author: Shaik Abdul Azeez
"""

def delta_between_sntp_packet():
    packet_filter = "Time delta from previous captured frame"
    count = 0
    time_diff_list = []

    filter_file = open(f'./reports/filter2_file.txt', 'r')
    line = filter_file.readlines()
    count1 = 0
    for x in line:
        count = count + 1
        if packet_filter in x:
            count1 += 1
            time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                'seconds', '')
            logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')

            if round(float(time_delta_from_previous_packet)) == 0:
                count1 -= 1
                continue
            else:
                time_diff_list.append(float(time_delta_from_previous_packet))
    filter_file.close()
    return time_diff_list
    # logger().info("Calculating the threshold value for keep alive interval")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SNTPClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_sntp_unicast_C19015(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter, utf_constants,
                                      sl_collections):
    capture_filename = request.node.name
    power_save = utf_constants.get("power_save")

    logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

    dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                                   power_save=power_save,
                                                   associated=wifi_dut.interfaces.wifi.associated)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {ap_bssid}")

    wifi_dut.interfaces.wifi.sntp_client_start()

    time, date = wifi_dut.interfaces.wifi.sntp_get_time_data()

    logger().info(f'*** Time is {time} ***')
    logger().info(f'*** Date is {date} ***')

    wifi_dut.interfaces.wifi.sntp_client_stop()

    wifi_sniffer.interfaces.capture.stop_capture()
    packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_addr['dut_mac_address'],
                                                                                    filter_name="ntp_packet")
    packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_addr['dut_mac_address'],
                                                                                    da_addr=ap_bssid,
                                                                                    filter_name="power_mgmt_bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
        'Unable to find ntp sniffer packets'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find the power save sniffer packets'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SNTPClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"channel": 1, "security": 'OPEN'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_sntp_keepalive_C19016(wifi_sniffer, wifi_dut, wifi_access_point, request, utf_constants, sniffer_filter, sl_collections):

    capture_filename = request.node.name
    time_delta = 30
    packet_filter2 = '    Flags: 0x1b, Leap Indicator: no warning, Version number: NTP Version 3, Mode: client'
    power_save = utf_constants.get("power_save")
    logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

    dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                                   power_save=power_save,
                                                   associated=wifi_dut.interfaces.wifi.associated)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {ap_bssid}")

    wifi_dut.interfaces.wifi.sntp_client_start()
    ip_version, sntp_method, sntp_server_address = wifi_dut.interfaces.wifi.sntp_get_server_info()
    logger().info(f'\n\n SNTP server address = {ip_version}, \n {sntp_method},\n {sntp_server_address}\n\n')

    times, date = wifi_dut.interfaces.wifi.sntp_get_time_data()
    logger().info(f'*** Time is {times} ***')
    logger().info(f'*** Date is {date} ***')
    time.sleep(180)

    wifi_dut.interfaces.wifi.sntp_client_stop()
    wifi_sniffer.interfaces.capture.stop_capture()

    packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_addr['dut_mac_address'],filter_name="ntp_keep_alive")

    packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_addr['dut_mac_address'],filter_name="ntp_packet")

    packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_addr['dut_mac_address'],
                                                                                    da_addr=ap_bssid,
                                                                                    filter_name="power_mgmt_bit")

    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                              packet_filter2=packet_filter2)['packet_count'], \
        'Unable to find the ntp keep alive sniffer packets'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
        'Unable to find ntp sniffer packets'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count'], \
        'Unable to find the power save sniffer packets'

    logger().info("""******** Validation of time delta between keep-alive packets ********""")
    sntp_packets_time_delta_list = delta_between_sntp_packet()
    logger().info(f'SNTP packet time delta list after removing 0 = {sntp_packets_time_delta_list}')
    for time_diff in sntp_packets_time_delta_list:
        logger().info(int(time_diff))
        is_between = int(time_diff) in range(0, time_delta + 2)
        logger().info(is_between)
    time.sleep(1)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SNTPClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_sntp_ludp_coexit_C19017(wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, remote_socket, request, sniffer_filter, utf_constants, sl_collections):

    capture_filename = request.node.name
    data = 'hello'
    power_save = utf_constants.get("power_save")

    logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

    dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                                   power_save=power_save,
                                                   associated=wifi_dut.interfaces.wifi.associated)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {ap_bssid}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Host IP is: {host_ip}")

    socket_id  = wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
    wifi_dut.interfaces.wifi.bind(socket_fd=socket_id, device_ip=dut_addr['device_ip'], ip_len=4, server_port=123)
    wifi_dut.interfaces.wifi.bsdSocketSendTo(socket_fd=socket_id, data=data, ip_addr= host_ip, ip_len=4, port=123)
    wifi_dut.interfaces.wifi.sntp_client_start(expected_status=SLStatus.SL_STATUS_SI91X_PORT_UNAVAILABLE)
    time.sleep(2)
    wifi_dut.interfaces.wifi.leave()
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()
    packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_addr['dut_mac_address'],
                                                                                    da_addr=ap_bssid,
                                                                                    filter_name="power_mgmt_bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find the power save sniffer packets'
