import re
import time
from datetime import datetime, timedelta

import pytest as pytest
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from interfaces.wifi import WlanError, SecurityMode
from utils.logger import get_logger
from devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes
from devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap,
)


def logger():
    return get_logger(__name__)


"""Author : Vivek"""

"""This function runs below test steps for DUT-RS9116 for Rejoin test case verification
        1. Configuration of DUT in 2G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new TCP/IP socket 
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number and send data.
        7. Disable the AP radio and check unicast Probe request packet in sniffer after some time it should start 
           broadcast probe request packet
        8. verify rejoin & probe request packet with different security, different channels, and for different region(US/UK/Japan) 
        9. Note: TC - 19724 is duplicate, TC-19726/27/28 current UTF implementation doesn't support.
           TC-19730/31/32 are depend on TLS/TTLS/PEAP
        

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)
"""


class FilterPacket:
    def delta_between_probe_packet(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()

        for x in line:
            count = count + 1
            if packet_filter in x:
                # logger().info(f'Line= {line[count]}')
                time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                    'seconds', '')
                logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')
                time_diff.append(float(time_delta_from_previous_packet))

        logger().info(time_diff)
        filter_file.close()
        return time_diff


class IopTcpIpSockets:
    def open_socket(self, wifi_networked_dut) -> int:
        if isinstance(wifi_networked_dut.interfaces.wifi, RSSAPICommands):
            result = wifi_networked_dut.interfaces.wifi.start_ip()
            dut_ip = result.ip.decode()
            logger().info(f"DUT ip address : {dut_ip}")
            assert isinstance(result, wifi_networked_dut.interfaces.wifi.IPConfig)

            tcp_socket_id = wifi_networked_dut.interfaces.wifi.open_tcp_client_socket()
            if isinstance(tcp_socket_id, int):
                logger().info(f"Socket open successfully : {tcp_socket_id}")
            else:
                logger().error(f"Unable to open socket id: {tcp_socket_id}")
                raise RuntimeError(tcp_socket_id)

            time.sleep(2)
            bind_response = wifi_networked_dut.interfaces.wifi.bind(tcp_socket_id, dut_ip)
            if bind_response.decode().split(">")[1].replace("'", '').strip() == 'success':
                logger().info(f"Bind socket successfully: {bind_response}")
            else:
                logger().error(f"Unable to bind socket: {bind_response}")
                raise RuntimeError(bind_response)
        return tcp_socket_id

    def connect_socket(self, wifi_networked_dut, tcp_socket_id: int):
        retry_limit: int = 2
        connect_status = False
        for retry in range(1, retry_limit):
            connect_response = wifi_networked_dut.interfaces.wifi.connect(tcp_socket_id)
            logger().info(f"Connect response : {connect_response}")
            if connect_response.decode() == '':
                logger().info(f"Unable to connect socket: {connect_response} in {retry} try")
                if retry < retry_limit:
                    pass
            elif connect_response.decode().split(">")[1].strip() == 'success':
                logger().info(f"Socket connected successfully in {retry} try")
                connect_status = True
                break
            logger().info(f"Socket connected with server in: {retry + 1} time")
        return connect_status


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
    },
)
def test_rejoin_C19721(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

    time.sleep(2)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # wifi_dut.interfaces.wifi.start_ip()

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.fc.type_subtype == 0x0004 and !(wlan.da == ff:ff:ff:ff:ff:ff)'
    packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype == ' \
                     f'0x0004 and wlan.da == ff:ff:ff:ff:ff:ff'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_unicast_prob_req')
    time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']
    time.sleep(120)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_broadcast_prob_req')
    time.sleep(5)
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(60)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    time.sleep(5)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
        'packet_count']


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost
    },
)
def test_rejoin_max_retry_failure_C19722(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    time.sleep(2)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=4, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # wifi_dut.interfaces.wifi.start_ip()

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.fc.type_subtype == 0x0004 and !(wlan.da == ff:ff:ff:ff:ff:ff)'
    packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype == ' \
                     f'0x0004 and wlan.da == ff:ff:ff:ff:ff:ff '

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_unicast_prob_req')
    time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']
    time.sleep(150)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_broadcast_prob_req')
    time.sleep(5)
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(60)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    time.sleep(5)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
        'packet_count']


@pytest.mark.parametrize(
    "channel_list",
    [1, 6, 11],
)
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
    },
)
def test_rejoin_scan_channels_C19723(wifi_sniffer, wifi_access_point, wifi_dut, channel_list):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_access_point.interfaces.wifi.start_ap(channel=channel_list)
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list)
    time.sleep(2)

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel_list)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # wifi_dut.interfaces.wifi.start_ip()

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff and wlan.sa == {mac_address}'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_scan_channel')
    time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(30)
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']


@pytest.mark.parametrize(
    "channel_list",
    [1, 6, 11],
)
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
    },
)
def test_rejoin_scan_other_channel_C19725(wifi_sniffer, wifi_access_point, wifi_dut, channel_list):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False

    time.sleep(2)
    wifi_access_point.interfaces.wifi.start_ap(channel=channel_list)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    wifi_dut.interfaces.wifi.scan_selective_channel(channel=channel_list, ssid=None,
                                                    scan_bitmap_2_4=0, scan_bitmap_5=0,
                                                    scan_feature=0)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # wifi_dut.interfaces.wifi.start_ip()

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan.fc.type_subtype == 0x0004 '

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")

    # time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(5)
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_scan_other_channel')
    time.sleep(60)
    wifi_sniffer.interfaces.capture.stop_capture()
    # Validate Broadcast Probe request packet
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']

    # Looking Probe request packet except current using channel and device should not broadcast any Probe req packet
    # any other channels
    cha_list = [1, 6, 11]
    if channel_list in cha_list:
        cha_list.remove(channel_list)
        logger().info(f'Channel list = {cha_list}')
    wifi_sniffer.interfaces.capture.configure_interface(channel=cha_list[0])
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_scan_other_channel')
    time.sleep(30)
    wifi_sniffer.interfaces.capture.stop_capture()
    result = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']
    if result is True:
        assert False


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost
    },
)
def test_rejoin_max_retry_failure_with_security_mode_change_C19729(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    time.sleep(2)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=4, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # wifi_dut.interfaces.wifi.start_ip()

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.ssid == ' \
                     f'{wifi_access_point.interfaces.wifi.ssid} and wlan.fc.type_subtype == 0x0004'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_max_retry_failure')
    end_time = datetime.now() + timedelta(minutes=1)

    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(20)
    wifi_access_point.interfaces.wifi.start_ap(security=SecurityMode.Open)
    time.sleep(20)

    """validate rejoin retry failure"""
    while datetime.now() < end_time:
        events = wifi_dut.interfaces.wifi.get_async_events()
        rejoin_error_events = [event for event in events if
                               event.event_type == RS9116AsyncEventType.RejoinError]
        if len(rejoin_error_events):
            logger().info(f'RE-JOIN ERROR = {rejoin_error_events}')
            break

    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
    },
)
def test_rejoin_eap_tls_C19730(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    ap_user_name = "\\\"user1\\\""
    ap_password = "\\\"12345678\\\""
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    time.sleep(2)
    wifi_dut.interfaces.wifi.eap_method(eap_method="TLS", eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")
    time.sleep(20)
    wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
    time.sleep(20)
    # Get IP through DHCP
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.fc.type_subtype == 0x0004 and !(wlan.da == ff:ff:ff:ff:ff:ff)'
    packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype == ' \
                     f'0x0004 and wlan.da == ff:ff:ff:ff:ff:ff '

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_unicast_prob_req')
    time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']
    time.sleep(120)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_broadcast_prob_req')
    time.sleep(5)
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(60)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    time.sleep(5)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
        'packet_count']


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
    },
)
def test_rejoin_eap_ttls_C19731(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    ap_user_name = "\\\"user1\\\""
    ap_password = "\\\"12345678\\\""
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    time.sleep(2)
    wifi_dut.interfaces.wifi.eap_method(eap_method="TTLS", eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")
    time.sleep(20)
    wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
    time.sleep(20)
    # Get IP through DHCP
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.fc.type_subtype == 0x0004 and !(wlan.da == ff:ff:ff:ff:ff:ff)'
    packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype == ' \
                     f'0x0004 and wlan.da == ff:ff:ff:ff:ff:ff '

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_unicast_prob_req')
    time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']
    time.sleep(120)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_broadcast_prob_req')
    time.sleep(5)
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(60)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    time.sleep(5)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
        'packet_count']


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
    },
)
def test_rejoin_eap_peap_C19732(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    ap_user_name = "\\\"user1\\\""
    ap_password = "\\\"12345678\\\""
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    time.sleep(2)
    wifi_dut.interfaces.wifi.eap_method(eap_method="PEAP", eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")
    time.sleep(20)
    wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
    time.sleep(20)
    # Get IP through DHCP
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.fc.type_subtype == 0x0004 and !(wlan.da == ff:ff:ff:ff:ff:ff)'
    packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype == ' \
                     f'0x0004 and wlan.da == ff:ff:ff:ff:ff:ff '

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_unicast_prob_req')
    time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']
    time.sleep(120)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_broadcast_prob_req')
    time.sleep(5)
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(60)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    time.sleep(5)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
        'packet_count']


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
    },
)
def test_rejoin_disable_C19733(wifi_sniffer, wifi_access_point, wifi_dut):
    # Verify default number of retries in rejoin procedure, expecting 19 broadcast packet after disable the AP radio
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    rejoin_max_value = 20
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max_value, scan_interval=6, beacon_missedcount=40,
                                    first_time_retry=0)
    time.sleep(2)
    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Max PSP in DUT******")

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Actual MAC_Address: {mac_address}")
    packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {mac_address} and wlan.da == ff:ff:ff:ff:ff:ff'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture()
    time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(170)
    wifi_sniffer.interfaces.capture.stop_capture()
    result = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'find_packet_num']
    if (int(result) + 1) == rejoin_max_value:
        logger().info(f"Default broadcast probe request packet count = {rejoin_max_value} is equal to one less "
                      f"sniffer packet "
                      f"count = {result}")
        assert True
    else:
        logger().info(f"Default broadcast probe request packet count = {rejoin_max_value} is not equal to one less "
                      f"sniffer "
                      f"packet "
                      f"count = {result}")
        assert False


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost
    },
)
def test_rejoin_psk_change_C19734(wifi_sniffer, wifi_access_point, wifi_dut):
    # Verify rejoin procedure when connected AP, PSK got changed
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    time.sleep(2)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=4, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # wifi_dut.interfaces.wifi.start_ip()

    logger().info(f"*****Enable Max PSP in DUT******")

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.ssid == ' \
                     f'{wifi_access_point.interfaces.wifi.ssid} and wlan.fc.type_subtype == 0x0004'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_psk_change')
    end_time = datetime.now() + timedelta(minutes=1)

    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(20)
    wifi_access_point.interfaces.wifi.start_ap(passphrase="87654321")
    time.sleep(20)

    """validate rejoin retry failure"""
    while datetime.now() < end_time:
        events = wifi_dut.interfaces.wifi.get_async_events()
        rejoin_error_events = [event for event in events if
                               event.event_type == RS9116AsyncEventType.RejoinError]
        if len(rejoin_error_events):
            logger().info(f'RE-JOIN ERROR = {rejoin_error_events}')
            break
        else:
            logger().info(f'RE-JOIN ERROR not observed')
            assert False
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
    },
)
def test_rejoin_with_disconnect_C19735(wifi_sniffer, wifi_access_point, wifi_dut):
    # Issue Disconnect command when module does not find AP in rejoin procedure when first time retry enable bit and
    # number of retries to infinite
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    time.sleep(2)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Max PSP in DUT******")

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Actual MAC_Address: {mac_address}")
    packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {mac_address} and wlan.da == ff:ff:ff:ff:ff:ff'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(test_rejoin_with_disconnect)
    time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(120)
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']
    wifi_dut.interfaces.wifi.leave()
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(20)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.config('wifi_access_point', wifi={"ssid": "testingpmk", "passphrase": '12345678', "security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
    },
)
def test_rejoin_beacon_miss_counter_C19736(wifi_sniffer, wifi_access_point, wifi_dut):
    # We need to validate time delta between Beacon & Unicast probe request packet as per current implementation
    # manually open the sniffer log and check the time delta between them.
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    time.sleep(2)
    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Max PSP in DUT******")

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Actual MAC_Address: {mac_address}")
    # packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {mac_address} and wlan.da == ff:ff:ff:ff:ff:ff'
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'
    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture()
    time.sleep(1)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(10)
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)
    ['packet_count']


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost
    },
)
def test_rejoin_scan_interval_1sec_C19737(wifi_sniffer, wifi_access_point, wifi_dut):
    # Set scan interval to 1 sec in rejoin params command Verify scan interval time in rejoin process
    tcp_socket_obj = IopTcpIpSockets()
    scan_interval = 1
    send_bytes = 1000
    validation = True
    packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'
    time_delta = 1
    status = False
    probe_time_delta_obj = FilterPacket()
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    time.sleep(2)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=4, scan_interval=scan_interval, beacon_missedcount=40,
                                    first_time_retry=0)
    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Max PSP in DUT******")

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.sa == {mac_address} ' \
                     f'and wlan.ssid == ' \
                     f'{wifi_access_point.interfaces.wifi.ssid} and wlan.fc.type_subtype == 0x0004 and ' \
                     f'wlan.da == ff:ff:ff:ff:ff:ff'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_scan_interval_1sec')
    end_time = datetime.now() + timedelta(minutes=1)

    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(120)

    """validate rejoin retry failure"""
    while datetime.now() < end_time:
        events = wifi_dut.interfaces.wifi.get_async_events()
        rejoin_error_events = [event for event in events if
                               event.event_type == RS9116AsyncEventType.RejoinError]
        if len(rejoin_error_events):
            logger().info(f'RE-JOIN ERROR = {rejoin_error_events}')
            break
        else:
            logger().info(f'RE-JOIN ERROR not observed')
            assert False
    wifi_sniffer.interfaces.capture.stop_capture()
    result = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']
    probe_packets_time_delta_list = probe_time_delta_obj.delta_between_probe_packet()
    logger().info(f'Probe packet time delta list= {probe_packets_time_delta_list}')

    probe_packets_time_delta_list.pop(0)
    logger().info(f'Probe packet time delta list after removing 0 = {probe_packets_time_delta_list}')
    for time_diff in probe_packets_time_delta_list:
        logger().info(int(time_diff))
        is_between = int(time_diff) in range(time_delta, time_delta + 1)
        if is_between is False:
            logger().info(is_between)
            status = is_between
            break
        else:
            logger().info(is_between)
            status = is_between
    if result and status is True:
        logger().info(f'Expected scan interval {scan_interval}sec found between Probe request packets')
        assert True
    else:
        logger().info(f'Expected scan interval {scan_interval}sec not found between Probe request packets')
        assert False


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost
    },
)
def test_rejoin_infinite_retry_C19738(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    time.sleep(2)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # wifi_dut.interfaces.wifi.start_ip()

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.ssid == ' \
                     f'{wifi_access_point.interfaces.wifi.ssid} and wlan.fc.type_subtype == 0x0004 and ' \
                     f'wlan.da == ff:ff:ff:ff:ff:ff'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_max_retry_failure')
    end_time = datetime.now() + timedelta(minutes=1)

    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(20)
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(20)

    """validate rejoin retry failure"""
    while datetime.now() < end_time:
        events = wifi_dut.interfaces.wifi.get_async_events()
        rejoin_error_events = [event for event in events if
                               event.event_type == RS9116AsyncEventType.RejoinError]
        if len(rejoin_error_events):
            logger().info(f'RE-JOIN ERROR = {rejoin_error_events}')
            break
        else:
            logger().info(f'Unable to find RE-JOIN ERROR')

    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
    },
)
def test_rejoin_with_bgscan_C19739(wifi_sniffer, wifi_access_point, wifi_dut):
    # Re-join with infinite retry when bgscan enable
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

    time.sleep(2)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Max PSP in DUT******")

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.fc.type_subtype == 0x0004 and !(wlan.da == ff:ff:ff:ff:ff:ff)'
    packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype == ' \
                     f'0x0004 and wlan.da == ff:ff:ff:ff:ff:ff '

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_with_bgscan')
    time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)
    wifi_access_point.interfaces.wifi.start_ap()
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_with_bgscan')
    time.sleep(60)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    time.sleep(5)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
        'packet_count']


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
    },
)
def test_rejoin_first_time_retry_C19740(wifi_sniffer, wifi_access_point, wifi_dut):
    # Verify first time retry functionality when AP sends de-auth frame while connecting
    validation = True
    packet_filter2 = False
    rejoin_retry_value = 4
    """Verify whether module is sending unicast probe request after 200 beacons miss count(i.e 20sec)"""
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_retry_value, scan_interval=6, beacon_missedcount=200,
                                    first_time_retry=1)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_first_time_retry')
    time.sleep(2)
    wifi_dut.interfaces.wifi.scan(ssid=None)
    with pytest.raises(WlanError) as exc_info:
        # This API trying connects STA to the third party AP with wrong psk
        wifi_dut.interfaces.wifi.join(passphrase="12345679", timeout=150)
        assert exc_info.value.error_code == 0x0008
    time.sleep(30)
    wifi_sniffer.interfaces.capture.stop_capture()

    # to capture all sniffer packet for validation purpose
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'
    # Try to validate M2 packets 4 times (becz rejoin_max=4), after first de-authentication packet.
    packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and radiotap.timestamp.ts >= ' \
                     f'12256739 and wlan_rsna_eapol.keydes.msgnr == 2'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)

    result = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
        'find_packet_num']
    import pdb
    pdb.set_trace()
    logger().info("Verify whether module is trying for given number of times after receiving de-auth frame")
    if int(result) == rejoin_retry_value:
        logger().info(f'Rejoin retry value = {rejoin_retry_value} is equal to No of M2 packet count = {result}')
        assert True
    else:
        logger().info(f'Rejoin retry value = {rejoin_retry_value} is not equal to No of M2 packet count = {result}')
        assert False


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost
    },
)
def test_rejoin_hidden_ssid_C19741(wifi_sniffer, wifi_access_point, wifi_dut):
    # Rejoin functionality with hidden mode AP
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_access_point.interfaces.wifi.config['broadcast_ssid'] = False
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(20)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

    time.sleep(2)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # wifi_dut.interfaces.wifi.start_ip()

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.fc.type_subtype == 0x0004 and !(wlan.da == ff:ff:ff:ff:ff:ff)'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_hidden_ssid')
    time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()
    end_time = datetime.now() + timedelta(minutes=1)
    time.sleep(120)
    """validate rejoin retry failure"""
    while datetime.now() < end_time:
        events = wifi_dut.interfaces.wifi.get_async_events()
        rejoin_error_events = [event for event in events if
                               event.event_type == RS9116AsyncEventType.RejoinError]
        if len(rejoin_error_events):
            logger().info(f'RE-JOIN ERROR = {rejoin_error_events}')
            break
        else:
            logger().info(f'RE-JOIN ERROR not observed')
            assert False
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']


@pytest.mark.skip
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost
    },
)
def test_rejoin_in_US_region_C19742(wifi_sniffer, wifi_access_point, wifi_dut):
    # Verify Rejoin Functionality with US region enabled in 2.4GHZ band
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    # Set the region value in AP side
    wifi_access_point.interfaces.wifi.config['region'] = 'US'
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(20)
    # Set the region value in DUT side
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=1, module_type=1)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # wifi_dut.interfaces.wifi.start_ip()

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.fc.type_subtype == 0x0004 and !(wlan.da == ff:ff:ff:ff:ff:ff)'
    packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype == ' \
                     f'0x0004 and wlan.da == ff:ff:ff:ff:ff:ff '

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_in_US_region')
    time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)
    wifi_access_point.interfaces.wifi.start_ap()
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_in_US_region')
    time.sleep(60)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    time.sleep(5)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
        'packet_count']


@pytest.mark.skip
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost
    },
)
def test_rejoin_in_UK_region_C19743(wifi_sniffer, wifi_access_point, wifi_dut):
    # Verify Rejoin Functionality with EU region enabled in 2.4GHZ band
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    # Set the region value in AP side
    wifi_access_point.interfaces.wifi.config['region'] = 'Europe'
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(20)
    # Set the region value in AP side
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=2, module_type=1)
    time.sleep(2)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # wifi_dut.interfaces.wifi.start_ip()

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.fc.type_subtype == 0x0004 and !(wlan.da == ff:ff:ff:ff:ff:ff)'
    packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype == ' \
                     f'0x0004 and wlan.da == ff:ff:ff:ff:ff:ff '

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_in_UK_region')
    time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)
    wifi_access_point.interfaces.wifi.start_ap()
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_in_UK_region')
    time.sleep(60)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    time.sleep(5)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
        'packet_count']


@pytest.mark.skip
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost
    },
)
def test_rejoin_in_japan_region_C19744(wifi_sniffer, wifi_access_point, wifi_dut):
    # Verify Rejoin Functionality with JP region enabled in 2.4GHZ band,
    # Please Note - ASUS AP doesn't have Japan region configure manually and execute

    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=3, module_type=1)
    time.sleep(2)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

    time.sleep(2)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Max PSP in DUT******")

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.fc.type_subtype == 0x0004 and !(wlan.da == ff:ff:ff:ff:ff:ff)'
    packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype == ' \
                     f'0x0004 and wlan.da == ff:ff:ff:ff:ff:ff '

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_in_japan_region')
    time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)
    wifi_access_point.interfaces.wifi.start_ap()
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_in_japan_region')
    time.sleep(60)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    time.sleep(5)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
        'packet_count']


@pytest.mark.skip
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost
    },
)
def test_rejoin_in_worldwide_region_C19745(wifi_sniffer, wifi_access_point, wifi_dut):
    # Verify Rejoin Functionality with world mode region enabled in 2.4GHZ band
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_access_point.interfaces.wifi.config['region'] = 'Asia'
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(20)
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=4, module_type=1)
    time.sleep(2)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

    time.sleep(2)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # wifi_dut.interfaces.wifi.start_ip()

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.fc.type_subtype == 0x0004 and !(wlan.da == ff:ff:ff:ff:ff:ff)'
    packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype == ' \
                     f'0x0004 and wlan.da == ff:ff:ff:ff:ff:ff '

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_in_worldwide_region')
    time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)
    wifi_access_point.interfaces.wifi.start_ap()
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_in_worldwide_region')
    time.sleep(60)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    time.sleep(5)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
        'packet_count']
