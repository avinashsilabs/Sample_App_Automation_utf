import re
import time

import pytest as pytest
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from interfaces.wifi import WlanError
from utils.logger import get_logger
from devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes, RS9116ExtCustomFeatureBitMap, IEEE802_11W
from devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap,
)


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9116 to verify 802.11w functionality 
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's(ASUS RT AX3000)
        3. Get the valid IP address
        4. Enable Background scan
        4. Create a new TCP/IP socket
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.
        7. Validate PMF capable/Required bit in Association Req RSN information, Protected flag:Data is protected in 
           Data/Control frame via sniffer.

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)
"""


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
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.Default
    },
)
def test_mgmt_pmf_capable_connection(wifi_sniffer, wifi_access_point, wifi_dut):
    """ Verify the Connection between AP(PMF capable) and DUT(PMF capable)"""
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_mgmt_pmf_capable_connection')
    time.sleep(2)
    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join(join_feature_bitmap=IEEE802_11W.Protection_capable)
    wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Max PSP in DUT******")

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    # Packet filter for Association req, with mgmt frame with protection capable
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype ' \
                     f'== 0x0000 and wlan.rsn.capabilities.mfpc == 1 and wlan.ta == {dut_mac_address}'

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
    time.sleep(2)
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    time.sleep(20)
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
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.Default
    },
)
def test_mgmt_pmf_required_connection(wifi_sniffer, wifi_access_point, wifi_dut):
    """ Verify the Connection between AP(PMF required) and DUT(PMF required)"""
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
    wifi_access_point.interfaces.wifi.start_ap()
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_mgmt_pmf_required_connection')
    time.sleep(2)
    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join(join_feature_bitmap=IEEE802_11W.Protection_Required)
    wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Max PSP in DUT******")

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    # Packet filter for Association req, with mgmt frame with protection capable
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype ' \
                     f'== 0x0000 and wlan.rsn.capabilities.mfpr == 1 and wlan.ta == {dut_mac_address}'

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
    time.sleep(2)
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    time.sleep(20)
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
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.Default
    },
)
def test_mgmt_pmf_required_connection_fail(wifi_access_point, wifi_dut):
    """ Verify the Connection between AP(PMF required) and DUT(PMF disable)"""
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    time.sleep(2)
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
    wifi_access_point.interfaces.wifi.start_ap()
    wifi_dut.interfaces.wifi.scan(ssid=None)
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.join()
    assert exc_info.value.error_code == 0x9


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.Default
    },
)
def test_mgmt_pmfrequiredAP_pmfcapableDUT_connection(wifi_sniffer, wifi_access_point, wifi_dut):
    """ Verify the Connection between AP(PMF required) and DUT(PMF capable)"""
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
    wifi_access_point.interfaces.wifi.start_ap()
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_mgmt_pmfrequiredAP_pmfcapableDUT_connection')
    time.sleep(2)
    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join(join_feature_bitmap=IEEE802_11W.Protection_capable)
    wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Max PSP in DUT******")

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    # Packet filter for Association req, with mgmt frame with protection capable
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype ' \
                     f'== 0x0000 and wlan.rsn.capabilities.mfpc == 1 and wlan.ta == {dut_mac_address}'

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
    time.sleep(2)
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    time.sleep(20)
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
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.Default
    },
)
def test_mgmt_pmfrequiredAP_pmfreqireandcapableDUT_connection(wifi_sniffer, wifi_access_point, wifi_dut):
    """ Verify the Connection between AP(PMF required) and DUT(PMF capable+required)"""
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
    wifi_access_point.interfaces.wifi.start_ap()
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_mgmt_pmfrequiredAP_pmfreqireandcapable')
    time.sleep(2)
    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join(join_feature_bitmap=IEEE802_11W.Protection_capable | IEEE802_11W.Protection_Required)
    wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Max PSP in DUT******")

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    # Packet filter for Association req, with mgmt frame with protection capable+required
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype ' \
                     f'== 0x0000 and wlan.rsn.capabilities.mfpc == 1 and wlan.rsn.capabilities.mfpr == 1 ' \
                     f'and wlan.ta == {dut_mac_address}'

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
    time.sleep(2)
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    time.sleep(20)
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
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.Default
    },
)
def test_mgmt_pmfcapableAP_pmfreqireandcapableDUT_connection(wifi_sniffer, wifi_access_point, wifi_dut):
    """ Verify the Connection between AP(PMF capable) and DUT(PMF capable+required)"""
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_mgmt_pmfreqireandcapable')
    time.sleep(2)
    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join(join_feature_bitmap=IEEE802_11W.Protection_capable | IEEE802_11W.Protection_Required)
    wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Max PSP in DUT******")

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    # Packet filter for Association req, with mgmt frame with protection capable+required
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype ' \
                     f'== 0x0000 and wlan.rsn.capabilities.mfpc == 1 and wlan.rsn.capabilities.mfpr == 1 ' \
                     f'and wlan.ta == {dut_mac_address}'

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
    time.sleep(2)
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    time.sleep(20)
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
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.Default
    },
)
def test_mgmt_unicast_frame_protection_bit(wifi_sniffer, wifi_access_point, wifi_dut):
    '''Verify that after association only unicast mgmt packet transmission with protection bit enable '''
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_mgmt_unicast_frame_protection_bit')
    time.sleep(2)
    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join(join_feature_bitmap=IEEE802_11W.Protection_capable | IEEE802_11W.Protection_Required)
    wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Max PSP in DUT******")

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    # Packet filter for Association req, with protection capable & required bit enable
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype ' \
                     f'== 0x0000 and wlan.rsn.capabilities.mfpc == 1 and wlan.rsn.capabilities.mfpr == 1 ' \
                     f'and wlan.ta == {dut_mac_address}'
    # Packet filter for mgmt action frame with protection bit enable and packet should only be unicast
    packet_filter3 = f'wlan.fc.protected == 1 and wlan.fc.type_subtype == 0x000d and !(wlan.fixed.action_code == 0x00) ' \
                     f'and (wlan.ta == {dut_mac_address})'

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
    time.sleep(60)
    wifi_sniffer.interfaces.capture.stop_capture()

    result1 = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']
    result2 = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
        'packet_count']
    if result1 is False or result2 is False:
        logger().info(
            f"Expected packet validation failed, Assoc req with RSN cap = {result1}, Action frame with Protection bit = {result2}")
        assert False
    else:
        logger().info(
            f"Assoc req with RSN cap = {result1}, Action frame with Protection bit = {result2}")
        logger().info("Sniffer validation Passed")
        assert True


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.Default
    },
)
def test_mgmt_action_frame_with_protection_bit_encyption(wifi_sniffer, wifi_access_point, wifi_dut):
    '''Validate encrypted mgmt action frame after association with protection bit enable'''
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_mgmt_action_frame_with_protection_bit_encyption')
    time.sleep(2)
    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join(join_feature_bitmap=IEEE802_11W.Protection_capable | IEEE802_11W.Protection_Required)
    wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Max PSP in DUT******")

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    # Packet filter to verify Association req with pmf capable & required enable bit
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype ' \
                     f'== 0x0000 and wlan.rsn.capabilities.mfpc == 1 and wlan.rsn.capabilities.mfpr == 1 ' \
                     f'and wlan.ta == {dut_mac_address}'
    # Packet filter to verify encrypted mgmt action packet after association to check protection bit on
    packet_filter3 = f'wlan.fc.protected == 1 and wlan.fc.type_subtype == 0x000d and wlan.sa == {dut_mac_address} ' \
                     f'and !(wlan.fixed.action_code == 0x00)'

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
    time.sleep(10)
    wifi_sniffer.interfaces.capture.stop_capture()
    result1 = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']
    result2 = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
        'packet_count']
    if result1 is False or result2 is False:
        logger().info(
            f"Expected packet validation failed, Assoc req with RSN cap = {result1}, Protection bit in Action frame = {result2}")
        assert False
    else:
        logger().info(
            f"Assoc req with RSN cap = {result1}, Protection bit in Action frame = {result2}")
        logger().info("Sniffer validation Passed")
        assert True


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.Default
    },
)
def test_disconnection_with_pmf(wifi_sniffer, wifi_access_point, wifi_dut):
    '''Validate disassoc mgmt frame after association with protection bit enable'''
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = False
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_disconnection_with_pmf')
    time.sleep(2)
    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join(join_feature_bitmap=IEEE802_11W.Protection_capable | IEEE802_11W.Protection_Required)
    wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Max PSP in DUT******")

    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype ' \
                     f'== 0x0000 and wlan.rsn.capabilities.mfpc == 1 and wlan.rsn.capabilities.mfpr == 1 ' \
                     f'and wlan.ta == {dut_mac_address}'
    packet_filter3 = f'(wlan.fc.type_subtype == 0x000c) and (wlan.fc.protected == 1) and wlan.ta == {dut_mac_address}'

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
    wifi_dut.interfaces.wifi.leave()
    time.sleep(30)
    wifi_sniffer.interfaces.capture.stop_capture()
    result1 = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']
    result2 = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
        'packet_count']
    if result1 is False or result2 is False:
        logger().info(
            f"Expected packet validation failed, Assoc req with RSN cap = {result1}, Protection bit in Deauth frame = {result2}")
        assert False
    else:
        logger().info(
            f"Assoc req with RSN cap = {result1}, Protection bit in Deauth frame = {result2}")
        logger().info("Sniffer validation Passed")
        assert True


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.Default
    },
)
def test_mgmt_pmf_enable_recieve_data(wifi_dut, wifi_access_point, wifi_sniffer, remote_socket):
    #
    validation = True
    packet_filter2 = False
    tcp_ip_port = 5001
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    # Start Sniffer
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_mgmt_pmf_enable_recieve_data')
    time.sleep(2)
    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join(join_feature_bitmap=IEEE802_11W.Protection_capable | IEEE802_11W.Protection_Required)
    wifi_dut.interfaces.wifi.start_ip()

    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype ' \
                     f'== 0x0000 and wlan.rsn.capabilities.mfpc == 1 and wlan.rsn.capabilities.mfpr == 1 ' \
                     f'and wlan.ta == {dut_mac_address}'
    # Open UDP socket remotely
    remote_socket.interfaces.socket.start_server(socket_type=1)
    # Open UDP socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_udp_client_socket()
    assert sock == 0, "socket id received is not matched. Expected is 0"
    # DUT binds to socket(device_ip, 5001)
    wifi_dut.interfaces.wifi.bind(socket_id=sock, device_ip=device_ip, server_port=tcp_ip_port)
    tx_buffer = "12345678901234567890123456789012345678901234567890"
    buffer_length = len(tx_buffer)
    # send 50 bytes of data from udp socket opened remotely
    remote_socket.interfaces.socket.send_data_udp(tx_buffer, device_ip, port=tcp_ip_port)
    # DUT receives data over udp socket after execution of below api
    buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=sock, data_len=buffer_length)
    # Stop sniffer and validate pmf bit in assoc request
    wifi_sniffer.interfaces.capture.stop_capture()
    output = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']
    assert output
    assert buffer_length == buffer_length_rx, "buffer length sent and received is not matched"
    assert tx_buffer.encode() == buffer_rx, "contents of data sent and receive are not matched"
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close udp socket opened in the dut"
