import re
import time

import pytest as pytest
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap,
)


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Enable Background scan
        4. Create a new TCP/IP socket
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.
        7. Expectation of this test case is to verify different parameters of Background scan functionalities. 
        8. Validate Probe response & HT information, BG scan on primary, non US & DFS channel etc. via sniffer with
           different mode/channels 

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)
        
    Author: Vivek Verma
"""


class IopTcpIpSockets:
    def open_socket(self, wifi_dut, dut_ip) -> int:
        if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
            tcp_socket_id = wifi_dut.interfaces.wifi.open_tcp_client_socket()
            if isinstance(tcp_socket_id, int):
                logger().info(f"Socket open successfully : {tcp_socket_id}")
            else:
                logger().error(f"Unable to open socket id: {tcp_socket_id}")
                raise RuntimeError(tcp_socket_id)

            time.sleep(2)
            bind_response = wifi_dut.interfaces.wifi.bind(tcp_socket_id, dut_ip)
            if bind_response.decode().split(">")[1].replace("'", '').strip() == 'success':
                logger().info(f"Bind socket successfully: {bind_response}")
            else:
                logger().error(f"Unable to bind socket: {bind_response}")
                raise RuntimeError(bind_response)
        return tcp_socket_id

    def connect_socket(self, wifi_dut, tcp_socket_id: int):
        retry_limit: int = 2
        connect_status = False
        for retry in range(1, retry_limit):
            connect_response = wifi_dut.interfaces.wifi.connect(tcp_socket_id)
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


@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default
    },
)
def test_bgscan_C19035(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True

    '''Verify RSI_STA connectivity by enabling BG scan in 2.4Ghz band'''
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bgscan_2g')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    result = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = result.ip.decode()
    logger().info(f"DUT ip address : {dut_ip}")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    # Validating probe request broadcast packet
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.sa == {dut_mac_address} and wlan.fc.type_subtype == 0x0004 ' \
                     f'and wlan.da == ff:ff:ff:ff:ff:ff'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
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
        else:
            logger().info(f"Data transfer failed")
            assert send_response
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        'Unable to find probe request broadcast packet'

    '''Again try to connect and send data as per test plan (repeat the steps from 5-10)'''
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
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
        else:
            logger().info(f"Data transfer failed")
            assert send_response
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "band": 2,
    },
)
def test_bgscan_dual_mode_C19036(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True

    '''Verify RSI_STA connectivity by enabling BG scan in Dual band'''
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bgscan_dual_mode')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    result = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = result.ip.decode()
    logger().info(f"DUT ip address : {dut_ip}")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    # Validating probe request broadcast packet
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.sa == {dut_mac_address} and wlan.fc.type_subtype == 0x0004 ' \
                     f'and wlan.da == ff:ff:ff:ff:ff:ff'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
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
        else:
            logger().info(f"Data transfer failed")
            assert send_response
    time.sleep(2)
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        'Unable to find probe request broadcast packet'

    '''Again try to connect and send data as per test plan (repeat the steps from 5-10)'''
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
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
        else:
            logger().info(f"Data transfer failed")
            assert send_response
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default
    },
)
def test_instant_bgscan_C19037(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True

    '''Verify RSI_STA connectivity by enabling instant BG scan'''
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.set_bgscan(1, 1, 10, 4, 10, 15, 20, 0)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_instant_bgscan')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    result = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = result.ip.decode()
    logger().info(f"DUT ip address : {dut_ip}")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    # Validating probe request broadcast packet
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.sa == {dut_mac_address} and wlan.fc.type_subtype == 0x0004 ' \
                     f'and wlan.da == ff:ff:ff:ff:ff:ff'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
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
        else:
            logger().info(f"Data transfer failed")
            assert send_response
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        'Unable to find probe request broadcast packet'

    '''Again try to connect and send data as per test plan (repeat the steps from 5-10)'''
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
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
        else:
            logger().info(f"Data transfer failed")
            assert send_response
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi="init")
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
def test_bgscan_rejoin_infinite_retry_C19038(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True

    '''Re-join with infinite retry when bgscan enable. Module should rejoin. If not module should attempt infinitely.
       If it successfully rejoin to AP bgscan should happen. '''
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    result = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = result.ip.decode()
    logger().info(f"DUT ip address : {dut_ip}")

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=2000, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    # Validating probe request broadcast packet
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype == ' \
                     f'0x0004 and wlan.da == ff:ff:ff:ff:ff:ff '

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
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
        else:
            logger().info(f"Data transfer failed")
            assert send_response
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bgscan_rejoin')
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(10)
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
        else:
            logger().info(f"Data transfer failed")
            assert send_response

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    wifi_dut.interfaces.wifi.leave()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        'Unable to find probe request broadcast packet'


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default
    },
)
def test_bgscan_primary_channel_2G_C19039(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    channel_bitmap_2_4 = 0
    channel_bitmap_5 = 0
    scan_feature_extend = 0

    '''configure the channels 1,6,11 in channel_bitmap field and verify whether the BG scan is happening in those 
       particular channels only or not'''
    channel_list = [1, 6, 11]
    for channel in channel_list:
        wifi_access_point.interfaces.wifi.start_ap(channel=channel)
        time.sleep(20)
        logger().info(f"Channel = {channel}")
        channel_bitmap_2_4 += 1 << (channel - 1)
        logger().info(f"channel bitmap = {channel_bitmap_2_4}")
        wifi_sniffer.interfaces.capture.configure_interface(channel)
        time.sleep(5)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bgscan_primary_channel_2g')
        wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)

        wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid,
                                                        scan_bitmap_2_4=channel_bitmap_2_4,
                                                        scan_bitmap_5=channel_bitmap_5,
                                                        scan_feature=scan_feature_extend)
        wifi_dut.interfaces.wifi.join(bgscan_flag=True)
        result = wifi_dut.interfaces.wifi.start_ip()
        dut_ip = result.ip.decode()
        logger().info(f"DUT ip address : {dut_ip}")

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info(f"*****Enable Max PSP in DUT******")
        wifi_dut.interfaces.wifi.power_save(2, 0)
        wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )

        # Validating probe request broadcast packet
        packet_filter1 = f'wlan_radio.channel == {channel} and wlan.sa == {dut_mac_address} ' \
                         f'and wlan.fc.type_subtype == 0x0004 ' \
                         f'and wlan.da == ff:ff:ff:ff:ff:ff '
        tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
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
            else:
                logger().info(f"Data transfer failed")
                assert send_response

        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
        wifi_dut.interfaces.wifi.leave()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        'Unable to find probe request broadcast packet'

# @pytest.mark.start_state("wifi_dut", wifi="init")
# @pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.config(
#     "wifi_dut",
#
#     wifi={
#
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
#         "custom_features": RS9116CustomFeatureBitMap.Default
#     },
# )
# def test_bgscan_non_us_channel(wifi_sniffer, wifi_access_point, wifi_dut):
#     tcp_socket_obj = IopTcpIpSockets()
#     send_bytes = 1000
#     validation = True
#     count = 1
#     packet_filter2 = False
#     channel_list = [12, 13, 14]
#     output_dict = {}
#     for channel in channel_list:
#         wifi_sniffer.interfaces.capture.configure_interface(channel)
#         time.sleep(5)
#         if count == 1:
#             logger().info(f"*****Sniffer capture start******")
#             wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bgscan_non_us_channel')
#             count = count + 1
#         wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
#         wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#         wifi_dut.interfaces.wifi.start_ip()
#
#         logger().info(f"*****Enable Max PSP in DUT******")
#         wifi_dut.interfaces.wifi.power_save(2, 0)
#         wifi_dut.interfaces.wifi.bt_power_save(
#             power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
#         )
#         dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
#         logger().info(f"DUT MAC_Address: {dut_mac_address}")
#         packet_filter1 = f'wlan_radio.channel == {channel} and wlan.sa == {dut_mac_address} ' \
#                          f'and wlan.fc.type_subtype == 0x0004 ' \
#                          f'and wlan.da == ff:ff:ff:ff:ff:ff '
#
#         tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
#         time.sleep(5)
#         connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
#         if connect_status is False:
#             logger().info("Unable to connect with Server")
#             assert connect_status
#         else:
#             send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
#             logger().info(f'SEND-RESPONSE = {send_response}')
#             if 'status 10' in str(send_response):
#                 result = send_response.decode().replace("\r\n", '').strip()
#                 match = re.findall(r"\d+", result)
#                 if int(match[1]) == send_bytes:
#                     logger().info(f"Send {send_bytes} bytes successfully")
#         wifi_dut.interfaces.wifi.leave()
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger().info("Stop Sniffer finally")
#         search_packet = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)
#
#         output_dict[channel] = search_packet['packet_count']
#         logger().info(f'Output = {output_dict}')
#     res = all(output_dict.values())
#     logger().info(f'Output = {output_dict}')
#     assert True if res is False else False


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "band": 1,
    },
)
def test_bgscan_5G_C19383(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = 'Data Rate:'

    ''' Verify RSI_STA connectivity by enabling BG scan in 5Ghz band '''
    wifi_access_point.interfaces.wifi.config['channel'] = 36
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(10)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bgscan_5g')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    result = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = result.ip.decode()
    logger().info(f"DUT ip address : {dut_ip}")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    # Validating probe request broadcast packet
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.sa == {dut_mac_address} and wlan.fc.type_subtype == 0x0004 ' \
                     f'and wlan.da == ff:ff:ff:ff:ff:ff'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
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
        else:
            logger().info(f"Data transfer failed")
            assert send_response
    time.sleep(2)
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)['packet_count'], \
        'Unable to find probe request broadcast packet'

    '''Again try to connect and send data as per test plan (repeat the steps from 5-10)'''
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
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
        else:
            logger().info(f"Data transfer failed")
            assert send_response
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "band": 2,
    },
)
def test_bgscan_5G_dual_band_C19384(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = 'Data Rate:'

    '''Verify RSI_STA connectivity by enabling BG scan in Dual band'''
    wifi_access_point.interfaces.wifi.config['channel'] = 36
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(10)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bgscan_5g_dual_band')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    result = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = result.ip.decode()
    logger().info(f"DUT ip address : {dut_ip}")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    # Validating probe request broadcast packet
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.sa == {dut_mac_address} and wlan.fc.type_subtype == 0x0004 ' \
                     f'and wlan.da == ff:ff:ff:ff:ff:ff'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
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
        else:
            logger().info(f"Data transfer failed")
            assert send_response
    time.sleep(2)
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        'Unable to find the broadcast probe request packet'

    '''Again try to connect and send data as per test plan (repeat the steps from 5-10)'''
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
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
        else:
            logger().info(f"Data transfer failed")
            assert send_response
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "band": 1,
    },
)
def test_bgscan_5G_rejoin_infinite_C19386(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True

    '''Verify Re-join with infinite retry when bgscan enable in 5GHZ.Module should rejoin. If not module should attempt
     infinitely. If it successfully rejoin to AP bgscan should happen'''
    wifi_access_point.interfaces.wifi.config['channel'] = 36
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(20)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bgscan_5g_rejoin')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    result = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = result.ip.decode()
    logger().info(f"DUT ip address : {dut_ip}")

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=2000, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    # Validating 11n capabilities
    packet_filter1 = f'((wlan.fc.type_subtype == 0x0000) && (wlan.sa == {dut_mac_address})) && (wlan.tag.number == 45)'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
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
        else:
            logger().info(f"Data transfer failed")
            assert send_response

    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'],\
        'Unable to find any HT capabilities'

    '''Again try to connect and send data as per test plan (repeat the steps from 5-10)'''
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
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
        else:
            logger().info(f"Data transfer failed")
            assert send_response
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
    },
)
def test_bgscan_5G_DFS_ch_C19385(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    packet_filter2 = 'Data Rate:'

    '''Verify BG Scan response when enable DFS channels'''
    wifi_access_point.interfaces.wifi.config['channel'] = 149
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(20)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bgscan_5g_dfs_ch')
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    result = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = result.ip.decode()
    logger().info(f"DUT ip address : {dut_ip}")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    # Validating HT capabilities
    packet_filter1 = f'((wlan.fc.type_subtype == 0x0000) && (wlan.sa == {dut_mac_address})) && (wlan.tag.number == 45)'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
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
        else:
            logger().info(f"Data transfer failed")
            assert send_response
    time.sleep(2)
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture(validation)
    logger().info("Stop Sniffer finally")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'],\
        'Unable to find HT capabilities packet'

    '''Again try to connect and send data as per test plan (repeat the steps from 5-10)'''
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
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
        else:
            logger().info(f"Data transfer failed")
            assert send_response
    wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "band": 2,
    },
)
def test_bgscan_primary_channel_5G_C19387(wifi_sniffer, wifi_access_point, wifi_dut):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    channel_bitmap_2_4 = 0
    channel_bitmap_5g = 0
    scan_feature_extend = 0
    channel_list = {36:0, 149:20, 165:24}

    '''configure the channels 36,149,165 in channel_bitmap field and verify whether the BG scan is happening in 
    those particular channels only or not'''
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
    for channel in channel_list:
        wifi_access_point.interfaces.wifi.start_ap(channel=channel)
        time.sleep(20)
        channel_bitmap_5g += 1 << (channel_list[channel])
        logger().info(f"channel bitmap = {channel_bitmap_5g}")
        wifi_sniffer.interfaces.capture.configure_interface(channel)
        time.sleep(5)
        wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid,
                                                        scan_bitmap_2_4=channel_bitmap_2_4,
                                                        scan_bitmap_5=channel_bitmap_5g,
                                                        scan_feature=scan_feature_extend)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bgscan_primary_channel_5G')
        wifi_dut.interfaces.wifi.join(bgscan_flag=True)
        result = wifi_dut.interfaces.wifi.start_ip()
        dut_ip = result.ip.decode()
        logger().info(f"DUT ip address : {dut_ip}")

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info(f"*****Enable Max PSP in DUT******")
        wifi_dut.interfaces.wifi.power_save(2, 0)
        wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )

        # Validating HT capabilities
        packet_filter1 = f'((wlan.fc.type_subtype == 0x0000) and (wlan.sa == {dut_mac_address})) and ' \
                         f'(wlan.tag.number == 45)'

        tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        time.sleep(2)
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
            else:
                logger().info(f"Data transfer failed")
                assert send_response
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find the HT capabilities packet in DUT side'


