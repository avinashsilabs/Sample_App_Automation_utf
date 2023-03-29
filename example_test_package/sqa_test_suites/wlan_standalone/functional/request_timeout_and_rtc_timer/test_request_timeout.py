from utf.interfaces.wifi import WlanError
from typing import Dict
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116ExtCustomFeatureBitMap, RS9116TCPIPFeatureBitMap, RS9116PowerSaveProcedureTypes, RS9116PowerSaveModes
import time
import pytest
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.iperf.iperf_utils import print_dict, ping
from datetime import datetime
import uuid
import re


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9116
        1. Configuration of DUT in 2G : BGN
        2. Start the sniffer before connection
        3. Set the keep alive timer in various time intervals(10sec & 30sec) 
        4. Association of Third party AP's
        5. Get the valid IP address
        6. Enable the power save mode in DUT & BT
        7. Stop the sniffer  
        8. Analyizing all sniffer capture packets and find the arp announcement packet 
        9. Validate the arp announcement packets with time delta as per keep alive timer
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Benazeer K
"""


class FilterPacket:
    '''This function is responsible to create a list for ARP announcement packet time delta '''

    def delta_between_arp_packet(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff_list = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter in x:
                time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                    'seconds', '')
                logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')
                time_diff_list.append(float(time_delta_from_previous_packet))

        filter_file.close()
        return time_diff_list


ping_count = 10


def arp_packet_decrypt(wifi_sniffer, logger, decryption_key: str, mac_address, print_layers: list,
                       capture_filename,
                       mode=0) -> Dict[str, int]:
    cipher_suite = []
    count = 0
    current_time = time.time()
    logger().info(f" **** capture_name {capture_filename}")
    updated_capture_file = 'filter_' + capture_filename + '_' + str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    file_name = f'./reports/{updated_capture_file}.pcap'
    logger().info("f **** updated file_name {updated_capture_file}")
    local_capture_file = file_name
    logger().info(f"++++ Remote capture file {wifi_sniffer.interfaces.capture.remote_capture_file}")

    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    # wlan_filter_file = local_capture_file
    packet_filter1 = f'(wlan.addr == {mac_address})'
    # packet_filter1 = f'wlan.sa == {mac_address} and wlan.da == ff:ff:ff:ff:ff:ff ' \
    #                  f'and arp.proto.type == 0x0800 and wlan.fc.pwrmgt == 1'
    wifi_sniffer.interfaces.capture.shell(
        f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
        f"frame.number -w "
        f"{wlan_filter_file}")

    # with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
    #     sftp.get(wifi_sniffer.interfaces.capture.remote_capture_file, local_capture_file)

    logger().info(f"+++++ LOCAL CAPTURE FILE {local_capture_file}")
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
            capture_file_filter=wifi_sniffer.interfaces.capture.remote_capture_file
    ):
        # logger().info(f"***************************packet is {packet}***************************")
        for layer in packet.layers:
            # logger().info(f"***************************layer is {layer}***************************")
            layer_name = layer.layer_name.lower()
            logger().info(f"***************************layer name is {layer_name}***************************")
    #         if layer_name == "websocket":
    #             http_layer = str(layer)
    #             if (re.search(".*Opcode: Ping", http_layer)):
    #                 logger().info(f"PING PACKET {http_layer}")
    #             elif (re.search(".*Opcode: Pong", http_layer)):
    #                 logger().info(f"PONG PACKET {http_layer}")
    #
    # return cipher_suite


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.parametrize("channel", [4])
@pytest.mark.config("wifi_access_point", wifi={"channel": 4, "security": 'OPEN'})
def test_request_timeout_keep_alive_10sec_c19746(wifi_sniffer, wifi_dut, wifi_access_point, channel):
    """=============================this test_case to validate keep-alive for 10secs=========================="""
    logger().info("*** Open security validation *****")
    time_delta = 10
    arp_time_delta_obj = FilterPacket()
    capture_filename = 'test_request_timeout_keep_alive_10sec'
    keep_alive_time = 4
    validation = True
    logger().info(f"Sniffer starts on configured channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    time.sleep(2)
    logger().info(f"Setting keep_alive feature in DUT")
    wifi_dut.interfaces.wifi.set_timeout(feature=keep_alive_time, timeout=10)
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
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Actual MAC_Address: {mac_address}")

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current Version: {result}")

    logger().info(f"DUT is join the third party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"DUT ip address : {device_ip}")

    logger().info(f"*****Initiating Power_save Mode2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    time.sleep(2)
    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(2)

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.sa == {mac_address} and wlan.da == ff:ff:ff:ff:ff:ff ' \
                     f'and arp.proto.type == 0x0800 and wlan.fc.pwrmgt == 1'
    # packet_filter1 = f'wlan.bssid == {mac_address}'
    packet_filter2 = 'Address Resolution Protocol (ARP Announcement)'

    time.sleep(55)
    logger().info(f"Sniffer is going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(2)
    logger().info(f"DUT is going to leave")
    wifi_dut.interfaces.wifi.leave()
    logger().info(f"Sniffer validation for ARP packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    logger().info(f"Decryption key is {decryption_key}")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
                'packet_count'], 'Unable to find ARP frames in sniffer'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find ARP frames in sniffer'

    """=============================Validation of time delta between keep-alive packets=========================="""
    arp_packets_time_delta_list = arp_time_delta_obj.delta_between_arp_packet()
    arp_packets_time_delta_list.pop(0)
    arp_packets_time_delta_list.pop(0)
    logger().info(f'APR packet time delta list after removing 0 = {arp_packets_time_delta_list}')
    for time_diff in arp_packets_time_delta_list:
        logger().info(int(time_diff))
        is_between = int(time_diff) in range(0, time_delta + 2)
        if is_between is False:
            logger().info(is_between)
            status = is_between
            break
        else:
            logger().info(is_between)
            status = is_between
    assert status
    time.sleep(1)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4, "security": 'OPEN'})
def test_request_timeout_keep_alive_30sec_C19750(wifi_sniffer, wifi_dut, wifi_access_point):
    """=============================this test_case to validate keep-alive for 30secs=========================="""
    time_delta = 30
    arp_time_delta_obj = FilterPacket()
    keep_alive_time = 4
    validation = True
    logger().info(f"Sniffer starts on configured channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_request_timeout_keep_alive_30sec')
    time.sleep(2)
    logger().info(f"Setting keep_alive feature in DUT")
    wifi_dut.interfaces.wifi.set_timeout(feature=keep_alive_time, timeout=30)
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
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Actual MAC_Address: {mac_address}")

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current Version: {result}")

    logger().info(f"DUT is join the third party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"DUT ip address : {device_ip}")

    logger().info(f"*****Initiating Power_save Mode2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    time.sleep(2)
    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(2)

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.sa == {mac_address} and wlan.da == ff:ff:ff:ff:ff:ff ' \
                     f'and arp.proto.type == 0x0800 and wlan.fc.pwrmgt == 1'
    packet_filter2 = 'Address Resolution Protocol (ARP Announcement)'

    time.sleep(90)
    logger().info(f"Sniffer is going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(2)
    logger().info(f"DUT is going to leave")
    wifi_dut.interfaces.wifi.leave()
    logger().info(f"Sniffer validation for ARP packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
                'packet_count'], 'Unable to find ARP frames in sniffer'

    """=============================Validation of time delta between keep-alive packets=========================="""
    arp_packets_time_delta_list = arp_time_delta_obj.delta_between_arp_packet()
    arp_packets_time_delta_list.pop(0)
    arp_packets_time_delta_list.pop(0)
    logger().info(f'APR packet time delta list after removing 0 = {arp_packets_time_delta_list}')
    for time_diff in arp_packets_time_delta_list:
        logger().info(int(time_diff))
        is_between = int(time_diff) in range(0, time_delta + 2)
        if is_between is False:
            logger().info(is_between)
            status = is_between
            break
        else:
            logger().info(is_between)
            status = is_between
    assert status
    time.sleep(1)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_request_timeout_scan_100misc_C19748(wifi_sniffer, wifi_dut, wifi_access_point):
    """=============================this test_case to validate scan for 100 Milli seconds=========================="""
    scan_timeout = 2
    validation = True
    wifi_dut.interfaces.wifi.set_timeout(feature=scan_timeout, timeout=100)
    logger().info(f"Sniffer starts on configured channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_request_timeout_scan_100misc')
    time.sleep(3)
    with TimeMeasurer() as t:
        logger().info(f"Initiating Scan")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    logger().info(scan_results)
    assert len(scan_results) > 0
    logger().info(f"Scan in {t.duration} seconds")
    assert (1.2 < t.duration < 1.5)
    time.sleep(2)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Actual MAC_Address: {mac_address}")

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current Version: {result}")

    logger().info(f"DUT is join the third party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"DUT ip address : {device_ip}")

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    time.sleep(2)
    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(2)

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.sa == {mac_address} and wlan.fc.type_subtype == 0x0004'

    time.sleep(10)
    logger().info(f"Sniffer is going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info(f"DUT is going to leave")
    wifi_dut.interfaces.wifi.leave()
    logger().info(f"Sniffer validation for probe request")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find probe request frames in sniffer'


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_request_timeout_scan_500misc_C19751(wifi_sniffer, wifi_dut, wifi_access_point):
    """=============================this test_case to validate scan for 500 Milliseconds=========================="""
    scan_timeout = 2
    validation = True
    wifi_dut.interfaces.wifi.set_timeout(feature=scan_timeout, timeout=500)
    logger().info(f"Sniffer starts on configured channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_request_timeout_scan_500misc')
    time.sleep(3)
    with TimeMeasurer() as t:
        logger().info(f"Initiating scan")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    logger().info(scan_results)
    assert len(scan_results) > 0
    logger().info(f"Scan in {t.duration} seconds")
    assert (1.2 < t.duration < 5.8)
    time.sleep(2)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Actual MAC_Address: {mac_address}")

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current Version: {result}")

    logger().info(f"DUT is join the third party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"DUT ip address : {device_ip}")

    logger().info(f"*****Initiating Power_save Mode2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    time.sleep(2)
    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(2)

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.sa == {mac_address} and wlan.fc.type_subtype == 0x0004'

    time.sleep(10)
    logger().info(f"Sniffer is going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info(f"DUT is going to leave")
    wifi_dut.interfaces.wifi.leave()
    logger().info(f"Sniffer validation for probe request")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find probe request frames in sniffer'



@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    },
)
@pytest.mark.parametrize("channel", [4])
@pytest.mark.config("wifi_access_point", wifi={"channel": 4, "security": 'OPEN'})
def test_sta_keep_alive_10sec_with_traffic_C19637(wifi_sniffer, wifi_dut, wifi_access_point, channel, wifi_client):
    """=============================this test_case to validate keep-alive for 10secs=========================="""
    logger().info("*** Open security validation *****")
    time_delta = 10
    arp_time_delta_obj = FilterPacket()
    capture_filename = 'test_sta_keep_alive_10sec_with_traffic_C19637'
    keep_alive_time = 4
    validation = True
    logger().info(f"Sniffer starts on configured channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    logger().info(f"enabling the BG scan params")
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
    logger().info(f"enabling the rejoin params")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    time.sleep(2)
    logger().info(f"Setting keep_alive feature in DUT")
    wifi_dut.interfaces.wifi.set_timeout(feature=keep_alive_time, timeout=10)
    time.sleep(2)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Actual MAC_Address: {mac_address}")

    logger().info(f"DUT is join the third party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"DUT ip address : {device_ip}")

    logger().info(f"*****Initiating Power_save Mode2 in DUT******")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    time.sleep(50)

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.sa == {mac_address} and wlan.da == ff:ff:ff:ff:ff:ff ' \
                     f'and arp.proto.type == 0x0800 and wlan.fc.pwrmgt == 1'
    packet_filter2 = 'Address Resolution Protocol (ARP Announcement)'

    packet_filter3 = f'((wlan.addr == {mac_address} && wlan.fc.type_subtype == 0) && (wlan.supported_rates == 0x96))' \
                     f' && (wlan.supported_rates == 0x24) && (wlan.ht.capabilities == 0x012c)'

    packet_filter4 = f'((wlan.sa == {mac_address} and wlan.da == ff:ff:ff:ff:ff:ff) && wlan.fc.type_subtype == 4)'
    time.sleep(50)
    logger().info(f"Sniffer is going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(2)
    logger().info(f"DUT is going to leave")
    wifi_dut.interfaces.wifi.leave()

    logger().info(f"Sniffer validation for Broadcast probe request packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
                'packet_count'], 'Unable to find probe request frames in sniffer'

    logger().info(f"Sniffer validation for ARP packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    logger().info(f"Decryption key is {decryption_key}")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
                'packet_count'], 'Unable to find arp frames in sniffer'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
                'packet_count'], 'Unable to find association frames in sniffer'


    """=============================Validation of time delta between keep-alive packets=========================="""
    arp_packets_time_delta_list = arp_time_delta_obj.delta_between_arp_packet()
    logger().info(f'APR packet time delta list before removing 0 = {arp_packets_time_delta_list}')
    arp_packets_time_delta_list.pop(0)
    arp_packets_time_delta_list.pop(0)
    logger().info(f'APR packet time delta list after removing 0 = {arp_packets_time_delta_list}')
    for time_diff in arp_packets_time_delta_list:
        logger().info(int(time_diff))
        is_between = int(time_diff) in range(0, time_delta + 2)
        if is_between is False:
            logger().info(is_between)
            status = is_between
            break
        else:
            logger().info(is_between)
            status = is_between
    assert status, "packets are not received in expected time"
    time.sleep(1)

###commented because still facing issue with auth_timeout_with_100msec
# @pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
# @pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake
#                     | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity,
#         "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
#     },
# )
# def test_wifi_auth_timeout_with_100msec(wifi_sniffer, wifi_dut, wifi_access_point):
#     """=================this test_case to validate Authentication timeout for 100 Milliseconds======================"""
#     wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#     wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_auth_timeout_with_100msec')
#     time.sleep(5)
#     auth_timeout = 1
#     wifi_dut.interfaces.wifi.set_timeout(feature=auth_timeout, timeout=100)
#     time.sleep(5)
#     wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
#
#     result = wifi_dut.interfaces.wifi.version()
#     logger().info(f"Actual version: {result}")
#
#     with pytest.raises(WlanError) as exc_info:
#         wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#         wifi_sniffer.interfaces.capture.stop_capture()
#     assert exc_info.value.error_code == 0x48
#
#
# @pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
# @pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake
#                     | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity,
#         "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
#     },
# )
# def test_wifi_auth_timeout_with_300msec(wifi_sniffer, wifi_dut, wifi_access_point):
#     """=================this test_case to validate Authentication timeout for 300 Milliseconds======================"""
#     wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#     wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_auth_timeout_with_300msec')
#     time.sleep(5)
#     auth_timeout = 1
#     wifi_dut.interfaces.wifi.set_timeout(feature=auth_timeout, timeout=100)
#     time.sleep(2)
#     wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
#
#     result = wifi_dut.interfaces.wifi.version()
#     logger().info(f"Actual version: {result}")
#
#     with pytest.raises(WlanError) as exc_info:
#         wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#         wifi_sniffer.interfaces.capture.stop_capture()
#     assert exc_info.value.error_code == 0x48