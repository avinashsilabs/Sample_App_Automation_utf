import pytest
import time
import re
from datetime import datetime, date
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.wifi import WlanError
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap

from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveModes,
    SocketOptions,
    SocketType,
    Cipher,
    DeviceConstants
)
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116CustomFeatureBitMap
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.thread_base import ThreadBase
import string
import random
from random import randint


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC)

    Test Steps:
        1. Configure the DUT in Wlan coex mode
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify power management bit to be enable in Null data frames 
        5. Initiate BLE advertise/scan

    Author: Jyothi Nagireddy

    Note: This testplan has a dependancy with dlink & tenda
"""


class BleThread_connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):
        if self.mode == "ble_master":
            logger().info(f"Start DUT")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            logger().info(f"Start ble client")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None
            time.sleep(10)
            logger().info(f"Start scanning and connect to ble client")
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
            timeout = 120
            logger().info(f"connect")
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
            logger().info(f"Disconnect")
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

        if self.mode == "ble_slave":
            logger().info(f" this thread used for sta+ble as a slave")
            logger().info(f"Set up DUT for BLE advertising")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            self.wifi_dut.interfaces.wifi.ble_start_advertising()
            logger().info(f"Begin Scanning for BLE devices")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None
            time.sleep(5)
            self.ble_client.interfaces.bluetooth.stop_scanning()
            logger().info(f"See that we found our device")
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
            assert (
                    found_devices[self.wifi_dut.interfaces.wifi.ble_address]
                    == self.wifi_dut.interfaces.wifi.ble_advertising_data
            )
            self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
            logger().info(f"Connecting will automatically stop advertising")
            # with pytest.raises(WlanError) as exc_info:
            #     self.wifi_dut.interfaces.wifi.ble_stop_advertising()
            # assert exc_info.value.error_code == 0x4E0C  # "command disallowed"
            # self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


class WifiThread_PSKMODE(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer=None, testcase=None, tcp_bypass=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.tcp_bypass = tcp_bypass

    def run(self):
        validation = True
        time_obj = FilterPacket()
        self.wifi_dut.interfaces.wifi.associated = False

        ssid = self.wifi_access_point.interfaces.wifi.ssid
        channel = self.wifi_access_point.interfaces.wifi.channel

        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        time.sleep(10)
        logger().info(f"this thread is used for wifi join")
        with TimeMeasurer() as t:
            logger().info(f"Scan for the AP's")
            # ap_mac = self.wifi_dut.interfaces.wifi.scan(ssid=None)
            ap_mac = self.wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=channel)
            ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
            logger().info(f'AP BSSID = {ap_bssid}')
            logger().info(f"Join Wi-Fi Access Point")
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            time.sleep(5)
            if not self.tcp_bypass:
                logger().info(f"This API Enables the DHCP in DUT")
                result = self.wifi_dut.interfaces.wifi.start_ip()
                assert isinstance(
                    result, self.wifi_dut.interfaces.wifi.IPConfig
                ), f"Failed to get IP address. Result = {result}"
                device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"Fetches the DUT mac address")
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")
            logger().info("DUT to power save in Wifi+bluetooth mode")
            self.wifi_dut.interfaces.wifi.power_save(2)
            self.wifi_dut.interfaces.wifi.bt_power_save(2)
            time.sleep(15)

            # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
            packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                             f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                             f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'

            packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'
            # packet_filter2 = f'(wlan.fc.type_subtype == 0x0004 and wlan.addr == {dut_mac_address})'

            # Validate the power management bit
            packet_filter3 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

            # Validate the eapol 4 key
            packet_filter4 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                             f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid})'

            # Validate dhcp
            packet_filter5 = f'wlan_radio.channel == {self.wifi_access_point.interfaces.wifi.channel} or dhcp'
            self.wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                                 'in sniffer'

            logger().info(" Validating power management bit 1")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '

            if not self.tcp_bypass:
                logger().info(" Validating dhcp")
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
                    'packet_count'], 'Unable to find dhcp in sniffer '

            logger().info("Validating time between two packets")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)
            time_stamp_list = time_obj.find_time_stamp()
            logger().info(f'time stamp list ={time_stamp_list}')

            # Calculating the unicast probe req time
            time_str1 = time_stamp_list[0]
            time_str1 = time_str1[:-3]
            time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()
            logger().info(f'probe req time {time_object1}')
            # Calcuting the reponse time of eapol4
            time_str2 = time_stamp_list[1]
            time_str2 = time_str2[:-3]
            time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()
            logger().info(f'eapol key time {time_object2}')
            date1 = date(1, 1, 1)
            datetime1 = datetime.combine(date1, time_object1)
            datetime2 = datetime.combine(date1, time_object2)
            time_taken = datetime2 - datetime1
            time_taken = time_taken.total_seconds()
            assert time_taken <= 60
            logger().info(f"time taken to connect is: {time_taken}")


class WifiThread_PMKmode(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer, testcase=None, tcp_bypass=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.tcp_bypass = tcp_bypass

    def run(self):
        validation = True
        time_obj = FilterPacket()
        self.wifi_dut.interfaces.wifi.associated = False

        logger().info("configuring the Sniffer with the channel")
        ssid = self.wifi_access_point.interfaces.wifi.ssid
        channel = self.wifi_access_point.interfaces.wifi.channel
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        time.sleep(10)
        logger().info(f"this thread is used for wifi join")

        with TimeMeasurer() as t:
            logger().info(f"Scan for the AP's")
            ap_mac = self.wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=channel)
            ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
            logger().info(f'AP BSSID = {ap_bssid}')
            logger().info(f"Generate PMK")
            self.wifi_dut.interfaces.wifi.generate_pmk(self.wifi_access_point.interfaces.wifi.ssid,
                                                       self.wifi_access_point.interfaces.wifi.passphrase)
            time.sleep(5)
            logger().info(f"Join Wi-Fi Access Point")
            logger().info(f"This API connects STA to the third party AP with the pmk generated")
            self.wifi_dut.interfaces.wifi.join_pmk(self.wifi_access_point.interfaces.wifi.ssid,
                                                   self.wifi_access_point.interfaces.wifi.passphrase)
            time.sleep(5)
            if not self.tcp_bypass:
                logger().info(f"This API Enables the DHCP in DUT")
                result = self.wifi_dut.interfaces.wifi.start_ip()
                assert isinstance(
                    result, self.wifi_dut.interfaces.wifi.IPConfig
                ), f"Failed to get IP address. Result = {result}"
                device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                logger().info(f"Fetches the DUT mac address")
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")

            logger().info("DUT to power save in Wifi+bluetooth mode")
            result = self.wifi_dut.interfaces.wifi.power_save(2)
            assert result
            result = self.wifi_dut.interfaces.wifi.bt_power_save(2)
            assert result
            time.sleep(15)

            # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
            packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                             f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                             f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'

            packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'

            # Validating the power management bit"
            packet_filter3 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

            # Validate the eapol 4 key
            packet_filter4 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                             f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid})'

            # Validate dhcp
            packet_filter5 = f'wlan_radio.channel == {self.wifi_access_point.interfaces.wifi.channel} or dhcp'
            self.wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                                 'in sniffer'

            logger().info(" Validating power management bit 1")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '

            if not self.tcp_bypass:
                logger().info(" Validating dhcp")
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
                    'packet_count'], 'Unable to find dhcp in sniffer '

            logger().info("Validating time between two packets")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)
            time_stamp_list = time_obj.find_time_stamp()
            logger().info(f'time stamp list ={time_stamp_list}')

            # Calculating the unicast probe req time
            time_str1 = time_stamp_list[0]
            time_str1 = time_str1[:-3]
            time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()
            logger().info(f'probe req time {time_object1}')
            # Calcuting the reponse time of eapol4
            time_str2 = time_stamp_list[1]
            time_str2 = time_str2[:-3]
            time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()
            logger().info(f'eapol key time {time_object2}')
            date1 = date(1, 1, 1)
            datetime1 = datetime.combine(date1, time_object1)
            datetime2 = datetime.combine(date1, time_object2)
            time_taken = datetime2 - datetime1
            time_taken = time_taken.total_seconds()
            assert time_taken <= 60
            logger().info(f"time taken to connect is: {time_taken}")


def connect_with_psk(wifi_dut, wifi_access_point, wifi_sniffer, tcp_bypass=False):
    validation = True
    time_obj = FilterPacket()
    wifi_dut.interfaces.wifi.associated = False
    channel = wifi_access_point.interfaces.wifi.channel
    ssid = wifi_access_point.interfaces.wifi.ssid
    ap_mac = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=channel)
    ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info(f"Join Wi-Fi Access Point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    time.sleep(5)
    if not tcp_bypass:
        logger().info(f"This API Enables the DHCP in DUT")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(result, wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f"Fetches the DUT mac address")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    logger().info("DUT to power save in Wifi+bluetooth mode")
    wifi_dut.interfaces.wifi.power_save(2)
    wifi_dut.interfaces.wifi.bt_power_save(2)
    time.sleep(15)

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'

    packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'

    # Validate the power management bit
    packet_filter3 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

    # Validate the eapol 4 key
    packet_filter4 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                     f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid})'

    # Validate dhcp
    packet_filter5 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} or dhcp'
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'

    logger().info(" Validating power management bit 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find power management bit 1 in sniffer '

    if not tcp_bypass:
        logger().info(" Validating dhcp")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
            'packet_count'], 'Unable to find dhcp in sniffer '

    logger().info("Validating time between two packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)
    time_stamp_list = time_obj.find_time_stamp()
    logger().info(f'time stamp list ={time_stamp_list}')

    # Calculating the unicast probe req time
    time_str1 = time_stamp_list[0]
    time_str1 = time_str1[:-3]
    time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()
    logger().info(f'probe req time {time_object1}')
    # Calcuting the reponse time of eapol4
    time_str2 = time_stamp_list[1]
    time_str2 = time_str2[:-3]
    time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()
    logger().info(f'eapol key time {time_object2}')
    date1 = date(1, 1, 1)
    datetime1 = datetime.combine(date1, time_object1)
    datetime2 = datetime.combine(date1, time_object2)
    time_taken = datetime2 - datetime1
    time_taken = time_taken.total_seconds()
    assert time_taken <= 60
    logger().info(f"time taken to connect is: {time_taken}")

    logger().info("Disabling power save mode wlan+bt")
    result = wifi_dut.interfaces.wifi.power_save(0)
    assert result
    result = wifi_dut.interfaces.wifi.bt_power_save(0)
    assert result

    logger().info("Disconnecting from wlan")
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave()
    logger().info(f"Leave completed in {t.duration} seconds")


def connect_with_pmk(wifi_dut, wifi_access_point, wifi_sniffer, tcp_bypass=False):
    validation = True
    time_obj = FilterPacket()
    wifi_dut.interfaces.wifi.associated = False

    channel = wifi_access_point.interfaces.wifi.channel
    ssid = wifi_access_point.interfaces.wifi.ssid
    ap_mac = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=channel)
    ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
    logger().info(f"Joining into Wi-Fi with pmk")
    wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid,
                                      wifi_access_point.interfaces.wifi.passphrase)
    time.sleep(5)
    if not tcp_bypass:
        logger().info(f"This API Enables the DHCP in DUT")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f"Fetches the DUT mac address")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    logger().info("Enabling power save mode wlan+bt")
    result = wifi_dut.interfaces.wifi.power_save(2)
    assert result
    result = wifi_dut.interfaces.wifi.bt_power_save(2)
    assert result
    time.sleep(15)

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid})|| wlan.addr == {dut_mac_address})'
    packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'

    # Validating the power management bit"
    packet_filter3 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

    # Validate the eapol 4 key
    packet_filter4 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                     f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid})'

    # Validate dhcp
    packet_filter5 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} or dhcp'
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'

    logger().info("Validating power management bit 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find power management bit 1 in sniffer '

    if not tcp_bypass:
        logger().info("Validating dhcp")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
            'packet_count'], 'Unable to find dhcp in sniffer '

    logger().info("Validating time between two packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)
    time_stamp_list = time_obj.find_time_stamp()
    logger().info(f'time stamp list ={time_stamp_list}')

    # Calculating the unicast probe req time
    time_str1 = time_stamp_list[0]
    time_str1 = time_str1[:-3]
    time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()
    logger().info(f'probe req time {time_object1}')
    # Calcuting the reponse time of eapol4
    time_str2 = time_stamp_list[1]
    time_str2 = time_str2[:-3]
    time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()
    logger().info(f'eapol key time {time_object2}')
    date1 = date(1, 1, 1)
    datetime1 = datetime.combine(date1, time_object1)
    datetime2 = datetime.combine(date1, time_object2)
    time_taken = datetime2 - datetime1
    time_taken = time_taken.total_seconds()
    assert time_taken <= 60
    logger().info(f"time taken to connect is: {time_taken}")

    logger().info("Disabling power save mode wlan+bt")
    result = wifi_dut.interfaces.wifi.power_save(0)
    assert result
    result = wifi_dut.interfaces.wifi.bt_power_save(0)
    assert result

    logger().info("Disconnecting from wlan")
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave()
    logger().info(f"Leave completed in {t.duration} seconds")


class FilterPacket:
    def find_time_stamp(self):
        packet_filter1 = "Arrival Time:"
        count = 0
        time_diff_list = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter1 in x:
                result = re.search('2022(.*)IST', x)
                time_stamp = result.group(1).strip()
                logger().info(f'time_stamp={time_stamp}')
                time_diff_list.append(time_stamp)

        filter_file.close()
        return time_diff_list


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteeetwobytesofsize",
                                               "passphrase": "123456789zx",
                                               "security": "WPA", "cipher": 'TKIP', "standard": '11bg'})
# "security": "WPA", "cipher": 'TKIP', "standard": '11g'})
def test_threading_sta_ble_dut_tkip_psk_C20211(wifi_dut, ble_client, wifi_access_point, wifi_sniffer):
    mode = "ble_slave"
    testcase = "sta with tkip psk + ble connection as a slave_C20211"
    with WifiThread_PSKMODE(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase), BleThread_connection(
            wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteeetwobytesofsize",
                                               "passphrase": "12123456789zx",
                                               "security": "WPA2", "cipher": 'AES', })
# "security": "WPA2", "cipher": 'AES', "standard": '11g'})
def test_threading_sta_ble_AES_psk_C20212(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
    mode = "ble_slave"
    testcase = "sta with AES pmk + ble connection as a slave_C20212"
    with WifiThread_PSKMODE(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase), BleThread_connection(
            wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteetwobytesofsize", "passphrase": "123456789zx",
                                               "security": "WPA", "cipher": 'TKIP', "standard": '11bg'})
def test_wpa_tkip_using_pmk_wlan_ble_mode_loop_C20213(wifi_dut, ble_client, wifi_access_point, wifi_sniffer):
    mode = "ble_slave"
    testcase = "sta with tkip psk + ble connection as a slave_C20213"

    with WifiThread_PMKmode(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase), BleThread_connection(
            wifi_dut, ble_client, mode):
        time.sleep(15)

    logger().info("Disconnecting from wlan")
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave()
    logger().info(f"Leave completed in {t.duration} seconds")

    logger().info("Repeating test for 10 iterations")
    for i in range(1, 5):
        logger().info(f"Iteration {i} started")
        connect_with_pmk(wifi_dut, wifi_access_point, wifi_sniffer)
        logger().info(f"Iteration {i} ended")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteeytwobytesofsize",
                                               "passphrase": "1234556789zx",
                                               "security": "WPA2", "cipher": 'AES'})
def test_wpa2_aes_using_pmk_wlan_ble_mode_loop_C20214(wifi_dut, ble_client, wifi_access_point, wifi_sniffer):
    mode = "ble_slave"
    testcase = "Join time with AES PMK + ble connection as a slave_C20214"
    with WifiThread_PMKmode(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase), BleThread_connection(
            wifi_dut, ble_client, mode):
        time.sleep(15)

    logger().info("Disconnecting from wlan")
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave()
    logger().info(f"Leave completed in {t.duration} seconds")

    logger().info("Repeating test for 10 iterations")
    for i in range(1, 5):
        logger().info(f"Iteration {i} started")
        connect_with_pmk(wifi_dut, wifi_access_point, wifi_sniffer)
        logger().info(f"Iteration {i} ended")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": "WPA", "cipher": 'TKIP', "standard": '11g'})
def test_threading_sta_ble_modes_tkip_psk_C20252(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
    mode = "ble_slave"
    testcase = "testcase for tkip with psk + ble_C20252"

    with WifiThread_PSKMODE(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase,
                            tcp_bypass=True), BleThread_connection(
        wifi_dut, ble_client, mode):
        time.sleep(15)

    logger().info("Disconnecting from wlan")
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave()
    logger().info(f"Leave completed in {t.duration} seconds")

    logger().info("Repeating test for 10 iterations")
    for i in range(1, 5):
        logger().info(f"Iteration {i} started")
        connect_with_psk(wifi_dut, wifi_access_point, wifi_sniffer, tcp_bypass=True)
        logger().info(f"Iteration {i} ended")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "testingpmk", "passphrase": 'Testing_pmk', "security": "WPA2", "cipher": 'AES'})
def test_threading_sta_ble_modes_AES_psk_C20253(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
    mode = "ble_slave"
    testcase = "testcase for AES with psk + ble_C20253"

    with WifiThread_PSKMODE(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase,
                            tcp_bypass=True), BleThread_connection(
        wifi_dut, ble_client, mode):
        time.sleep(15)

    logger().info("Disconnecting from wlan")
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave()
    logger().info(f"Leave completed in {t.duration} seconds")

    logger().info("Repeating test for 10 iterations")
    for i in range(1, 5):
        logger().info(f"Iteration {i} started")
        connect_with_psk(wifi_dut, wifi_access_point, wifi_sniffer, tcp_bypass=True)
        logger().info(f"Iteration {i} ended")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "testingpmk", "passphrase": 'Testing_psk', "security": "WPA", "cipher": 'TKIP',
                          "standard": '11bg'})
def test_threading_sta_ble_modes_tkip_pmk_C20254(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
    mode = "ble_slave"
    testcase = "testcase for tkip with pmk + ble_C20254"

    with WifiThread_PMKmode(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase,
                            tcp_bypass=True), BleThread_connection(
        wifi_dut, ble_client, mode):
        time.sleep(15)

    logger().info("Disconnecting from wlan")
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave()
    logger().info(f"Leave completed in {t.duration} seconds")

    logger().info("Repeating test for 10 iterations")
    for i in range(1, 5):
        logger().info(f"Iteration {i} started")
        connect_with_pmk(wifi_dut, wifi_access_point, wifi_sniffer, tcp_bypass=True)
        logger().info(f"Iteration {i} ended")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "testingpmk", "passphrase": 'Testing_psk', "security": "WPA2", "cipher": 'AES'})
def test_threading_sta_ble_modes_AES_pmk_C20255(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
    mode = "ble_slave"
    testcase = "testcase for AES with pmk + ble_20255"

    with WifiThread_PMKmode(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase,
                            tcp_bypass=True), BleThread_connection(
        wifi_dut, ble_client, mode):
        time.sleep(15)

    logger().info("Disconnecting from wlan")
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave()
    logger().info(f"Leave completed in {t.duration} seconds")

    logger().info("Repeating test for 10 iterations")
    for i in range(1, 5):
        logger().info(f"Iteration {i} started")
        connect_with_pmk(wifi_dut, wifi_access_point, wifi_sniffer, tcp_bypass=True)
        logger().info(f"Iteration {i} ended")
