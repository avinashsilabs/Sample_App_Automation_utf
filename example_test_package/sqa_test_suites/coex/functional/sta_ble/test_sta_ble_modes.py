import re
import time
from datetime import datetime, date
import pytest
from utf.utils.iperf.iperf_utils import ping
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, RS9116PowerSaveProcedureTypes, RS9116ExtTCPIPFeatureBitMap, \
    RS9116CustomFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116BTFeatureBitMap

ble_client_address = None
ble_dut_address = None

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

    Note: This test-plan has a dependency with dlink & tenda
"""


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
                result = re.search(r'\d+:\d+:\d+.\d+', x)
                logger().info(f"year : {result}")
                time_stamp = result.group().strip()
                logger().info(f'time_stamp={time_stamp}')
                time_diff_list.append(time_stamp)

        filter_file.close()
        return time_diff_list


class BleThread_Adver(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):
        if self.mode == "ble_slave":
            logger().info(f" this thread used for sta+ble as a slave")
            logger().info(f"Set up DUT for BLE advertising")
            ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert ble_dut_address is not None
            self.wifi_dut.interfaces.wifi.ble_start_advertising()
            logger().info(f"Begin Scanning for BLE devices")


class BleThread_connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):
        global ble_client_address
        global ble_dut_address
        if self.mode == "ble_master":
            logger().info(f"Start DUT")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            logger().info(f"Start ble client")
            ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert ble_client_address is not None
            time.sleep(10)
            logger().info(f"Start scanning and connect to ble client")
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=30)
            timeout = 120
            logger().info(f"connect")
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=timeout)

        if self.mode == "ble_slave":
            logger().info(f" this thread used for sta+ble as a slave")
            logger().info(f"Set up DUT for BLE advertising")
            ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert ble_dut_address is not None
            self.wifi_dut.interfaces.wifi.ble_start_advertising()
            logger().info(f"Begin Scanning for BLE devices")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
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
            self.ble_client.interfaces.bluetooth.connect(ble_dut_address)
            logger().info(f"Connection success")


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
        with TimeMeasurer():
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
                result = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
                assert isinstance(
                    result, self.wifi_dut.interfaces.wifi.IPConfig
                ), f"Failed to get IP address. Result = {result}"
                device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"Fetches the DUT mac address")
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")
            # logger().info("DUT to power save in Wifi+bluetooth mode")
            # self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
            #                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
            # self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
            #                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
            # time.sleep(15)
            if not self.tcp_bypass:
                logger().info(f"Initiate ping from third party wifi-client to DUT")
                status = ping(device_ip, 10)
                assert status == 1, "DUT not responding for ping request......"
                logger().info("ping to DUT is successful....")

            packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'

            # Validate the eapol 4 key
            packet_filter4 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                             f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid})'

            self.wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter6 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4 and ' \
                             f'wlan.da == {ap_bssid})'

            logger().info("Validating eapol4 packet")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
                'packet_count'], 'Unable to find eapol4 packet in sniffer '

            logger().info("Validating time between two packets")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)

            time_stamp_list = time_obj.find_time_stamp()
            logger().info(f'time stamp list ={time_stamp_list}')

            length = len(time_stamp_list)
            packet_found = False
            if length >= 2:
                packet_found = True
            assert packet_found is True, "4th eapol packet not found in capture file"

            # Calculating the unicast probe req time
            time_str1 = time_stamp_list[0]
            time_str1 = time_str1[:-3]
            time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()
            logger().info(f'probe req time {time_object1}')
            # Calculating the response time of eapol4
            time_str2 = time_stamp_list[length-1]
            time_str2 = time_str2[:-3]
            time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()
            logger().info(f'eapol key time {time_object2}')
            date1 = date(1, 1, 1)
            datetime1 = datetime.combine(date1, time_object1)
            datetime2 = datetime.combine(date1, time_object2)
            time_taken = datetime2 - datetime1
            time_taken = time_taken.total_seconds()
            logger().warning(f"time taken to connect is: {time_taken}") if time_taken > 0.04 else \
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

        with TimeMeasurer():
            logger().info(f"Scan for the AP's")
            ap_mac = self.wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=channel)
            ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
            logger().info(f'AP BSSID = {ap_bssid}')
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
            #
            # logger().info("DUT to power save in Wifi+bluetooth mode")
            # result = self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
            #                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)
            # assert result
            # result = self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
            #                                                      RS9116PowerSaveProcedureTypes.FastPowerSave)
            # assert result
            # time.sleep(15)

            packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'

            # Validate the eapol 4 key
            packet_filter4 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                             f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid})'

            self.wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter6 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4 and' \
                             f' wlan.da == {ap_bssid})'

            logger().info("Validating eapol4 packet")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
                    'packet_count'], 'Unable to find eapol4 packet in sniffer '

            logger().info("Validating time between two packets")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)

            time_stamp_list = time_obj.find_time_stamp()
            logger().info(f'time stamp list ={time_stamp_list}')

            length = len(time_stamp_list)
            packet_found = False
            if length >= 2:
                packet_found = True
            assert packet_found is True, "4th eapol packet not found in capture file"

            # Calculating the unicast probe req time
            time_str1 = time_stamp_list[0]
            time_str1 = time_str1[:-3]
            time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()
            logger().info(f'probe req time {time_object1}')
            # Calculating the response time of eapol4
            time_str2 = time_stamp_list[length-1]
            time_str2 = time_str2[:-3]
            time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()
            logger().info(f'eapol key time {time_object2}')
            date1 = date(1, 1, 1)
            datetime1 = datetime.combine(date1, time_object1)
            datetime2 = datetime.combine(date1, time_object2)
            time_taken = datetime2 - datetime1
            time_taken = time_taken.total_seconds()
            logger().warning(f"time taken to connect is: {time_taken}") if time_taken > 0.04 else \
                logger().info(f"time taken to connect is: {time_taken}")


class Cleanup_Thread(ThreadBase):
    def __init__(self, wifi_dut, ble_client, ble_mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_mode = ble_mode

    def run(self):
        global ble_client_address
        global ble_dut_address
        logger().info("This thread is to disconnect wlan+ble on DUT")

        # Ble disconnect
        logger().info("Initiating BLE Disconnect")
        if self.ble_mode == "ble_master":
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address, timeout=30)
        else:
            self.ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
        time.sleep(3)
        logger().info("Successfully disconnected from BLE")

        # wlan disconnect
        logger().info("Initiating WLAN Disconnect")
        self.wifi_dut.interfaces.wifi.leave()


def connect_with_psk(wifi_dut, wifi_access_point, wifi_sniffer, tcp_bypass=False):
    validation = True
    time_obj = FilterPacket()
    wifi_dut.interfaces.wifi.associated = False
    channel = wifi_access_point.interfaces.wifi.channel
    ssid = wifi_access_point.interfaces.wifi.ssid
    ap_mac = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=channel)
    ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file="psk_sniffer")

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
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    time.sleep(15)

    packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'

    # Validate the eapol 4 key
    packet_filter4 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                     f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid})'

    wifi_sniffer.interfaces.capture.stop_capture()

    packet_filter6 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4 and ' \
                     f'wlan.da == {ap_bssid})'

    logger().info("Validating eapol4 packet")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
        'packet_count'], 'Unable to find eapol4 packet in sniffer '

    logger().info("Validating time between two packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)

    time_stamp_list = time_obj.find_time_stamp()
    logger().info(f'time stamp list ={time_stamp_list}')

    length = len(time_stamp_list)
    packet_found = False
    if length >= 2:
        packet_found = True
    assert packet_found is True, "4th eapol packet not found in capture file"

    # Calculating the unicast probe req time
    time_str1 = time_stamp_list[0]
    time_str1 = time_str1[:-3]
    time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()
    logger().info(f'probe req time {time_object1}')
    # Calculating the response time of eapol4
    time_str2 = time_stamp_list[length-1]
    time_str2 = time_str2[:-3]
    time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()
    logger().info(f'eapol key time {time_object2}')
    date1 = date(1, 1, 1)
    datetime1 = datetime.combine(date1, time_object1)
    datetime2 = datetime.combine(date1, time_object2)
    time_taken = datetime2 - datetime1
    time_taken = time_taken.total_seconds()
    logger().warning(f"time taken to connect is: {time_taken}") if time_taken > 0.04 else \
        logger().info(f"time taken to connect is: {time_taken}")

    for i in range(0, 3):
        try:
            logger().info("Disabling power save mode wlan+bt")
            result = wifi_dut.interfaces.wifi.power_save(0, 0)
            assert result
            result = wifi_dut.interfaces.wifi.bt_power_save(0, 0)
            assert result
            break
        except:
            logger().info(f"failed result count : {i}")



def connect_with_psk_without_scan(wifi_dut, wifi_access_point, wifi_sniffer, tcp_bypass=False):
    validation = True
    time_obj = FilterPacket()
    wifi_dut.interfaces.wifi.associated = False
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file="psk_sniffer")

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

    packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'

    # Validate the eapol 4 key
    packet_filter4 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                     f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid})'

    wifi_sniffer.interfaces.capture.stop_capture()

    packet_filter6 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4 and ' \
                     f'wlan.da == {ap_bssid})'

    logger().info("Validating eapol4 packet")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
        'packet_count'], 'Unable to find eapol4 packet in sniffer '

    logger().info("Validating time between two packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)

    time_stamp_list = time_obj.find_time_stamp()
    logger().info(f'time stamp list ={time_stamp_list}')

    length = len(time_stamp_list)
    packet_found = False
    if length == 2:
        packet_found = True
    assert packet_found is True, "4th eapol packet not found in capture file"

    # Calculating the unicast probe req time
    time_str1 = time_stamp_list[0]
    time_str1 = time_str1[:-3]
    time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()
    logger().info(f'probe req time {time_object1}')
    # Calculating the response time of eapol4
    time_str2 = time_stamp_list[1]
    time_str2 = time_str2[:-3]
    time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()
    logger().info(f'eapol key time {time_object2}')
    date1 = date(1, 1, 1)
    datetime1 = datetime.combine(date1, time_object1)
    datetime2 = datetime.combine(date1, time_object2)
    time_taken = datetime2 - datetime1
    time_taken = time_taken.total_seconds()
    assert time_taken <= 2, f"time taken to connect is: {time_taken}"
    logger().info(f"time taken to connect is: {time_taken}")

    logger().info("DUT to power save in Wifi+bluetooth mode")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    if not tcp_bypass:
        ping_count = 300
        logger().info(f"pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info(f"ping to DUT is successful....")

    for i in range(0, 3):
        try:
            logger().info("Disabling power save mode wlan+bt")
            result = wifi_dut.interfaces.wifi.power_save(0, 0)
            assert result
            result = wifi_dut.interfaces.wifi.bt_power_save(0, 0)
            assert result
            break
        except:
            logger().info(f"failed result count : {i}")


def connect_with_pmk(wifi_dut, wifi_access_point, wifi_sniffer, tcp_bypass=False):
    validation = True
    time_obj = FilterPacket()
    wifi_dut.interfaces.wifi.associated = False

    channel = wifi_access_point.interfaces.wifi.channel
    ssid = wifi_access_point.interfaces.wifi.ssid
    ap_mac = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=channel)
    ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file="pmk_sniffer")

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
    result = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                 RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert result
    result = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                    RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert result
    time.sleep(15)

    packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'

    # Validate the eapol 4 key
    packet_filter4 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                     f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid})'

    wifi_sniffer.interfaces.capture.stop_capture()

    packet_filter6 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4 and ' \
                     f'wlan.da == {ap_bssid})'

    logger().info("Validating eapol4 packet")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
        'packet_count'], 'Unable to find eapol4 packet in sniffer '

    logger().info("Validating time between two packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)

    time_stamp_list = time_obj.find_time_stamp()
    logger().info(f'time stamp list ={time_stamp_list}')

    length = len(time_stamp_list)
    packet_found = False
    if length >= 2:
        packet_found = True
    assert packet_found is True, "4th eapol packet not found in capture file"

    # Calculating the unicast probe req time
    time_str1 = time_stamp_list[0]
    time_str1 = time_str1[:-3]
    time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()
    logger().info(f'probe req time {time_object1}')
    # Calculating the response time of eapol4
    time_str2 = time_stamp_list[length-1]
    time_str2 = time_str2[:-3]
    time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()
    logger().info(f'eapol key time {time_object2}')
    date1 = date(1, 1, 1)
    datetime1 = datetime.combine(date1, time_object1)
    datetime2 = datetime.combine(date1, time_object2)
    time_taken = datetime2 - datetime1
    time_taken = time_taken.total_seconds()
    logger().warning(f"time taken to connect is: {time_taken}") if time_taken > 0.04 else \
        logger().info(f"time taken to connect is: {time_taken}")

    for i in range(0, 3):
        try:
            logger().info("Disabling power save mode wlan+bt")
            result = wifi_dut.interfaces.wifi.power_save(0, 0)
            assert result
            result = wifi_dut.interfaces.wifi.bt_power_save(0, 0)
            assert result
            break
        except:
            logger().info(f"failed result count : {i}")



def connect_with_pmk_without_scan(wifi_dut, wifi_access_point, wifi_sniffer, tcp_bypass=False):
    validation = True
    time_obj = FilterPacket()
    wifi_dut.interfaces.wifi.associated = False
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file="pmk_sniffer")

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

    packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'

    # Validate the eapol 4 key
    packet_filter4 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                     f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid})'

    wifi_sniffer.interfaces.capture.stop_capture()

    packet_filter6 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4 and ' \
                     f'wlan.da == {ap_bssid})'

    logger().info("Validating eapol4 packet")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
        'packet_count'], 'Unable to find eapol4 packet in sniffer '

    logger().info("Validating time between two packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)

    time_stamp_list = time_obj.find_time_stamp()
    logger().info(f'time stamp list ={time_stamp_list}')

    length = len(time_stamp_list)
    packet_found = False
    if length == 2:
        packet_found = True
    assert packet_found is True, "4th eapol packet not found in capture file"

    # Calculating the unicast probe req time
    time_str1 = time_stamp_list[0]
    time_str1 = time_str1[:-3]
    time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()
    logger().info(f'probe req time {time_object1}')
    # Calculating the response time of eapol4
    time_str2 = time_stamp_list[1]
    time_str2 = time_str2[:-3]
    time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()
    logger().info(f'eapol key time {time_object2}')
    date1 = date(1, 1, 1)
    datetime1 = datetime.combine(date1, time_object1)
    datetime2 = datetime.combine(date1, time_object2)
    time_taken = datetime2 - datetime1
    time_taken = time_taken.total_seconds()
    assert time_taken <= 2, f"time taken to connect is: {time_taken}"
    logger().info(f"time taken to connect is: {time_taken}")

    logger().info("DUT to power save in Wifi+bluetooth mode")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    ping_count = 300
    logger().info(f"pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info(f"ping to DUT is successful....")

    for i in range(0, 3):
        try:
            logger().info("Disabling power save mode wlan+bt")
            result = wifi_dut.interfaces.wifi.power_save(0, 0)
            assert result
            result = wifi_dut.interfaces.wifi.bt_power_save(0, 0)
            assert result
            break
        except:
            logger().info(f"failed result count : {i}")

def connect_with_tkip_pmk(wifi_dut, wifi_access_point, wifi_sniffer, tcp_bypass=False, security_type=None):
    validation = True
    time_obj = FilterPacket()
    # wifi_dut.interfaces.wifi.associated = False

    channel = wifi_access_point.interfaces.wifi.channel
    ssid = wifi_access_point.interfaces.wifi.ssid
    ap_mac = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=channel)
    ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file="pmk_sniffer")
    wifi_dut.interfaces.wifi.generate_pmk(wifi_access_point.interfaces.wifi.ssid,
                                          wifi_access_point.interfaces.wifi.passphrase)
    logger().info(f"This API connects STA to the third party AP with the pmk generated")
    wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid,
                                      wifi_access_point.interfaces.wifi.passphrase, security_type)
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
    result = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                 RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert result
    result = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                    RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert result
    logger().info(f"Disabling powersave")
    wifi_dut.interfaces.wifi.power_save(0, 0)
    wifi_dut.interfaces.wifi.bt_power_save(0, 0)
    time.sleep(5)
    wifi_dut.interfaces.wifi.leave()
    packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'

    # Validate the eapol 4 key
    packet_filter4 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4) or ' \
                     f'(wlan.fc.type_subtype == 0x0004 and wlan.da == {ap_bssid})'

    wifi_sniffer.interfaces.capture.stop_capture()

    packet_filter6 = f'(eapol.keydes.replay_counter == 2 and wlan_rsna_eapol.keydes.msgnr == 4 and ' \
                     f'wlan.da == {ap_bssid})'

    logger().info("Validating eapol4 packet")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
        'packet_count'], 'Unable to find eapol4 packet in sniffer '

    logger().info("Validating time between two packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4, packet_filter2)

    time_stamp_list = time_obj.find_time_stamp()
    logger().info(f'time stamp list ={time_stamp_list}')

    length = len(time_stamp_list)
    packet_found = False
    if length >= 2:
        packet_found = True
    assert packet_found is True, "4th eapol packet not found in capture file"

    # Calculating the unicast probe req time
    time_str1 = time_stamp_list[0]
    time_str1 = time_str1[:-3]
    time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()
    logger().info(f'probe req time {time_object1}')
    # Calculating the response time of eapol4
    time_str2 = time_stamp_list[length-1]
    time_str2 = time_str2[:-3]
    time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()
    logger().info(f'eapol key time {time_object2}')
    date1 = date(1, 1, 1)
    datetime1 = datetime.combine(date1, time_object1)
    datetime2 = datetime.combine(date1, time_object2)
    time_taken = datetime2 - datetime1
    time_taken = time_taken.total_seconds()
    logger().warning(f"time taken to connect is: {time_taken}") if time_taken > 0.04 else \
        logger().info(f"time taken to connect is: {time_taken}")

def ble_continous_advertise(wifi_dut, ble_client):
    try:
        logger().info(f"Set up DUT for BLE advertising")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert ble_dut_address, f"Unable to find ble dut address"
        wifi_dut.interfaces.wifi.ble_start_advertising()
        logger().info(f"Begin Scanning for BLE devices")
        ble_client.interfaces.bluetooth.close()
        time.sleep(3)
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, f"ble client address not found"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        logger().info(f"ble_scan_list:\n{found_devices}")
        assert wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (found_devices[
                    wifi_dut.interfaces.wifi.ble_address] == wifi_dut.interfaces.wifi.ble_advertising_data), "Could not able to find our DUT"
        logger().info(f"See that we found our device:'{ble_dut_address}'")
    except Exception as e:
        logger().info("*************** Exception block for stop advertising and stop scanning")
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        ble_client.interfaces.wifi.stop_scanning()
        raise e

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.
        EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv", "ble_stop_scan", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteeetwobytesofsize", "passphrase": "123456789zx",
                                               "security": "WPA", "cipher": 'TKIP', "standard": '11bg'})
def test_threading_sta_ble_dut_tkip_psk_c20211(wifi_dut, ble_client, wifi_access_point, wifi_sniffer):
    ble_mode = "ble_slave"
    testcase = "sta with tkip psk + ble connection as a slave_C20211"
    with WifiThread_PSKMODE(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase), BleThread_connection(
            wifi_dut, ble_client, ble_mode):
        time.sleep(15)

    logger().info("Cleanup Thread Execution Starts...")
    with Cleanup_Thread(wifi_dut, ble_client, ble_mode):
        time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.
        EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv", "ble_stop_scan", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteeetwobytesofsize", "passphrase": "12123456789zx",
                                               "security": "WPA2", "cipher": 'AES', })
def test_threading_sta_ble_aes_psk_c20212(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
    ble_mode = "ble_slave"
    testcase = "sta with AES pmk + ble connection as a slave_C20212"
    with WifiThread_PSKMODE(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase), BleThread_connection(
            wifi_dut, ble_client, ble_mode):
        time.sleep(15)

    logger().info("Cleanup Thread Execution Starts...")
    with Cleanup_Thread(wifi_dut, ble_client, ble_mode):
        time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.
        EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features":  RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv", "ble_stop_scan", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteeetwobytesofsize", "passphrase": "12345676789zx",
                                               "security": "WPA", "cipher": 'TKIP', "standard": '11bg'})
def test_join_time_in_wpa_tkip_using_pmk_c20213(wifi_dut, ble_client, wifi_access_point, wifi_sniffer, utf_constants):
     try:
          security_type = 7
          iter_count = utf_constants.get("iter_count")
          ble_continous_advertise(wifi_dut, ble_client)
          time.sleep(5)
          for i in range(1, iter_count+1):
               connect_with_tkip_pmk(wifi_dut, wifi_access_point, wifi_sniffer, security_type=security_type)
               time.sleep(15)
               logger().info(f"iteration completed: {i}")
     finally:
         wifi_dut.interfaces.wifi.leave()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "band": 0
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "ble_stop_scan", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteeytwobytesofsize", "passphrase": "1234556789zx",
                                               "security": "WPA2", "cipher": 'AES'})
def test_wpa2_aes_using_pmk_wlan_ble_mode_loop_c20214(wifi_dut, ble_client, wifi_access_point, wifi_sniffer, utf_constants):
    ble_mode = "ble_slave"
    testcase = "Join time with AES PMK + ble connection as a slave_C20214"
    with WifiThread_PMKmode(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase), \
        BleThread_Adver(wifi_dut, ble_client, ble_mode):
        time.sleep(15)

    logger().info("Cleanup Thread Execution Starts...")
    wifi_dut.interfaces.wifi.leave()
    time.sleep(5)

    logger().info("Repeating test for 10 iterations")
    iter_count = utf_constants.get('iter_count')
    for i in range(0, iter_count):
        logger().info(f"Iteration {i} started")
        connect_with_pmk_without_scan(wifi_dut, wifi_access_point, wifi_sniffer)
        logger().info(f"Iteration {i} ended")

        logger().info("Cleanup Thread Execution Starts...")
        wifi_dut.interfaces.wifi.leave()
        logger().info(f"iteration completed: {i}")
        time.sleep(5)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "band": 0
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": "WPA", "cipher": 'TKIP', "standard": '11g'})
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "ble_stop_scan", "disassociated"])
def test_threading_sta_ble_modes_tkip_psk_c20252(wifi_dut, wifi_access_point, wifi_sniffer, ble_client, utf_constants):
    ble_mode = "ble_slave"
    testcase = "testcase for tkip with psk + ble_C20252"

    with WifiThread_PSKMODE(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase, tcp_bypass=True), \
        BleThread_Adver(wifi_dut, ble_client, ble_mode):
        time.sleep(15)

    logger().info("Cleanup Thread Execution Starts...")
    wifi_dut.interfaces.wifi.leave()
    time.sleep(5)

    logger().info("Repeating test for 10 iterations")
    iter_count = utf_constants.get('iter_count')
    for i in range(0, iter_count):
        logger().info(f"Iteration {i} started")
        connect_with_psk_without_scan(wifi_dut, wifi_access_point, wifi_sniffer, tcp_bypass=True)
        logger().info(f"Iteration {i} ended")

        logger().info("Cleanup Thread Execution Starts...")
        wifi_dut.interfaces.wifi.leave()
        logger().info(f"iteration completed: {i}")
        time.sleep(5)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "band": 0
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "ble_stop_scan", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "testingpmk", "passphrase": 'Testing_pmk', "security": "WPA2", "cipher": 'AES'})
def test_threading_sta_ble_modes_aes_psk_c20253(wifi_dut, wifi_access_point, wifi_sniffer, ble_client, utf_constants):
    ble_mode = "ble_slave"
    testcase = "testcase for AES with psk + ble_C20253"

    with WifiThread_PSKMODE(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase,tcp_bypass=True), \
        BleThread_Adver(wifi_dut, ble_client, ble_mode):
        time.sleep(15)

    logger().info("Cleanup Thread Execution Starts...")
    wifi_dut.interfaces.wifi.leave()
    time.sleep(5)

    logger().info("Repeating test for 10 iterations")
    iter_count = utf_constants.get('iter_count')
    for i in range(0, iter_count):
        logger().info(f"Iteration {i} started")
        connect_with_psk_without_scan(wifi_dut, wifi_access_point, wifi_sniffer, tcp_bypass=True)
        logger().info(f"Iteration {i} ended")

        logger().info("Cleanup Thread Execution Starts...")
        wifi_dut.interfaces.wifi.leave()
        logger().info(f"iteration completed: {i}")
        time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.
        EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features":  RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv", "ble_stop_scan", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "testingpmk", "passphrase": 'Testing_psk', "security": "WPA", "cipher": 'TKIP', "standard": '11bg'})
def test_join_time_in_wpa_pmk_using_tkip_in_tcp_bypass_c20254(wifi_dut, wifi_access_point, wifi_sniffer, ble_client, utf_constants):
    try:
        security_type = 7
        iter_count = utf_constants.get("iter_count")
        ble_continous_advertise(wifi_dut, ble_client)
        time.sleep(5)
        for i in range(1, iter_count + 1):
            connect_with_tkip_pmk(wifi_dut, wifi_access_point, wifi_sniffer,  tcp_bypass=True, security_type=security_type)
            time.sleep(15)
            logger().info(f"iteration completed: {i}")
    finally:
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.
        EnahanceMaxPsp,
        "band": 0
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv", "ble_stop_scan", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "testingpmk", "passphrase": 'Testing_psk', "security": "WPA2", "cipher": 'AES'})
def test_threading_sta_ble_modes_aes_pmk_c20255(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
    ble_mode = "ble_slave"
    testcase = "testcase for AES with pmk + ble_20255"

    with WifiThread_PMKmode(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase,
                            tcp_bypass=True), BleThread_connection(wifi_dut, ble_client, ble_mode):
        time.sleep(15)

    logger().info("Cleanup Thread Execution Starts...")
    with Cleanup_Thread(wifi_dut, ble_client, ble_mode):
        time.sleep(5)

    logger().info("Repeating test for 5 iterations")
    for i in range(1, 5):
        logger().info(f"Iteration {i} started")
        connect_with_pmk(wifi_dut, wifi_access_point, wifi_sniffer, tcp_bypass=True)
        logger().info(f"Iteration {i} ended")

        logger().info("Cleanup Thread Execution Starts...")
        with Cleanup_Thread(wifi_dut, ble_client, ble_mode):
            time.sleep(5)
