import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.iperf.iperf_utils import ping, get_host_ip
from utf.interfaces.wifi import WlanError
from utf.utils.stopwatch import Stopwatch
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
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap,
)
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.thread_base import ThreadBase
import time
import string
import random
from random import randint
import re


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
"""


class DNSThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer=None, testcase1=None, testcase2=None, testcase3=None,
                 testcase=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.testcase1 = testcase1
        self.testcase2 = testcase2
        self.testcase3 = testcase3

    def run(self):
        validation = True
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        logger().info(f"this thread is used for wifi join")
        with TimeMeasurer() as t:
            logger().info(f"Scan for the AP's")
            ap_mac = self.wifi_dut.interfaces.wifi.scan(ssid=None)
            ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
            logger().info(f'AP BSSID = {ap_bssid}')
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            self.wifi_dut.interfaces.wifi.start_ip()
            device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            time.sleep(5)
            logger().info(f"enabling powersave in both wifi and bluetooth")
            self.wifi_dut.interfaces.wifi.power_save(2)
            self.wifi_dut.interfaces.wifi.bt_power_save(2)
            time.sleep(10)
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {dut_mac_address}")
            logger().info(f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol")
            packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                             f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                             f'(wlan.fc.type_subtype == 0x000b))'

            logger().info(f"Validating the power management bit")
            packet_filter2 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

            if (self.testcase1 == "dnsquery"):
                logger().info("=======DNS SERVER WITH DHCP========")
                result = self.wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "NULL", "NULL")
                logger().info(result.decode())

            elif (self.testcase2 == "dnswrongip"):
                with pytest.raises(WlanError) as exc_info:
                    logger().info("=======DNS SERVER WITH DHCP========")
                    result = self.wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "10.210.110.11", "10.89.41.10")
                    logger().info(result.decode())
                assert exc_info.value.error_code == 0xbba3 or 0xBBA1 or 0xaf

            elif (self.testcase3 == "dnsstatic"):
                logger().info("=======DNS SERVER WITH DHCP========")
                result = self.wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "10.207.110.11", "10.8.4.10")
                logger().info(result.decode())
                time.sleep(15)
            status = ping(device_ip, 100)
            assert status == 1, f"received packets is 100%, expected is 1"
        logger().info(f"Scan and join, ping in {t.duration} seconds")
        self.wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'
        logger().info(" Validate power management bit 1")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '


class httpgetpostThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, http_server, index_path, wifi_sniffer, testcase):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.http_server = http_server
        self.index_path = index_path
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase

    def run(self):
        validation = True
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        logger().info(f"this thread is used for wifi join")
        with TimeMeasurer() as t:
            logger().info(f"Scan for the AP's")
            ap_mac = self.wifi_dut.interfaces.wifi.scan(ssid=None)
            ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
            logger().info(f'AP BSSID = {ap_bssid}')
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            self.wifi_dut.interfaces.wifi.start_ip()
            time.sleep(2)
            self.wifi_dut.interfaces.wifi.power_save(2)
            self.wifi_dut.interfaces.wifi.bt_power_save(2)
            time.sleep(5)
            logger().info(f"*****Enable Max PSP in DUT******")
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            time.sleep(5)
            logger().info(f"DUT MAC_Address: {dut_mac_address}")
            time.sleep(2)

            logger().info(f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol")
            packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                             f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                             f'(wlan.fc.type_subtype == 0x000b))'

            logger().info(f"Validating the power management bit")
            packet_filter2 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

            self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
            logger().info("API used to get the http data")
            self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path)
            time.sleep(10)
            logger().info(f"API used to post the http data")
            self.wifi_dut.interfaces.http.http_post(self.http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                    post_data="utf automation")
            time.sleep(15)
        logger().info(f"Scan and join in {t.duration} seconds")
        self.wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'
        logger().info(" Validate power management bit 1")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '
        logger().info(f"Verified device is in power save")
        logger().info(" Validate power management bit 1")


class httpgetThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, http_server, index_path, wifi_sniffer, testcase):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.http_server = http_server
        self.index_path = index_path
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase

    def run(self):
        validation = True
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        logger().info(f"this thread is used for wifi join")
        with TimeMeasurer() as t:
            logger().info(f"Scan for the AP's")
            ap_mac = self.wifi_dut.interfaces.wifi.scan(ssid=None)
            ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
            logger().info(f'AP BSSID = {ap_bssid}')
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            self.wifi_dut.interfaces.wifi.start_ip()
            time.sleep(2)
            self.wifi_dut.interfaces.wifi.power_save(2)
            self.wifi_dut.interfaces.wifi.bt_power_save(2)
            time.sleep(5)
            logger().info(f"*****Enable Max PSP in DUT******")
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            time.sleep(5)
            logger().info(f"DUT MAC_Address: {dut_mac_address}")
            time.sleep(2)

            logger().info(f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol")
            packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                             f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                             f'(wlan.fc.type_subtype == 0x000b))'

            logger().info(f"Validating the power management bit")
            packet_filter2 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

            self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi

            logger().info("API used to get the http data")
            self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path)

            time.sleep(10)
        logger().info(f"Scan and join in {t.duration} seconds")
        self.wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'

        logger().info(" Validate power management bit 1")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '
        logger().info(f"Verified device is in power save")
        logger().info(" Validate power management bit 1")


class httppostThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, http_server, index_path, wifi_sniffer, testcase):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.http_server = http_server
        self.index_path = index_path
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase

    def run(self):
        validation = True
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        logger().info(f"this thread is used for wifi join")
        with TimeMeasurer() as t:
            logger().info(f"Scan for the AP's")
            ap_mac = self.wifi_dut.interfaces.wifi.scan(ssid=None)
            ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
            logger().info(f'AP BSSID = {ap_bssid}')
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            self.wifi_dut.interfaces.wifi.start_ip()
            time.sleep(2)
            self.wifi_dut.interfaces.wifi.power_save(2)
            self.wifi_dut.interfaces.wifi.bt_power_save(2)
            time.sleep(5)
            logger().info(f"*****Enable Max PSP in DUT******")
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            time.sleep(5)
            logger().info(f"DUT MAC_Address: {dut_mac_address}")
            time.sleep(2)

            logger().info(f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol")
            packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                             f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                             f'(wlan.fc.type_subtype == 0x000b))'

            logger().info(f"Validating the power management bit")
            packet_filter2 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

            self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi

            logger().info(f"API used to post the http data")
            self.wifi_dut.interfaces.http.http_post(self.http_server.interfaces.http, "cgi-bin/cgi_example.py", post_data="utf automation")
            time.sleep(15)
        logger().info(f"Scan and join in {t.duration} seconds")
        self.wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'
        logger().info(" Validate power management bit 1")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '
        logger().info(f"Verified device is in power save")
        logger().info(" Validate power management bit 1")


class bgscandatatransferThread(ThreadBase):
    def __init__(self, wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, net_perf_client=None, protocol=None,
                 testcase=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client

    def __print_throughput(self, iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def run(self):
        validation = True
        packet_filter2 = False
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        time.sleep(4)
        self.wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
        logger().info(f"Join Wi-Fi Access Point")
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        logger().info(f"Successfully connected to AP")
        time.sleep(1)
        logger().info(f"This API Enables the DHCP in DUT")
        ip_config = self.wifi_dut.interfaces.wifi.start_ip()
        time.sleep(3)
        self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        time.sleep(2)
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"Found device ip: {device_ip}")
        logger().info(f"This API Enables the wifi power save mode in DUT")
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        logger().info(f"Enables the bt power save in DUT")
        self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        time.sleep(5)
        logger().info(f"Initiate ping from third party wifi-client to DUT")
        status = ping(device_ip, 10)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        logger().info(f"Fetches the DUT mac address")
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")
        logger().info(f"Validating the power management bit")
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'
        logger().info(f"preparing iperf")
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=self.protocol)
        logger().info(f"creating results object for sharing between host and dut")
        result = Result(self.net_perf_client.interfaces.net_perf.protocol)
        logger().info(f"open socket and start listening")
        with self.wifi_dut.interfaces.wifi.start_socket_reader(
                log_file=self.net_perf_client.interfaces.net_perf.device_log_file_handle,
                result=result,
                protocol=self.net_perf_client.interfaces.net_perf.protocol,
                port=self.net_perf_client.interfaces.net_perf.client_port,
                device_ip=device_ip,
                data_len=self.net_perf_client.interfaces.net_perf.client_data_len,
                time=self.net_perf_client.interfaces.net_perf.client_timeout) as obj:
            logger().info(f"start iperf")
            self.net_perf_client.interfaces.net_perf.start()
            logger().info(f"capture device output")
            self.wifi_dut.interfaces.wifi.read_from_device(obj, self.net_perf_client.interfaces.net_perf.client_timeout)
        logger().info(f"get and print throughput")
        tp = self.net_perf_client.interfaces.net_perf.process_output(result)
        assert tp is not None
        self.wifi_sniffer.interfaces.capture.stop_capture()
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
            'packet_count'], 'Unable to find power management bit in sniffer'
        logger().info(f"Verified device is in power save")


class WifidatatransferThread(ThreadBase):
    def __init__(self, wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, net_perf_client=None, protocol=None,
                 testcase=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client

    def __print_throughput(self, iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def run(self):
        validation = True
        packet_filter2 = False
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        time.sleep(4)
        self.wifi_dut.interfaces.wifi.scan(ssid=None)
        logger().info(f"Join Wi-Fi Access Point")
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        logger().info(f"Successfully connected to AP")
        time.sleep(1)
        logger().info(f"This API Enables the DHCP in DUT")
        ip_config = self.wifi_dut.interfaces.wifi.start_ip()
        time.sleep(3)
        self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        time.sleep(2)
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"Found device ip: {device_ip}")
        logger().info(f"This API Enables the wifi power save mode in DUT")
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        logger().info(f"Enables the bt power save in DUT")
        self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        time.sleep(5)
        logger().info(f"Initiate ping from third party wifi-client to DUT")
        status = ping(device_ip, 10)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        logger().info(f"Fetches the DUT mac address")
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")
        logger().info(f"Validating the power management bit")
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'
        logger().info(f"preparing iperf")
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=self.protocol)
        logger().info(f"creating results object for sharing between host and dut")
        result = Result(self.net_perf_client.interfaces.net_perf.protocol)
        logger().info(f"open socket and start listening")
        with self.wifi_dut.interfaces.wifi.start_socket_reader(
                log_file=self.net_perf_client.interfaces.net_perf.device_log_file_handle,
                result=result,
                protocol=self.net_perf_client.interfaces.net_perf.protocol,
                port=self.net_perf_client.interfaces.net_perf.client_port,
                device_ip=device_ip,
                data_len=self.net_perf_client.interfaces.net_perf.client_data_len,
                time=self.net_perf_client.interfaces.net_perf.client_timeout) as obj:
            logger().info(f"start iperf")
            self.net_perf_client.interfaces.net_perf.start()
            logger().info(f"capture device output")
            self.wifi_dut.interfaces.wifi.read_from_device(obj, self.net_perf_client.interfaces.net_perf.client_timeout)
        logger().info(f"get and print throughput")
        tp = self.net_perf_client.interfaces.net_perf.process_output(result)
        assert tp is not None
        self.wifi_sniffer.interfaces.capture.stop_capture()
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
            'packet_count'], 'Unable to find power management bit in sniffer'
        logger().info(f"Verified device is in power save")


class BleThread_connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):
        if (self.mode == "ble_master"):
            logger().info(f"Start DUT")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            logger().info(f"Start ble client")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None
            time.sleep(1)
            logger().info(f"Start scanning and connect to ble client")
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
            timeout = 120
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
            logger().info(f"Disconnect")
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

        if (self.mode == "ble_slave"):
            logger().info(f"Set up DUT for BLE advertising")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            time.sleep(10)
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
            with pytest.raises(WlanError) as exc_info:
                self.wifi_dut.interfaces.wifi.ble_start_advertising()
            assert exc_info.value.error_code == 0x4E0C
            self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
            logger().info(f"Connecting will automatically stop advertising")
            with pytest.raises(WlanError) as exc_info:
                self.wifi_dut.interfaces.wifi.ble_stop_advertising()
            assert exc_info.value.error_code == 0x4E0C
            time.sleep(20)
            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


class BleThread_initdeinit(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):
        if (self.mode == "ble_master"):
            logger().info(f"Start DUT")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            logger().info(f"Start ble client")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None
            time.sleep(40)
            logger().info(f"Start scanning and connect to ble client")
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
            timeout = 120
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
            logger().info(f"Disconnect")
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
            self.wifi_dut.interfaces.wifi.bt_deinit()
            time.sleep(1)

        if (self.mode == "ble_slave"):
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
            with pytest.raises(WlanError) as exc_info:
                self.wifi_dut.interfaces.wifi.ble_stop_advertising()
            assert exc_info.value.error_code == 0x4E0C  # "command disallowed"
            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
            self.wifi_dut.interfaces.wifi.bt_deinit()
            time.sleep(1)

class WifidatatransferThread(ThreadBase):
    def __init__(
        self,
        wifi_sniffer,
        wifi_dut,
        wifi_access_point,
        wifi_client,
        net_perf_client=None,
        protocol=None,
        testcase=None,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client

    def __print_throughput(self, iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def run(self):
        validation = True
        packet_filter2 = False
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        time.sleep(4)
        self.wifi_dut.interfaces.wifi.scan(ssid=None)
        logger().info(f"Join Wi-Fi Access Point")
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        logger().info(f"Successfully connected to AP")
        time.sleep(1)
        logger().info(f"This API Enables the DHCP in DUT")
        ip_config = self.wifi_dut.interfaces.wifi.start_ip()
        time.sleep(3)
        self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        time.sleep(2)
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
        logger().info(f"Found device ip: {device_ip}")
        logger().info(f"This API Enables the wifi power save mode in DUT")
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        logger().info(f"Enables the bt power save in DUT")
        self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        time.sleep(5)
        logger().info(f"Initiate ping from third party wifi-client to DUT")
        status = ping(device_ip, 10)
        assert (
            status is True
        ), "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        logger().info(f"Fetches the DUT mac address")
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")
        logger().info(f"Validating the power management bit")
        packet_filter1 = f"wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}"
        logger().info(f"preparing iperf")
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"{host_ip}")
        self.net_perf_client.interfaces.net_perf.init_client(
            host_ip=host_ip, device_ip=device_ip, protocol=self.protocol
        )
        logger().info(f"creating results object for sharing between host and dut")
        result = Result(self.net_perf_client.interfaces.net_perf.protocol)
        logger().info(f"open socket and start listening")
        with self.wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=self.net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=self.net_perf_client.interfaces.net_perf.protocol,
            port=self.net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=self.net_perf_client.interfaces.net_perf.client_data_len,
            time=self.net_perf_client.interfaces.net_perf.client_timeout,
        ) as obj:
            logger().info(f"start iperf")
            self.net_perf_client.interfaces.net_perf.start()
            logger().info(f"capture device output")
            self.wifi_dut.interfaces.wifi.read_from_device(
                obj, self.net_perf_client.interfaces.net_perf.client_timeout
            )
        logger().info(f"get and print throughput")
        tp = self.net_perf_client.interfaces.net_perf.process_output(result)
        assert tp is not None
        self.wifi_sniffer.interfaces.capture.stop_capture()
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter1, packet_filter2
        )["packet_count"], "Unable to find power management bit in sniffer"
        logger().info(f"Verified device is in power save")

class otafthread(ThreadBase):
    def __init__(self, wifi_dut,  wifi_access_point, http_server, wifi_client, wifi_sniffer, testcase=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.wifi_sniffer = wifi_sniffer
        self.http_server = http_server
        self.testcase = testcase

    def run(self):
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        """ ******* SERVER CHECKS ******* """
        logger().info("checking server stats....")
        server_stat = self.http_server.interfaces.http.started
        assert server_stat == True
        logger().info(f'http server state is {server_stat}')
        logger().info("fetching server ip....")
        host_ip = get_host_ip()
        start_time = time.perf_counter_ns()
        async_timestamp = 0
        logger().info(f"server ip is {host_ip}")
        logger().info("pinging to server ip....")
        status = ping(host_ip, 10)
        assert status == 1, "unable to ping to server"
        logger().info("Fetching the DUT version...")
        self.wifi_dut.interfaces.wifi.version()
        logger().info("Joining ap....")
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        logger().info("Starting dhcp....")
        self.wifi_dut.interfaces.wifi.start_ip()
        logger().info(f"performs the firmware upgrade on DUT over the http port")
        logger().info("Performing fw upgrade on DUT....")
        self.wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)
        time.sleep(90)
        with pytest.raises(WlanError) as exc_info:
         logger().info("fetching otaf upgrade status....")
         self.wifi_dut.interfaces.wifi.get_http_otaf_status()
        assert exc_info.value.error_code == 0xbb38

        time.sleep(10)
        events = self.wifi_dut.interfaces.wifi.get_async_events()
        if len(events):
            for event in events:
                if event.event_type == RS9116AsyncEventType.HTTP_OTAF_STATUS:
                    async_timestamp = event.timestamp

        if not async_timestamp:
            logger().info(f"Asynchronous message is not received after otaf over http")
        else:
            time_duration = (async_timestamp - start_time) / 1000000000
            logger().info(f"Time taken to upgrade firmware using http otaf {time_duration} seconds")

        logger().info("resetting the DUT after upgrade....")
        self.wifi_dut.interfaces.wifi.reset_soft()
        time.sleep(60)

        logger().info("Initializing DUT....")
        self.wifi_dut.interfaces.wifi.init()
        time.sleep(10)

        logger().info("fetching DUT version after init....")
        self.wifi_dut.interfaces.wifi.version()

        logger().info("Stop Sniffer finally")
        self.wifi_sniffer.interfaces.capture.stop_capture(sniffer_validation=False)
        time.sleep(10)


class BleThread_Multipleconnection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):
           if (self.mode == "ble_master"):
              logger().info(f"Start DUT")
              bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
              assert bt_dut_address is not None
              logger().info(f"Start ble client")
              bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
              assert bt_client_address is not None
              time.sleep(1)
              logger().info(f"Start scanning and connect to ble client")
              self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
              timeout = 120
              self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
              self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

           if (self.mode == "ble_slave"):
               bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
               assert bt_dut_address is not None
               self.wifi_dut.interfaces.wifi.ble_start_advertising()

               logger().info(f"Begin Scanning for BLE devices")
               bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
               assert bt_client_address is not None
               device_found = False
               sw = Stopwatch()
               while sw.elapsed_sec < 30:
                   found_devices = self.ble_client.interfaces.bluetooth.get_devices()
                   if bt_dut_address in found_devices and \
                           found_devices[bt_dut_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data:
                       device_found = True
                       break
               self.ble_client.interfaces.bluetooth.stop_scanning()
               assert device_found
               self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
               time.sleep(2)
               self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
               time.sleep(1)
               self.ble_client.interfaces.wifi.ble_start_advertising()
               time.sleep(1)
               self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
               time.sleep(2)
               self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
               time.sleep(1)
               self.ble_client.interfaces.wifi.ble_start_advertising()
               time.sleep(1)
               self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
               time.sleep(2)
               self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
               time.sleep(1)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_threading_sta_ble_dns_C20360(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
    mode = "ble_slave"
    testcase1 = "dnsquery"
    testcase2 = ""
    testcase3 = ""
    testcase = "dns Query with ble"
    with DNSThread(wifi_dut, wifi_access_point, wifi_sniffer, testcase1=testcase1, testcase2=testcase2,
                   testcase3=testcase3, testcase=testcase), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_threading_sta_ble_dns_C20234(wifi_dut, wifi_access_point, wifi_sniffer, ble_client ):
    mode = "ble_slave"
    testcase1 = ""
    testcase2 = "dnswrongip"
    testcase3 = ""
    testcase = "dns wrong ip with ble"
    with DNSThread(wifi_dut, wifi_access_point, wifi_sniffer, testcase1=testcase1, testcase2=testcase2,
                   testcase3=testcase3, testcase=testcase), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_threading_sta_ble_dns_C20233(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
    mode = "ble_slave"
    testcase1 = ""
    testcase2 = ""
    testcase3 = "dnsstatic"
    testcase = "dns static with ble connection"
    with DNSThread(wifi_dut, wifi_access_point, wifi_sniffer, testcase1=testcase1, testcase2=testcase2,
                   testcase3=testcase3, testcase=testcase), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_threading_httpgetpostfunctionality_ble_C20347(wifi_dut, wifi_access_point, http_server, index_path, ble_client, wifi_sniffer):
    mode = "ble_slave"
    testcase = "testcase for http get + post download with ble"
    with httpgetpostThread(wifi_dut, wifi_access_point, http_server, index_path, wifi_sniffer, testcase=testcase), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_threading_httpgetfunctionality_ble_C20339_C20235(wifi_dut, wifi_access_point, http_server, index_path, ble_client, wifi_sniffer):
    mode = "ble_slave"
    testcase = "testcase for http get download with ble"
    with httpgetThread(wifi_dut, wifi_access_point, http_server, index_path, wifi_sniffer, testcase=testcase), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_threading_httppostfunctionality_ble_C20340_C20236(wifi_dut, wifi_access_point, http_server, index_path, ble_client, wifi_sniffer):
    mode = "ble_slave"
    testcase = "testcase for http post download with ble"
    with httppostThread(wifi_dut, wifi_access_point, http_server, index_path, wifi_sniffer, testcase=testcase), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,

    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_threading_bgscan_ble_C20362(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, net_perf_client, protocol, ble_client):
    mode = "ble_master"
    testcase = "testcase for bgscan + ble connection"
    with bgscandatatransferThread(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, net_perf_client, protocol, testcase=testcase), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,

    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_threading_scan_bledeinit_C20326(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, net_perf_client, protocol, ble_client):
    mode = "ble_slave"
    testcase = "testcase for scan + ble_init_deinit"
    with WifidatatransferThread(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, net_perf_client, protocol, testcase=testcase), BleThread_initdeinit(wifi_dut, ble_client, mode):
        time.sleep(15)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.OpenMode
        | RS9116FeatureBitMap.PSKSecurity,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_threading_sta_ble_C20341(wifi_sniffer, wifi_dut, wifi_access_point,  wifi_client,  net_perf_client,  protocol, ble_client,
):
    mode = "ble_slave"
    testcase = "testcase for datatransfer + multiple ble connections(slave) "
    with WifidatatransferThread(
        wifi_sniffer,
        wifi_dut,
        wifi_access_point,
        wifi_client,
        net_perf_client,
        protocol,
        testcase=testcase,
    ), BleThread_Multipleconnection(wifi_dut, ble_client, mode):
        time.sleep(15)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN |  RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
        },
    )
@pytest.mark.http_server("raspi_lighttpd_tls")
def test_threading_sta_ble_C20238(wifi_dut,  wifi_access_point, http_server, wifi_client, wifi_sniffer,  ble_client):
    mode = "ble_slave"
    testcase = "sta + ble connection as a slave"
    with otafthread(wifi_dut, wifi_access_point, http_server, wifi_client, wifi_sniffer, testcase=testcase), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


