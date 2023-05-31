import pytest
import time
import re
from datetime import datetime, date
from utf.utils.time_measurer import TimeMeasurer
import ipaddress
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping, print_dict
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.interfaces.wifi import WlanError
import random
import string
from random import randint
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116PowerSaveModes, RS9116PowerSaveProcedureTypes, RS9116TCPIPFeatureBitMap, RS9116CustomFeatureBitMap, \
    RS9116ExtCustomFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116OperatingMode, RS9116Band, SocketOptions, \
    SocketType, Cipher, DeviceConstants, RS9116StoreConfiguration
from utf import UtfDatabaseProperties


def logger():
    return get_logger(__name__)


"""
    Setup Requirement: DUT(RS9116) , EFR32, 1 Raspberry PI required,
    Raspi should be connected to AP and configured with static IP in ap page
    Access Point(Third Party AP'), Sniffer(NUC) , 
    Reported by Sairam & Pallavi
    Description:ip_conflict cases
"""


def wifi_client_join(wifi_client, wifi_access_point, dhcp_start="192.168.50.2", dhcp_end="192.168.50.80"):
    logger().info("associating raspi to wifi AP")
    wifi_client.interfaces.wifi.join(security="WPA2", ssid="IPConflict_Sil_916", passphrase="test1234", channel='8')
    wifi_client_ip = wifi_client.interfaces.wifi.get_ip_address()
    wifi_client_gateway_ip = wifi_client.interfaces.wifi.get_gateway_ip()
    logger().info("wifi_client ip: " + wifi_client_ip)
    wifi_client_start_ip = int(wifi_client_ip.split('.')[-1]) + 1
    logger().info(f"**** start IP wifi_client ip {wifi_client_start_ip}")
    dhcp_start_value = int(dhcp_start.split('.')[-1])
    dhcp_end_value = int(dhcp_end.split('.')[-1])
    logger().info(f"**** dhcp end value {dhcp_end_value}")
    dut_ip = wifi_client_ip
    if wifi_client_start_ip >= dhcp_end_value:
        value = randint(dhcp_start_value, wifi_client_start_ip - 2)
    else:
        value = randint(wifi_client_start_ip, dhcp_end_value)
    dut_ip = re.sub("\d{1,3}$", str(value), dut_ip)
    logger().info(f" dut ip is {dut_ip}")
    assert ipaddress.ip_address(wifi_client_ip) > ipaddress.IPv4Address(
        '169.254.255.255'), f"RASPI IP Address is static ip--{wifi_client_ip} hense test is terminating"
    return wifi_client_ip, dut_ip, wifi_client_gateway_ip


def wifi_dut_mac_address(wifi_dut):
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address is : {mac_address}")
    assert wifi_dut.interfaces.wifi.get_dut_mac_address() not in ["00:00:00:00:00:00", "", " ", None]
    return str(mac_address)


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


class cleanup_store_config():
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut

    def dut_recovery(self):
        tries = 0
        while tries < 3:
            tries += 1
            try:
                logger().info("Initiating reset for device cleanup")
                self.wifi_dut.interfaces.wifi.reset_soft()
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.associated = True
                logger().info("Initializing the DUT")
                self.wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9, retries=1)
                time.sleep(10)
                return True
            except:
                logger().info("clean up process failed ,retrying for 3 times")
                # if tries==2:
                #     return

    def disconnect(self):
        try:
            logger().info("Initiating disconnect for cleanup")
            self.wifi_dut.interfaces.wifi.leave()
            time.sleep(5)
            logger().info("cfg disable")
            # Enables the store configuration
            self.wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
            return True
        except:
            logger().info("clean up process failed")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_static_ip_assignment_with_existing_ip_C101962(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client,
                                                       utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        capture_file = "test_static_ip_assignment_with_existing_ip_C101962"
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        logger().info(f" dhcp_start {dhcp_start} and dhcp_end value {dhcp_end}")

        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")

        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_static_ip_assignment_with_existing_ip_C101962')
        logger().info(f"=========== configured the sniffer on {channel} on NUC with file name {capture_file}")
        time.sleep(3)

        result = wifi_dut_mac_address(wifi_dut)
        logger().info(f" DUT_mac_address is: {result}")
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("============ ip address sending ================")
        time.sleep(10)
        interface = wifi_client.interfaces.wifi.config["interface"]
        try:
            rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {interface} up")
            assert rc == 0
            logger().info(f"\n{stdout}\n")
        except:
            time.sleep(10)
        logger().info(f" Interface is {interface}")
        ip = wifi_client.interfaces.wifi.get_ip_address(network_interface=interface)
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                                      static_ip=ip,
                                                                      static_subnet="255.255.255.0",
                                                                      static_gateway=ap_ip, timeout=60,
                                                                      vap_id=0)
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
        logger().info(f"Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                         f'wlan.sa == {result} and wlan.da == ff:ff:ff:ff:ff:ff ' \
                         f'and arp.proto.type == 0x0800'
        packet_filter2 = 'Address Resolution Protocol (ARP Announcement)'
        time.sleep(2)
        logger().info(f"Sniffer validation for ARP packets")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"Decryption key is {decryption_key}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)

    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_static_ip_assignment_to_DUT_C101963(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        capture_file = "test_static_ip_assignment_to_DUT_C101963"
        file_name = "test_static_ip_assignment_to_DUT_C101963"
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        logger().info(f" dhcp_start {dhcp_start} and dhcp_end value {dhcp_end}")
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = wifi_client_join(wifi_client, wifi_access_point, dhcp_start,
                                                                          dhcp_end)
        logger().info(f" dut ip checking {dut_ip}")
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")

        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_static_ip_assignment_to_DUT_C101963')
        logger().info(f"=========== configured the sniffer on {channel} on NUC with file name {capture_file}")
        time.sleep(3)
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address is : {mac_address}")
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("============ ip address sending ================")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                         static_ip=dut_ip,
                                                         static_subnet="255.255.255.0",
                                                         static_gateway=wifi_client_gateway_ip, timeout=40, vap_id=0)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'Device is {device_ip}')
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'dhcp_start': '192.168.50.60',
        'dhcp_end': '192.168.50.80',
        'dhcp_lease': '3600'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_Dynamic_ip_assignment_to_DUT_C101964(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        capture_file = "test_Dynamic_ip_assignment_to_DUT_C101964"
        file_name = "test_Dynamic_ip_assignment_to_DUT_C101964"
        wifi_dut.interfaces.wifi.associated = False
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        logger().info(f" dhcp_start {dhcp_start} and dhcp_end value {dhcp_end}")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")

        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Dynamic_ip_assignment_to_DUT_C101964')
        logger().info(f"=========== configured the sniffer on {channel} on NUC with file name {capture_file}")
        time.sleep(3)
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address is : {mac_address}")
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'Device is {device_ip}')
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_static_ip_assignment_with_and_Without_ip_Conflict_to_DUT_C101965(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                          wifi_client, utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        capture_file = "test_static_ip_assignment_with_and_Without_ip_Conflict_to_DUT_C101965"
        wifi_dut.interfaces.wifi.associated = False
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        logger().info(f" dhcp_start {dhcp_start} and dhcp_end value {dhcp_end}")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=capture_file)
        time.sleep(3)
        interface = wifi_client.interfaces.wifi.config["interface"]
        try:
            rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {interface} up")
            assert rc == 0
            logger().info(f"\n{stdout}\n")
        except:
            time.sleep(10)
        logger().info(f" Interface is {interface}")
        ip = wifi_client.interfaces.wifi.get_ip_address(network_interface=interface)
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        result = wifi_dut_mac_address(wifi_dut)
        logger().info(f" DUT_mac_address is: {result}")
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("sending static ip configuration address")
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                                      static_ip=ip,
                                                                      static_subnet="255.255.255.0",
                                                                      static_gateway=ap_ip, timeout=40,
                                                                      vap_id=0)
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
        wifi_client.interfaces.wifi.config["interface"] = "wlan0"
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = wifi_client_join(wifi_client, wifi_access_point, dhcp_start,
                                                                          dhcp_end)

        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                         static_ip=dut_ip,
                                                         static_subnet="255.255.255.0",
                                                         static_gateway=wifi_client_gateway_ip, timeout=40, vap_id=0)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="36000")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 6,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_Dynamic_ip_assignment_with_and_Without_ip_Conflict_to_DUT_C101966(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                           wifi_client, utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        capture_file = "test_Dynamic_ip_assignment_with_and_Without_ip_Conflict_to_DUT_C101966"
        wifi_dut.interfaces.wifi.associated = False
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(3), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="120")
        logger().info(f" dhcp_start {dhcp_start} and dhcp_end value {dhcp_end}")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_Dynamic_ip_assignment_with_and_Without_ip_Conflict_to_DUT_C101966')
        time.sleep(3)
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address is : {mac_address}")
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("sending dynamic ip configuration address")
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.start_ip()
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF9C, "The 0xFF9C Error is expected for this test"
        logger().info("executing the except block and adding dhcp settings")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(253), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        time.sleep(10)
        for retry_count in range(5):
            try:
                wifi_dut.interfaces.wifi.start_ip()
                device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            except Exception as err:
                logger().info(
                    f"Failed to get dhcp ip..retry_count{retry_count + 1}\nException:{err}"
                )
                time.sleep(10)
        for retry_count in range(5):
            try:
                logger().info(f"DUT ip {device_ip}")
                logger().info("pinging to dut.....")
                status = ping(device_ip, ping_count)
                assert status, "DUT not responding for ping request......"
                logger().info("ping to DUT is successful....")
                break
            except Exception as err:
                logger().info(
                    f"Failed to ping to DUT...retry_count{retry_count + 1}\nException:{err}"
                )
                time.sleep(10)
        assert status, "DUT not responding for ping request......"
        logger().info(f"ping is successful")
        time.sleep(2)
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="36000")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
@pytest.mark.config('wifi_access_point',
                    wifi={'ssid': 'IPConflict_Sil_916', 'security': 'WPA2', 'passphrase': 'test1234', 'channel': 8})
def test_Dynamic_IP_Assignment_when_DHCP_Pool_Exhausted_C101969(wifi_sniffer,
                                                                wifi_dut,
                                                                wifi_access_point, utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        capture_file = "test_Dynamic_IP_Assignment_when_DHCP_Pool_Exhausted_C101969"
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(3), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        wifi_dut.interfaces.wifi.associated = False
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file)
        time.sleep(3)
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("============ ip address sending ================")
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.start_ip()
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF9C, "The 0xFF9C Error is expected for this test"
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_TCP_Tx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101974(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                    wifi_client, net_perf_client, protocol,
                                                                    utf_constants,
                                                                    rs_helper):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        capture_file = "test_TCP_Tx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101974"
        file_name = "test_TCP_Tx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101974"
        wifi_dut.interfaces.wifi.associated = False
        interface = wifi_client.interfaces.wifi.config['interface']
        logger().info(f"Checking the interface {interface}")
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(24), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        logger().info(f" dhcp_start {dhcp_start} and dhcp_end value {dhcp_end}")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_TCP_Tx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101974')
        time.sleep(3)
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = wifi_client_join(wifi_client, wifi_access_point, dhcp_start,
                                                                          dhcp_end)
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        result = wifi_dut_mac_address(wifi_dut)
        logger().info(f" DUT_mac_address is: {result}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address(network_interface=interface)
        logger().info(f'Fetching the host ip address...{host_ip}')
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("sending static ipconfiguration address")
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                                      static_ip=wifi_client_ip,
                                                                      static_subnet="255.255.255.0",
                                                                      static_gateway=wifi_client_gateway_ip, timeout=40,
                                                                      vap_id=0)
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
        logger().info(f"** set IP in static mode **")
        time.sleep(10)
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                         static_ip=dut_ip,
                                                         static_subnet="255.255.255.0",
                                                         static_gateway=wifi_client_gateway_ip, timeout=40, vap_id=0)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        for retry_count in range(5):
            try:
                logger().info(f"DUT ip {device_ip}")
                logger().info("pinging to dut.....")
                status = ping(device_ip, ping_count)
                assert status, "DUT not responding for ping request......"
                logger().info("ping to DUT is successful....")
                break
            except Exception as err:
                logger().info(
                    f"Failed to ping to DUT...retry_count{retry_count + 1}\nException:{err}"
                )
                time.sleep(10)
        assert status, "DUT not responding for ping request......"
        time.sleep(2)
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="36000")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_custom_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_TCP_Rx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101975(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                    wifi_client, net_perf_client, protocol,
                                                                    utf_constants, rs_helper):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        capture_file = "test_TCP_Rx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101975"
        wifi_dut.interfaces.wifi.associated = False
        interface = wifi_client.interfaces.wifi.config['interface']
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(24), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        logger().info(f" dhcp_start {dhcp_start} and dhcp_end value {dhcp_end}")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_TCP_Rx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101975')
        time.sleep(3)
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = wifi_client_join(wifi_client, wifi_access_point, dhcp_start,
                                                                          dhcp_end)
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        result = wifi_dut_mac_address(wifi_dut)
        logger().info(f" DUT_mac_address is: {result}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address(network_interface=interface)
        logger().info(f'Fetching the host ip address...{host_ip}')
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("sending static ipconfiguration address")
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                                      static_ip=wifi_client_ip,
                                                                      static_subnet="255.255.255.0",
                                                                      static_gateway=wifi_client_gateway_ip, timeout=40,
                                                                      vap_id=0)
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                         static_ip=dut_ip,
                                                         static_subnet="255.255.255.0",
                                                         static_gateway=wifi_client_gateway_ip, timeout=40, vap_id=0)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        time.sleep(2)
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="RX")
        wifi_dut.interfaces.wifi.leave()
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="36000")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_UDP_Tx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101976(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                    wifi_client, net_perf_client, protocol, rs_helper,
                                                                    utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        wifi_dut.interfaces.wifi.associated = False
        interface = wifi_client.interfaces.wifi.config['interface']
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(24), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        logger().info(f" dhcp_start {dhcp_start} and dhcp_end value {dhcp_end}")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_UDP_Tx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101976')
        time.sleep(3)
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = wifi_client_join(wifi_client, wifi_access_point, dhcp_start,
                                                                          dhcp_end)
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        result = wifi_dut_mac_address(wifi_dut)
        logger().info(f" DUT_mac_address is: {result}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address(network_interface=interface)
        logger().info(f'Fetching the host ip address...{host_ip}')
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("sending static ipconfiguration address")
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                                      static_ip=wifi_client_ip,
                                                                      static_subnet="255.255.255.0",
                                                                      static_gateway=wifi_client_gateway_ip, timeout=40,
                                                                      vap_id=0)
            logger().info(f"result {result}")
        assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                         static_ip=dut_ip,
                                                         static_subnet="255.255.255.0",
                                                         static_gateway=wifi_client_gateway_ip, timeout=40, vap_id=0)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        for retry_count in range(5):
            try:
                logger().info(f"DUT ip {device_ip}")
                logger().info("pinging to dut.....")
                status = ping(device_ip, ping_count)
                assert status, "DUT not responding for ping request......"
                logger().info("ping to DUT is successful....")
                break
            except Exception as err:
                logger().info(
                    f"Failed to ping to DUT...retry_count{retry_count + 1}\nException:{err}"
                )
                time.sleep(10)
        assert status, "DUT not responding for ping request......"
        time.sleep(2)
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="36000")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_UDP_Rx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101977(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                    wifi_client, net_perf_client, protocol, rs_helper,
                                                                    utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        capture_file = "test_UDP_Rx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101977"
        file_name = "test_UDP_Rx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101977"
        wifi_dut.interfaces.wifi.associated = False
        interface = wifi_client.interfaces.wifi.config['interface']
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(24), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        logger().info(f" dhcp_start {dhcp_start} and dhcp_end value {dhcp_end}")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_UDP_Rx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101977')
        time.sleep(3)
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = wifi_client_join(wifi_client, wifi_access_point, dhcp_start,
                                                                          dhcp_end)
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        result = wifi_dut_mac_address(wifi_dut)
        logger().info(f" DUT_mac_address is: {result}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address(network_interface=interface)
        logger().info(f'Fetching the host ip address...{host_ip}')
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("sending static ipconfiguration address")
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                                      static_ip=wifi_client_ip,
                                                                      static_subnet="255.255.255.0",
                                                                      static_gateway=wifi_client_gateway_ip, timeout=40,
                                                                      vap_id=0)
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                         static_ip=dut_ip,
                                                         static_subnet="255.255.255.0",
                                                         static_gateway=wifi_client_gateway_ip, timeout=40, vap_id=0)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        timeout = 60
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="RX")
        wifi_dut.interfaces.wifi.leave()
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="36000")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "set_send_feature_frame": 1,
        "ca_cert": "ca-chain.cert.pem",
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_SSL_Tx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101978(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                    wifi_client, ssl_server, utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        pkt_count = 30000
        buffer_length = 1370
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        bytes_sent = (pkt_count * buffer_length)
        capture_file = "test_SSL_Tx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101978"
        file_name = "test_SSL_Tx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101978"
        wifi_dut.interfaces.wifi.associated = False
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        logger().info(f" dhcp_start {dhcp_start} and dhcp_end value {dhcp_end}")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_SSL_Tx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101978')
        time.sleep(3)
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = wifi_client_join(wifi_client, wifi_access_point, dhcp_start,
                                                                          dhcp_end)
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        result = wifi_dut_mac_address(wifi_dut)
        logger().info(f" DUT_mac_address is: {result}")
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("sending static ip configuration address")
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                                      static_ip=wifi_client_ip,
                                                                      static_subnet="255.255.255.0",
                                                                      static_gateway=wifi_client_gateway_ip, timeout=40,
                                                                      vap_id=0)
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                         static_ip=dut_ip,
                                                         static_subnet="255.255.255.0",
                                                         static_gateway=wifi_client_gateway_ip, timeout=40, vap_id=0)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        ssl_server.interfaces.ssl.start_server()
        logger().info(f"###Open ssl client socket in the DUT###")
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        logger().info(f"# Enable ssl option for socket opened")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        local_port = randint(5001, 60000)
        logger().info(f"*******Socket binds at device_ip with port 5001 in DUT*****")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        logger().info(f"****ssl socket opened in DUT connects to the server****")
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

        logger().info(f"****API returns 100 bytes of random data*****")
        data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        data_length = len(data_sent)
        logger().info(f"Sending data {data_sent} over socket_no->{sock}")
        logger().info(f" ******DUT sends 100 bytes of data over ssl socket*********")
        wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
        server_socket_no = 1
        logger().info(f"***####SSL server receives the data over ssl socket****####")
        data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
        logger().info(f"Data received on remote socket opened is {data_receive}")
        assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
        logger().info("Data sent by DUT and received on server is matching")

        if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
            ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
        result = wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
        logger().info(f"Number of bytes sent by dut {result}")
        bytes_sent = result

        bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)

        logger().info(
            f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")

        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger().info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        time.sleep(2)
        wifi_dut.interfaces.wifi.leave()
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(10)
        wifi_dut.interfaces.wifi.inited = False


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "set_send_feature_frame": 1,
        "ca_cert": "ca-chain.cert.pem",
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_SSL_Rx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101979(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                    wifi_client, ssl_server, utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        pkt_count = 30000
        buffer_length = 1370
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        bytes_sent = (pkt_count * buffer_length)
        capture_file = "test_SSL_Rx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101979"
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(24), ap_ip)
        wifi_dut.interfaces.wifi.associated = False
        wifi_access_point.interfaces.wifi.enable_dhcp_ap()
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_SSL_Rx_Once_IP_Conflict_resolved_in_Static_IP_Mode_C101979')
        time.sleep(3)
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = wifi_client_join(wifi_client, wifi_access_point, dhcp_start,
                                                                          dhcp_end)
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        result = wifi_dut_mac_address(wifi_dut)
        logger().info(f" DUT_mac_address is: {result}")
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("sending static ipconfiguration address")
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                                      static_ip=wifi_client_ip,
                                                                      static_subnet="255.255.255.0",
                                                                      static_gateway=wifi_client_gateway_ip, timeout=40,
                                                                      vap_id=0)
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                         static_ip=dut_ip,
                                                         static_subnet="255.255.255.0",
                                                         static_gateway=wifi_client_gateway_ip, timeout=40, vap_id=0)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        ssl_server.interfaces.ssl.start_server()
        wifi_dut.interfaces.wifi.socket_config(total_sockets=1, total_tcp_sockets=1, total_udp_sockets=0,
                                               tcp_tx_only_sockets=0,
                                               tcp_rx_only_sockets=1, udp_tx_only_sockets=0, udp_rx_only_sockets=0,
                                               tcp_rx_high_performance_sockets=1, tcp_rx_window_size_cap=44,
                                               tcp_rx_window_div_factor=10)
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_ENABLE,
                                                               socket_flag=SocketType.ASYNCHRONOUS)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        logger().info(f" *****# Enable ssl option for socket opened *****#")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, 38,
                                                   128)

        local_port = randint(5001, 60000)
        logger().info(f"#*****Socket binds with device_ip and Port number 5001 in DUT****#")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        logger().info(f"#****ssl socket opened in DUT connects to the server****#")
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
        server_socket_no = 1
        pkt_count = 50000
        duration = 60
        with TimeMeasurer() as t:
            ssl_server.interfaces.ssl.send_data_socket(server_socket_no, pkt_count, msg_length=buffer_length,
                                                       duration=duration)
        time_duration = t.duration
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger().info("Successfully closed opened socket in the DUT")
        bytes_sent = ssl_server.interfaces.ssl.data_send_stats(server_socket_no)
        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
        bytes_received = int(result.split(b":")[1])
        logger().info(f"bytes sent by remote peer -> {bytes_sent}")
        logger().info(f"bytes received on socket {sock} -> {bytes_received}")
        logger().info(f"SSL rx throughput ->  {(bytes_received * 8) / (1000 * 1000 * time_duration)} Mbps")
        ssl_server.interfaces.ssl.stop_server()
        time.sleep(5)
        wifi_dut.interfaces.wifi.leave()
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(10)
        wifi_dut.interfaces.wifi.inited = False
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="36000")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
# @pytest.mark.config(
#     "wifi_client",
#     wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
#           "interface": "wlan0"}
# )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_static_ip_ip_conflict_with_multiple_times_in_loop_C101980(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                   wifi_client, utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        loop_count = 5
        capture_file = "test_static_ip_ip_conflict_with_multiple_times_in_loop_C101980"
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        # wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
        #                                                  dhcp_lease="3600")
        # wifi_client_ip, dut_ip, wifi_client_gateway_ip = wifi_client_join(wifi_client, wifi_access_point, dhcp_start,
        #                                                                   dhcp_end)
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")

        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_static_ip_ip_conflict_with_multiple_times_in_loop_C101980')
        logger().info(f"=========== configured the sniffer on {channel} on NUC with file name {capture_file}")
        time.sleep(3)
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address is : {mac_address}")
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        interface = wifi_client.interfaces.wifi.config["interface"]
        try:
            rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {interface} up")
            assert rc == 0
            logger().info(f"\n{stdout}\n")
        except:
            time.sleep(10)
        logger().info(f" Interface is {interface}")
        ip = wifi_client.interfaces.wifi.get_ip_address(network_interface=interface)
        logger().info("============ ip address sending ================")
        for i in range(0, loop_count):
            with pytest.raises(WlanError) as exc_info:
                result = wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                                          static_ip=ip,
                                                                          static_subnet="255.255.255.0",
                                                                          static_gateway=ap_ip,
                                                                          timeout=40,
                                                                          vap_id=0)
                logger().info(f"result : {result}")
            assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(10)
        wifi_dut.interfaces.wifi.inited = False
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="36000")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.store_config
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_ip_conflict_detection_during_auto_join_C101983(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client,
                                                        utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        capture_file = "test_ip_conflict_detection_during_auto_join_C101983"
        file_name = "test_ip_conflict_detection_during_auto_join_C101983"
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(5), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")

        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_ip_conflict_detection_during_auto_join_C101983')
        logger().info(f"=========== configured the sniffer on {channel} on NUC with file name {capture_file}")
        time.sleep(3)
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address is : {mac_address}")
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("============ ip address sending ================")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                         static_ip="192.168.50.63",
                                                         static_subnet="255.255.255.0",
                                                         static_gateway="192.168.50.1", timeout=40, vap_id=0)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'Device is {device_ip}')
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        logger().info("Enable Auto Configuration")
        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)
        logger().info("Initiating wireless de init")
        wifi_dut.interfaces.wifi.wireless_deinit()
        time.sleep(20)
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = wifi_client_join(wifi_client, wifi_access_point, dhcp_start,
                                                                          dhcp_end)
        logger().info(f"Wifi client device IP is {wifi_client_ip}")
        time.sleep(10)
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=0)
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        logger().info(f"Exception: {str(Ex)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(Ex)) or ("0xFFFFFFE2" in str(Ex)) or ("0xFFFFFFD5" in str(Ex)):
            clean_up.dut_recovery()
        clean_up.disconnect()
    finally:
        clean_up = cleanup_store_config(wifi_dut)
        clean_up.dut_recovery()
        clean_up.disconnect()
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(10)
        wifi_dut.interfaces.wifi.inited = False
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="36000")


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
@pytest.mark.config('wifi_access_point',
                    wifi={'ssid': 'IPConflict_Sil_916', 'security': 'WPA2', 'passphrase': 'test1234', 'channel': 8})
def test_IP_Conflict_Detection_When_DHCP_Fails_C101985(wifi_sniffer,
                                                       wifi_dut, wifi_client,
                                                       wifi_access_point, utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        capture_file = "test_IP_Conflict_Detection_When_DCHP_Fails_C101985"
        file_name = "test_IP_Conflict_Detection_When_DCHP_Fails_C101985"
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = wifi_client_join(wifi_client, wifi_access_point, dhcp_start,
                                                                          dhcp_end)
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        wifi_dut.interfaces.wifi.associated = False
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file)
        time.sleep(3)
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("============ ip address sending ================")
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.start_ip()
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF9C, "The 0xFF9C Error is expected for this test"
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                                      static_ip=wifi_client_ip,
                                                                      static_subnet="255.255.255.0",
                                                                      static_gateway=wifi_client_gateway_ip, timeout=40,
                                                                      vap_id=0)
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(10)
        wifi_dut.interfaces.wifi.inited = False
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="36000")


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
        "pll_mode": 0,
        "rf_type": 1,
        "wireless_mode": 0,
        "enable_ppp": 0,
        "afe_type": 1,
        "features_enable": 49,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.dut("rs9116")
@pytest.mark.AT
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_static_ip_assignment_in_at_mode_with_and_Without_ip_Conflict_to_DUT_C101982(wifi_sniffer, wifi_dut,
                                                                                     wifi_access_point,
                                                                                     wifi_client, utf_constants):
    try:
        validation = False
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        capture_file = "test_static_ip_assignment_in_at_mode_with_and_Without_ip_Conflict_to_DUT_C101982"
        wifi_dut.interfaces.wifi.associated = False
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(24), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_static_ip_assignment_in_at_mode_with_and_Without_ip_Conflict_to_DUT_C101982')
        time.sleep(3)
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = wifi_client_join(wifi_client, wifi_access_point, dhcp_start,
                                                                          dhcp_end)
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        result = wifi_dut_mac_address(wifi_dut)
        logger().info(f" DUT_mac_address is: {result}")
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("sending static ipconfiguration address")
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                                      static_ip=wifi_client_ip,
                                                                      static_subnet="255.255.255.0",
                                                                      static_gateway=wifi_client_gateway_ip, timeout=40,
                                                                      vap_id=0)
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
        ip_address = wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                                      static_ip=dut_ip,
                                                                      static_subnet="255.255.255.0",
                                                                      static_gateway=wifi_client_gateway_ip, timeout=40,
                                                                      vap_id=0)
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_address)
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(10)
        wifi_dut.interfaces.wifi.inited = False
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="36000")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19312", "passphrase": "12345678", "channel": 8

    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_static_ip_assignment_when_dut_in_concurrent_Mode_C101967(firmware_loader, wifi_sniffer,
                                                                  wifi_dut,
                                                                  wifi_access_point, wifi_client, utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        capture_file = "test_static_ip_assignment_when_dut_in_concurrent_Mode_C101967"
        file_name = "test_static_ip_assignment_when_dut_in_concurrent_Mode_C101967"
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        logger().info(f" dhcp_start {dhcp_start} and dhcp_end value {dhcp_end}")
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = wifi_client_join(wifi_client, wifi_access_point, dhcp_start,
                                                                          dhcp_end)
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        wifi_dut.interfaces.wifi.associated = False
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_static_ip_assignment_when_dut_in_concurrent_Mode_C101967')
        time.sleep(3)
        ##### preparing wifi_dut as access point - AP Mode
        logger().info(f"starting RSI_DUT as ACCESS Point in channel no {channel}")
        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'ap mac is {ap_mac}')
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        logger().info("Bringing up DUT in AP mode")
        wifi_dut.interfaces.wifi.start_ap(ssid="RS9116_AP_C101967", security="WPA2", passphrase="12345678", channel=8)
        time.sleep(10)
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("============ ip address sending ================")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                         static_ip=dut_ip,
                                                         static_subnet="255.255.255.0",
                                                         static_gateway=wifi_client_gateway_ip, timeout=40, vap_id=0)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(10)
        wifi_dut.interfaces.wifi.inited = False


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19312", "passphrase": "12345678", "channel": 8

    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_Dynamic_IP_Assignment_when_dut_in_concurrent_Mode_C101973(firmware_loader, wifi_sniffer,
                                                                   wifi_dut,
                                                                   wifi_access_point, wifi_client, utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        capture_file = "test_Dynamic_IP_Assignment_when_dut_in_concurrent_Mode_C101973"
        file_name = "test_Dynamic_IP_Assignment_when_dut_in_concurrent_Mode_C101973"
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        logger().info(f" dhcp_start {dhcp_start} and dhcp_end value {dhcp_end}")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        wifi_dut.interfaces.wifi.associated = False
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file)
        time.sleep(3)
        ##### preparing wifi_dut as access point - AP Mode
        logger().info(f"starting RSI_DUT as ACCESS Point in channel no {channel}")
        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'ap mac is {ap_mac}')
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        logger().info("Bringing up DUT in AP mode")
        wifi_dut.interfaces.wifi.start_ap(ssid="RS9116_AP_C101973", security="WPA2", passphrase="12345678", channel=8)
        time.sleep(10)
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("============ ip address sending ================")
        wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(10)
        wifi_dut.interfaces.wifi.inited = False


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19312", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_Dynamic_IP_assignment_when_DHCP_Pool_Exhausted_in_concurrent_Mode_C101972(firmware_loader, wifi_sniffer,
                                                                                   wifi_dut,
                                                                                   wifi_access_point, wifi_client,
                                                                                   utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        capture_file = "test_Dynamic_IP_assignment_with_and_without_ip_Conflict_in_concurrent_Mode_C101972"
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(3), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        # wifi_client_join(wifi_client, wifi_access_point)
        dut_mac_address = wifi_dut_mac_address(wifi_dut)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        wifi_dut.interfaces.wifi.associated = False
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file)
        time.sleep(3)
        ##### preparing wifi_dut as access point - AP Mode
        logger().info(f"starting RSI_DUT as ACCESS Point in channel no {channel}")
        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'ap mac is {ap_mac}')
        time.sleep(10)
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        time.sleep(10)
        logger().info("Bringing up DUT in AP mode")
        wifi_dut.interfaces.wifi.start_ap(ssid="RS9116_AP_C101972", security="WPA2", passphrase="12345678", channel=8)
        time.sleep(10)
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("============ ip address sending ================")
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.start_ip()
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF9C, "The 0xFF9C Error is expected for this test"
        # wifi_client.interfaces.wifi.leave()
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        time.sleep(60)  # waiting for 60 seconds to rejoin
        for ip_count in range(4):
            try:
                ip_config = wifi_dut.interfaces.wifi.start_ip()
                assert isinstance(ip_config,
                                  wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {ip_config}"
                dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                break
            except:
                logger().info(f"Get IP address through dhcp process is failed. retry count -> {ip_count + 1}")
                time.sleep(10)
        assert dut_ip, "ip setting in DUT has failed"
        logger().info(f'DUT ip {dut_ip}')
        status = ping(dut_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(10)
        wifi_dut.interfaces.wifi.inited = False
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C101971", "passphrase": "12345678", "channel": 8

    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_Dynamic_IP_assignment_with_and_without_ip_Conflict_in_concurrent_Mode_C101971(firmware_loader, wifi_sniffer,
                                                                                       wifi_dut,
                                                                                       wifi_access_point, wifi_client,
                                                                                       utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        capture_file = "test_Dynamic_IP_assignment_with_and_without_ip_Conflict_in_concurrent_Mode_C101971"
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(3), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        # wifi_client_join(wifi_client, wifi_access_point)
        dut_mac_address = wifi_dut_mac_address(wifi_dut)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        wifi_dut.interfaces.wifi.associated = False
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file)
        time.sleep(3)
        ##### preparing wifi_dut as access point - AP Mode
        logger().info(f"starting RSI_DUT as ACCESS Point in channel no {channel}")
        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'ap mac is {ap_mac}')
        time.sleep(10)
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        time.sleep(10)
        logger().info("Bringing up DUT in AP mode")
        wifi_dut.interfaces.wifi.start_ap(ssid="RS9116_AP_C101971", security="WPA2", passphrase="12345678", channel=8)
        time.sleep(10)
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("============ ip address sending ================")
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.start_ip()
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF9C, "The 0xFF9C Error is expected for this test"
        # wifi_client.interfaces.wifi.leave()
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        time.sleep(60)  # waiting for 60 seconds to rejoin
        for ip_count in range(4):
            try:
                ip_config = wifi_dut.interfaces.wifi.start_ip()
                assert isinstance(ip_config,
                                  wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {ip_config}"
                dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                break
            except:
                logger().info(f"Get IP address through dhcp process is failed. retry count -> {ip_count + 1}")
                time.sleep(10)
        assert dut_ip, "ip setting in DUT has failed"
        logger().info(f'DUT ip {dut_ip}')
        status = ping(dut_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(10)
        wifi_dut.interfaces.wifi.inited = False
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(254), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19312", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_static_ip_with_and_without_ipconflict_when_dut_in_concurrent_Mode_C101970(firmware_loader, wifi_sniffer,
                                                                                   wifi_dut,
                                                                                   wifi_access_point, wifi_client,
                                                                                   utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        capture_file = "test_static_ip_with_and_without_ipconflict_when_dut_in_concurrent_Mode_C101970"
        file_name = "test_static_ip_with_and_without_ipconflict_when_dut_in_concurrent_Mode_C101970"
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(24), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        logger().info(f" dhcp_start {dhcp_start} and dhcp_end value {dhcp_end}")
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = wifi_client_join(wifi_client, wifi_access_point, dhcp_start,
                                                                          dhcp_end)
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        wifi_dut.interfaces.wifi.associated = False
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file)
        time.sleep(3)
        ##### preparing wifi_dut as access point - AP Mode
        logger().info(f"starting RSI_DUT as ACCESS Point in channel no {channel}")
        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'ap mac is {ap_mac}')
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        logger().info("Bringing up DUT in AP mode")
        wifi_dut.interfaces.wifi.start_ap(ssid="RS9116_AP_C101970", security="WPA2", passphrase="12345678", channel=8)
        time.sleep(20)
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        logger().info("============ ip address sending ================")
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                                      static_ip=wifi_client_ip,
                                                                      static_subnet="255.255.255.0",
                                                                      static_gateway=wifi_client_gateway_ip, timeout=40,
                                                                      vap_id=0)
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                         static_ip=dut_ip,
                                                         static_subnet="255.255.255.0",
                                                         static_gateway=wifi_client_gateway_ip, timeout=40, vap_id=0)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C101968", "passphrase": "12345678", "channel": 8

    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'RS9116_AP_C101968',
        'security': 'WPA2',
        'passphrase': '12345678',
        'channel': 8,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_static_ip_assignment_with_ip_conflict_in_concurrent_Mode_C101968(firmware_loader, wifi_sniffer,
                                                                          wifi_dut,
                                                                          wifi_access_point, wifi_client,
                                                                          utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        capture_file = "test_static_ip_assignment_with_ip_conflict_in_concurrent_Mode_C101968"
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(24), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        logger().info(f" dhcp_start {dhcp_start} and dhcp_end value {dhcp_end}")
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = wifi_client_join(wifi_client, wifi_access_point)
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        wifi_dut.interfaces.wifi.associated = False
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file)
        time.sleep(3)
        ##### preparing wifi_dut as access point - AP Mode
        logger().info(f"starting RSI_DUT as ACCESS Point in channel no {channel}")
        ap_mac = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'ap mac is {ap_mac}')
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        logger().info("Bringing up DUT in AP mode")
        wifi_dut.interfaces.wifi.start_ap(ssid="RS9116_AP_C101968", security="WPA2", passphrase="12345678", channel=8)
        time.sleep(20)
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("============ ip address sending ================")
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                                      static_ip=wifi_client_ip,
                                                                      static_subnet="255.255.255.0",
                                                                      static_gateway=wifi_client_gateway_ip, timeout=40,
                                                                      vap_id=0)
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(10)
        wifi_dut.interfaces.wifi.inited = False


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
        "pll_mode": 0,
        "rf_type": 1,
        "wireless_mode": 0,
        "enable_ppp": 0,
        "afe_type": 1,
        "features_enable": 49,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'IPConflict_Sil_916',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,

    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "IPConflict_Sil_916", "passphrase": "test1234", "channel": 8,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.dut("rs9116")
@pytest.mark.AT
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_client", wifi="disassociated")
def test_static_ip_ip_Conflict_in_at_mode_DUT_C101981(wifi_sniffer, wifi_dut, wifi_access_point,
                                                      wifi_client, utf_constants):
    try:
        validation = False
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        capture_file = "test_static_ip_ip_Conflict_in_at_mode_DUT_C101981"
        file_name = "test_static_ip_ip_Conflict_in_at_mode_DUT_C101981"
        wifi_dut.interfaces.wifi.associated = False
        # wifi_access_point.interfaces.wifi.enable_dhcp_ap()
        ap_ip = wifi_access_point.interfaces.wifi.ap_test_ip
        assert ap_ip, "Please Add the AP test ip in the ap section of harness"
        logger().info(f"AP Ip {ap_ip}")
        dhcp_start = re.sub("\d{1,3}$", str(2), ap_ip)
        dhcp_end = re.sub("\d{1,3}$", str(9), ap_ip)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start=dhcp_start, dhcp_end=dhcp_end,
                                                         dhcp_lease="3600")
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_static_ip_ip_Conflict_in_at_mode_DUT_C101981')
        time.sleep(3)
        wifi_client_ip, dut_ip, wifi_client_gateway_ip = wifi_client_join(wifi_client, wifi_access_point, dhcp_start,
                                                                          dhcp_end)
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        result = wifi_dut_mac_address(wifi_dut)
        logger().info(f" DUT_mac_address is: {result}")
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("sending static ipconfiguration address")
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode="static",
                                                                      static_ip=wifi_client_ip,
                                                                      static_subnet="255.255.255.0",
                                                                      static_gateway=wifi_client_gateway_ip, timeout=40,
                                                                      vap_id=0)
            logger().info(f"result : {result}")
        assert exc_info.value.error_code == 0xFF75, "The 0xFF75 Error is expected for this test"
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(10)
        wifi_dut.interfaces.wifi.inited = False
