import pytest
import datetime
from datetime import datetime
import re
import uuid
from typing import Dict
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping, get_host_ip
from utf.interfaces.wifi import WlanError
from utf.interfaces.bluetooth import BLEDeviceState
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
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes, RS9116PowerSaveProcedureTypes
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap,
    RS9116BTFeatureBitMap
)
from utf.utils.thread_base import ThreadBase
import threading
import time
import string
import random


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


def ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address=None):
    ble_client_address = None
    if ble_mode == "ble_master":
        logger().info(f"Set up DUT for BLE master role")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
        logger().info("Started BLE in DUT")
        assert ble_dut_address, f"Unable to fetch ble dut address"
        logger().info("Start ble client")
        ble_client.interfaces.bluetooth.close()
        time.sleep(3)
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
        assert ble_client_address, "Unable to get ble_client_address"
        time.sleep(5)
        logger().info("Start scanning and connect to ble client")
        wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        time.sleep(5)
        logger().info("Initiating BLE connection with ble_client")
        wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=120)
        logger().info("BLE Connection success")

    if ble_mode == "ble_slave":
        conn_params = {
            "min_conn_interval": 36,
            "max_conn_interval": 36,
            "conn_latency": 0,
            "supervision_timeout": 400}
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
        ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_address,
                                                min_conn_interval=conn_params["min_conn_interval"],
                                                max_conn_interval=conn_params["max_conn_interval"],
                                                conn_latency=conn_params["conn_latency"],
                                                supervision_timeout=conn_params["supervision_timeout"])
        logger().info("BLE Connection success")
        time.sleep(2)
    return ble_client_address, ble_dut_address


def dns_pkt_check(
        wifi_sniffer,
        logger,
        decryption_key: str,
        dut_mac_address,
        capture_filename,
) -> Dict[str, int]:
    current_time = time.time()
    dns_capture_list = []
    updated_capture_file = (
            "filter_"
            + capture_filename
            + "_"
            + str(datetime.fromtimestamp(current_time).strftime("%H_%M_%S"))
    )
    file_name = f"./reports/{updated_capture_file}.pcap"
    local_capture_file = file_name
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f"(wlan.addr == {dut_mac_address})"
    wifi_sniffer.interfaces.capture.shell(
        f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
        f"frame.number -w "
        f"{wlan_filter_file}"
    )
    with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
        sftp.get(wlan_filter_file, local_capture_file)
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
            capture_file_filter=local_capture_file,
    ):
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            if layer_name == "dns":
                dns_layer = str(layer)
                dns_capture_list.append(tuple([dns_layer, packet.sniff_timestamp]))
                logger().info(f"DNS layer {dns_layer}")
    return dns_capture_list


def ble_disconnect(wifi_dut, ble_address):
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_address, timeout=30)
    time.sleep(3)
    logger().info("Successfully disconnected from BLE SLAVE Device")


def wifi_leave(wifi_dut):
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave(timeout=60)
    logger().info(f"Leave completed in {t.duration} seconds")


def check_connection_status(wifi_dut, ble=False, wlan=False):
    if ble:
        logger().info("Checking connection status of BLE")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
        logger().info("DUT is not disconnected from BLE")

    if wlan:
        logger().info("Checking connection status of Wi-Fi")
        events = wifi_dut.interfaces.wifi.get_async_events()
        disconnect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Disconnect]
        count_disconnect = set()
        if len(disconnect_events):
            count_disconnect.add(str(disconnect_events[0]))
            logger().info(f"Disconnect Events:{count_disconnect}")
            assert False, f"DUT is not connected to Wi-Fi"
        assert len(disconnect_events) == 0
        logger().info(f"DUT is not disconnected from Wi-Fi during traffic run for long duration")


class Blethread(ThreadBase):
    def __init__(self, wifi_dut, ble_client, ble_mode=None, ble_dut_address=None, ble_address=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = ble_dut_address
        self.ble_mode = ble_mode
        self.ble_address = ble_address

    def run(self):
        ble_master_slave(self.wifi_dut, self.ble_client, self.ble_mode, ble_dut_address=None)
        ble_disconnect(self.wifi_dut, self.ble_address)


class WifiThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, wifi_Sniffer, utf_constants, bssid=None, dut_mac_address=None,
                 testcase=None, device_ip=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.utf_constants = utf_constants
        self.wifi_sniffer = wifi_Sniffer
        self.bssid = bssid
        self.device_ip = device_ip
        self.dut_mac_address = dut_mac_address
        self.testcase = testcase

    def join_get_ip(self):
        count_i = 4
        self.bssid = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {self.bssid}")
        for count in range(1, count_i):
            try:
                scan_fail = 1
                logger().info("Scanning to the Wifi Access Point")
                self.wifi_dut.interfaces.wifi.scan(channel=self.wifi_access_point.interfaces.wifi.channel,
                                                   ssid=None)
                scan_fail = 0
                break
            except:
                logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
                time.sleep(1)
        if scan_fail:
            logger().info(f"Scanning to the AP has failed")
            assert scan_fail == 0, "Scanning to the AP is failed"
        self.bssid = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {self.bssid}")
        for count in range(1, count_i):
            try:
                join_fail = 1
                logger().info("***************Joining to the Wifi Access Point*****************")
                self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
                join_fail = 0
                break
            except:
                logger().info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
                time.sleep(1)
        if join_fail:
            logger().info(f"Joining to the AP has failed")
            assert join_fail == 0, "Joining to the AP is failed"

        for count in range(1, count_i):
            try:
                ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
                self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
                logger().info(f"Found device ip: {self.device_ip}")
                break
            except:
                logger().info(f"Get IP address through dhcp process is failed...retry count -> {count}")
                time.sleep(1)
        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {self.dut_mac_address}")
        return self.bssid, self.dut_mac_address, self.device_ip

    def powersave_ping(self):
        ping_count = self.utf_constants.get("ping_count")
        logger().info(
            f"The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put")
        logger().info(f"DUT to power save in Wifi+bluetooth mode")
        enable_wifips = self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                 RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifips, f" unable to enable the wifips"
        enable_btps = self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                  RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_btps, f"unable to enable the btps"
        logger().info(f"Initiating ping to DUT ip {self.device_ip} after power save")
        status = ping(self.device_ip, ping_count)
        time.sleep(5)
        assert status == 1, "DUT not responding for ping request......"

    def sniffer_validation(self):
        validation = True
        packet_filter1 = f"wlan.addr=={self.dut_mac_address} && wlan.fc.type_subtype == 0 ||eapol"
        packet_filter2 = f"wlan.addr=={self.bssid} && wlan.fc.type_subtype == 1 ||eapol"
        logger().info(f"validate PS-POLL frame with PM bit set to '1'")
        packet_filter3 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x001a) and (wlan.ta == {self.dut_mac_address}) ' \
                         f'and (wlan.ra == {self.bssid}))'
        logger().info(f"validate QOS data frame with more data bit set to '1'")
        packet_filter4 = f' (wlan.fc.moredata == 1) and ((wlan.fc.type_subtype == 0x0028) and (wlan.ra == {self.dut_mac_address}) ' \
                         f'and (wlan.ta == {self.bssid}))'
        logger().info(
            f"Validating association, eapol from DUT"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find association, eapol sent from DUT in sniffer '
        logger().info(
            f"Validating association, eapol from AP"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find association, eapol sent from AP in sniffer '
        logger().info('Validating PS Poll frames are sent from the device with power management bit')
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Sniffer validation failed for ps-poll frame with PM bit 1'
        logger().info('Validating more data bit in QOS data frames')
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Sniffer validation failed for QOS data frame with more data bit 1'
        logger().info(
            f"Validating DHCP frames from AP & DUT"
        )
        logger().info("passing passphrase and ssid to decrypt dhcp packets")
        decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"decryption_key : {decryption_key}")
        logger().info("DHCP decryption is in progress...this may take some time")
        dhcp_list = self.wifi_sniffer.interfaces.capture.get_dhcp_list(self.dut_mac_address, decryption_key, ["dhcp"])
        logger().info(f"dhcp_list : {dhcp_list}")
        assert dhcp_list, "DHCP packets not found"


class DnsThread(ThreadBase):
    def __init__(self, wifi_dut, utf_constants, dns_mode=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.dns_mode = dns_mode
        self.utf_constants = utf_constants

    def dns_request_with_server(self):
        if self.dns_mode == "dnsquery":
            logger().info("=======DNS SERVER WITH DHCP========")
            result = self.wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "NULL", "NULL")
            logger().info(result.decode())
        elif self.dns_mode == "wrong_dnsserver":
            with pytest.raises(WlanError) as exc_info:
                logger().info("=======DNS SERVER WITH DHCP========")
                result = self.wifi_dut.interfaces.wifi.dns_get(4, "www.abcd.com", "NULL", "NULL")
                logger().info(result.decode())
            assert exc_info.value.error_code == 0xbba3 or 0xBBA1 or 0xaf
        elif self.dns_mode == "dnsstatic":
            ping_count = self.utf_constants.get("ping_count")
            logger().info("=======DNS SERVER WITH DHCP========")
            static_ip = "10.207.110.11"
            result = self.wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", static_ip, "NULL")
            dns_response = result.decode()
            ip_sen = dns_response.split("\n")
            ip_str = ip_sen[1]
            dns_ip = ip_str.split(":")
            logger().info(f"dns_response_ip : {dns_ip[1]}")
            logger().info(f"ping_count:{ping_count}")
            status = ping(dns_ip[1], ping_count)
            time.sleep(10)
            assert status == 1, "DUT not responding for ping request......"


class ConnectionStatus(ThreadBase):
    def __init__(self, wifi_dut, bt=False, ble=False, wlan=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt = bt
        self.ble = ble
        self.wlan = wlan

    def run(self):
        check_connection_status(self.wifi_dut, self.ble, self.wlan)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation
                    | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "bt_features": RS9116BTFeatureBitMap.Default
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_DNS_client_functionality_by_configuring_the_DNS_server_statically_after_BLE_connection_as_slave_C20233(
        wifi_dut, wifi_access_point, wifi_sniffer, utf_constants, ble_client):
    logger().info("*******************C20233************************")
    validation = True
    testcase = "dns_static + ble"
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_mode = "ble_slave"
    logger().info(f"ble mode : {ble_mode}")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address=None)
    logger().info(f"**********wifi*******************")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants, testcase=testcase)
    dns_mode = "dnsstatic"
    logger().info(f"dns_mode : '{dns_mode}'")
    dns_obj = DnsThread(wifi_dut, utf_constants, dns_mode=dns_mode)
    bssid, dut_mac_address, device_ip = wifi_obj.join_get_ip()
    time.sleep(10)
    logger().info(
        f"The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put")
    logger().info(f"DUT to power save in Wifi+bluetooth mode")
    enable_wifips = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifips, f" unable to enable the wifips"
    enable_btps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_btps, f"unable to enable the btps"
    dns_obj.dns_request_with_server()
    time.sleep(10)
    check_connection_status(wifi_dut, wlan=True)
    check_connection_status(wifi_dut, ble=True)
    wifi_leave(wifi_dut)
    logger().info("Initiating BLE disconnection from ble_client")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation()
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    dns_pkt = dns_pkt_check(
        wifi_sniffer,
        logger,
        decryption_key,
        dut_mac_address,
        testcase,
    )
    logger().info(f"*********** DNS packet {dns_pkt} ***********")
    assert dns_pkt, "***** Unable to find dns packet in the sniffer capture ***"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_DNS_client_functionality_by_configuring_wrong_DNS_server_after_BLE_connection_C20234(wifi_dut,
                                                                                              wifi_access_point,
                                                                                              wifi_sniffer,
                                                                                              utf_constants,
                                                                                              ble_client):
    logger().info("*******************C20234************************")
    validation = True
    testcase = "wrong_dnsserver + ble"
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    logger().info(f"**********wifi*******************")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants, testcase=testcase)
    dns_mode = "wrong_dnsserver"
    logger().info(f"wrong_dnsserver :  '{dns_mode}'")
    dns_obj = DnsThread(wifi_dut, utf_constants, dns_mode=dns_mode)
    bssid, dut_mac_address, device_ip = wifi_obj.join_get_ip()
    time.sleep(5)
    wifi_obj.powersave_ping()
    ble_mode = "ble_slave"
    logger().info(f"ble mode : {ble_mode}")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address=None)
    dns_obj.dns_request_with_server()
    time.sleep(5)
    check_connection_status(wifi_dut, wlan=True)
    check_connection_status(wifi_dut, ble=True)
    wifi_leave(wifi_dut)
    logger().info("Initiating BLE disconnection from ble_client")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_functionality_of_DNS_query_When_BLE_is_in_ADV_state_and_later_in_scan_state_C20360(wifi_dut, wifi_access_point,
                                                                                            utf_constants, wifi_sniffer,
                                                                                            ble_client):
    logger().info("*******************C20360************************")
    validation = True
    testcase = "dns_query+ble"
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info(f"**********wifi*******************")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants, testcase=testcase)
    dns_mode = "dnsquery"
    logger().info(f"dns_mode : {dns_mode}")
    dns_obj = DnsThread(wifi_dut, utf_constants, dns_mode=dns_mode)
    bssid, dut_mac_address, device_ip = wifi_obj.join_get_ip()
    time.sleep(5)
    wifi_obj.powersave_ping()
    dns_obj.dns_request_with_server()
    time.sleep(5)
    check_connection_status(wifi_dut, wlan=True)
    check_connection_status(wifi_dut, ble=True)
    logger().info(f"Clean up activity")
    wifi_leave(wifi_dut)
    logger().info("Initiating BLE disconnection from ble_client")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    time.sleep(4)
    logger().info("Successfully disconnected from BLE SLAVE Device")
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    dns_pkt = dns_pkt_check(
        wifi_sniffer,
        logger,
        decryption_key,
        dut_mac_address,
        testcase,
    )
    logger().info(f"*********** DNS packet {dns_pkt} ***********")
    assert dns_pkt, "***** Unable to find dns packet in the sniffer capture ***"
    wifi_obj.sniffer_validation()
