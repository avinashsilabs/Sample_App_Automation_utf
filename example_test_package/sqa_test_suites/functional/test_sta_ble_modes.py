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
import time
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


class WifiThread_PMKmode(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer=None, testcase=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase

    def run(self):
        validation = True
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        time.sleep(10)
        logger().info(f"this thread is used for wifi join")
        with TimeMeasurer() as t:
            logger().info(f"Scan for the AP's")
            ap_mac = self.wifi_dut.interfaces.wifi.scan(ssid=None)
            ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
            logger().info(f'AP BSSID = {ap_bssid}')
            logger().info(f"Join Wi-Fi Access Point")
            logger().info(f"This API connects STA to the third party AP with the pmk generated")
            self.wifi_dut.interfaces.wifi.join_pmk(self.wifi_access_point.interfaces.wifi.ssid,
                                                   self.wifi_access_point.interfaces.wifi.passphrase)
            time.sleep(10)
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
            logger().info(f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol")
            packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                             f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                             f'(wlan.fc.type_subtype == 0x000b))'
            logger().info(f"Validating the power management bit")
            packet_filter2 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'
            status = ping(device_ip, 100)
            assert status == 1, f'ping is successful'
            self.wifi_sniffer.interfaces.capture.stop_capture()
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                                 'in sniffer'
            logger().info(" Validate power management bit 1")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '

class WifiThread_PSKMODE(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer=None, testcase=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase

    def run(self):
        validation = True
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        time.sleep(10)
        logger().info(f"this thread is used for wifi join")
        with TimeMeasurer() as t:
            logger().info(f"Scan for the AP's")
            ap_mac = self.wifi_dut.interfaces.wifi.scan(ssid=None)
            ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
            logger().info(f'AP BSSID = {ap_bssid}')
            logger().info(f"Join Wi-Fi Access Point")
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            time.sleep(10)
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
            logger().info(f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol")
            packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                             f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                             f'(wlan.fc.type_subtype == 0x000b))'
            logger().info(f"Validating the power management bit")
            packet_filter2 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'
            status = ping(device_ip, 100)
            assert status == 1, f'ping is successful'
            self.wifi_sniffer.interfaces.capture.stop_capture()
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                                 'in sniffer'
            logger().info(" Validate power management bit 1")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
                'packet_count'], 'Unable to find power management bit 1 in sniffer '


class ModesThread_bypass(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer, WPA_TKIP_PMK, WPA_AES_PMK, WPA_TKIP_PSK, WPA_AES_PSK,
                 testcase=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.WPA_TKIP_PMK = WPA_TKIP_PMK
        self.WPA_AES_PMK = WPA_AES_PMK
        self.WPA_TKIP_PSK = WPA_TKIP_PSK
        self.WPA_AES_PSK = WPA_AES_PSK
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase

    def run(self):
        if self.WPA_TKIP_PMK | self.WPA_AES_PMK:
            with TimeMeasurer() as t:
                validation = True
                logger().info("configuring the Sniffer with the channel")
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel)
                logger().info("start capturing with Sniffer by giving the test case name as filename")
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
                time.sleep(10)
                logger().info(f"This API connects STA to the third party AP with the pmk generated")
                self.wifi_dut.interfaces.wifi.join_pmk(self.wifi_access_point.interfaces.wifi.ssid,
                                                       self.wifi_access_point.interfaces.wifi.passphrase)
                logger().info(f"Fetches the DUT mac address")
                dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
                logger().info(f"Device mac address: {dut_mac_address}")
                logger().info("DUT to power save in Wifi+bluetooth mode")
                self.wifi_dut.interfaces.wifi.power_save(2)
                self.wifi_dut.interfaces.wifi.bt_power_save(2)
                time.sleep(5)
                logger().info(f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol")
                packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                                 f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                                 f'(wlan.fc.type_subtype == 0x000b))'
                logger().info(f"Validating the power management bit")
                packet_filter2 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'
                self.wifi_sniffer.interfaces.capture.stop_capture()
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                    'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                                     'in sniffer'
                logger().info(" Validate power management bit 1")
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
                    'packet_count'], 'Unable to find power management bit 1 in sniffer '

            assert (t.duration < 50)
            logger().info(f"Associated in {t.duration} seconds")
        elif self.WPA_TKIP_PSK | self.WPA_AES_PSK:
            with TimeMeasurer() as t:
                validation = True
                logger().info("configuring the Sniffer with the channel")
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel)

                logger().info("start capturing with Sniffer by giving the test case name as filename")
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
                time.sleep(10)
                self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
                logger().info(f"Fetches the DUT mac address")
                dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
                logger().info(f"Device mac address: {dut_mac_address}")
                logger().info("DUT to power save in Wifi+bluetooth mode")
                self.wifi_dut.interfaces.wifi.power_save(2)
                self.wifi_dut.interfaces.wifi.bt_power_save(2)
                logger().info(f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol")
                packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                                 f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                                 f'(wlan.fc.type_subtype == 0x000b))'
                logger().info(f"Validating the power management bit")
                packet_filter2 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'
                self.wifi_sniffer.interfaces.capture.stop_capture()
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                    'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                                     'in sniffer'
                logger().info(" Validate power management bit 1")
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
                    'packet_count'], 'Unable to find power management bit 1 in sniffer '
            assert (t.duration < 50)
            logger().info(f"Associated in {t.duration} seconds")


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
            time.sleep(10)
            logger().info(f"Start scanning and connect to ble client")
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
            logger().info(
                f"Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?")
            timeout = 120
            logger().info(f"Initiating connection this can take upto {timeout} seconds....")
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
            logger().info(f"Disconnect")
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

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


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteeetwobytesofsize",
                                               "passphrase": "123456789qwertyuio123456789qwertyuio123456789zxcvbnm123456789zx",
                                               "security": "WPA2", "cipher": 'AES', "standard": '11g'})
def test_threading_sta_ble_AES_pmk_C20212(wifi_dut, ble_client, wifi_access_point, wifi_sniffer):
    mode = "ble_slave"
    testcase = "sta with AES pmk + ble connection as a slave"
    with WifiThread_PMKmode(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase), BleThread_connection(
            wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteeetwobytesofsize",
                                               "passphrase": "123456789qwertyuio123456789qwertyuio123456789zxcvbnm123456789zx",
                                               "security": "WPA2", "cipher": 'TKIP', "standard": '11g'})
def test_threading_sta_ble_dut_tkip_pmk_C20211(wifi_dut, ble_client, wifi_access_point, wifi_sniffer):
    mode = "ble_slave"
    testcase = "sta with tkip pmk + ble connection as a slave"
    with WifiThread_PMKmode(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase), BleThread_connection(
            wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteeetwobytesofsize",
                                               "passphrase": "123456789qwertyuio123456789qwertyuio123456789zxcvbnm123456789zx",
                                               "security": "WPA", "cipher": 'TKIP', "standard": '11g'})
def test_threading_sta_ble_dut_tkip_psk_C20213(wifi_dut, ble_client, wifi_access_point, wifi_sniffer):
    mode = "ble_slave"
    testcase = "sta with tkip psk + ble connection as a slave"
    with WifiThread_PSKMODE(wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase), BleThread_connection(
            wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteeetwobytesofsize",
                                               "passphrase": "123456789qwertyuio123456789qwertyuio123456789zxcvbnm123456789zx",
                                               "security": "WPA2", "cipher": 'AES', "standard": '11g'})
def test_threading_sta_ble_dut_AES_psk_C20214(wifi_dut, ble_client, wifi_access_point, wifi_sniffer):
    mode = "ble_slave"
    testcase = "sta with AES psk + ble connection as a slave"
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
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": "WPA2", "cipher": 'TKIP', "standard": '11g'})
def test_threading_sta_ble_modes_tkip_pmk_C20252(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
    WPA_TKIP_PMK = True
    WPA_AES_PMK = False
    WPA_TKIP_PSK = False
    WPA_AES_PSK = False
    mode = "ble_slave"
    testcase = "testcase for tkip with pmk + ble in bypass"
    with ModesThread_bypass(wifi_dut, wifi_access_point, wifi_sniffer, WPA_TKIP_PMK, WPA_AES_PMK, WPA_TKIP_PSK,
                            WPA_AES_PSK, testcase=testcase), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "testingpmk", "passphrase": 'Testing_pmk', "security": "WPA2", "cipher": 'AES',
                          })
def test_threading_sta_ble_modes_AES_pmk_C20253(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
    WPA_TKIP_PMK = False
    WPA_AES_PMK = True
    WPA_TKIP_PSK = False
    WPA_AES_PSK = False
    mode = "ble_slave"
    testcase = "testcase for AES with pmk + ble"
    with ModesThread_bypass(wifi_dut, wifi_access_point, wifi_sniffer, WPA_TKIP_PMK, WPA_AES_PMK, WPA_TKIP_PSK,
                            WPA_AES_PSK, testcase=testcase), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "testingpmk", "passphrase": 'Testing_psk', "security": "WPA", "cipher": 'TKIP',
                          "standard": '11g'})
def test_threading_sta_ble_modes_tkip_psk_C20254(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
    WPA_TKIP_PMK = False
    WPA_AES_PMK = False
    WPA_TKIP_PSK = True
    WPA_AES_PSK = False
    mode = "ble_slave"
    testcase = "testcase for tkip with psk + ble"
    with ModesThread_bypass(wifi_dut, wifi_access_point, wifi_sniffer, WPA_TKIP_PMK, WPA_AES_PMK, WPA_TKIP_PSK,
                            WPA_AES_PSK,
                            testcase=testcase), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "testingpmk", "passphrase": 'Testing_psk', "security": "WPA2", "cipher": 'AES'})
def test_threading_sta_ble_modes_AES_psk_C20255(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
    WPA_TKIP_PMK = False
    WPA_AES_PMK = False
    WPA_TKIP_PSK = False
    WPA_AES_PSK = True
    mode = "ble_slave"
    testcase = "testcase for AES with psk + ble"
    with ModesThread_bypass(wifi_dut, wifi_access_point, wifi_sniffer, WPA_TKIP_PMK, WPA_AES_PMK, WPA_TKIP_PSK,
                            WPA_AES_PSK, testcase=testcase), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)

