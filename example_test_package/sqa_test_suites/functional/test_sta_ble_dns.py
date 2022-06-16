import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.iperf.iperf_utils import ping, get_host_ip
from utf.interfaces.wifi import WlanError
from utf.interfaces.bluetooth import BLEDeviceState
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
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap, RS9116BTFeatureBitMap
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
            self.wifi_dut.interfaces.wifi.power_save(2,1)
            self.wifi_dut.interfaces.wifi.bt_power_save(2,1)
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
                with pytest.raises(WlanError) as exc_info:
                 logger().info("=======DNS SERVER WITH DHCP========")
                 result = self.wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "NULL", "NULL")
                 logger().info(result.decode())
                assert exc_info.value.error_code == 0xFF74
            elif (self.testcase2 == "dnswrongip"):
                with pytest.raises(WlanError) as exc_info:
                    logger().info("=======DNS SERVER WITH DHCP========")
                    result = self.wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "10.210.110.11", "10.89.41.10")
                    logger().info(result.decode())
                assert exc_info.value.error_code == 0xbba3 or 0xBBA1 or 0xaf
            elif (self.testcase3 == "dnsstatic"):
                with pytest.raises(WlanError) as exc_info:
                   logger().info("=======DNS SERVER WITH DHCP========")
                   result = self.wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "10.207.110.11", "10.8.4.10")
                   logger().info(result.decode())
                   time.sleep(15)
                assert exc_info.value.error_code == 0xFF74
            status = ping(device_ip, 100)
            assert status == 1, f"received packets is 100%, expected is 1"
            logger().info(f"Validating the dhcp packets")
            packet_filter3 = f'wlan_radio.channel == {self.wifi_access_point.interfaces.wifi.channel} or dhcp'
        self.wifi_dut.interfaces.wifi.leave()
        logger().info(f"Scan and join, ping in {t.duration} seconds")
        self.wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'
        logger().info(" Validate power management bit 1")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer  '
        logger().info(" Validate dhcp")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find dhcp in sniffer '

class BleThread_connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):
        if self.mode == "ble_master":
            logger().info(f"this is ble thread, Start DUT as a master")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            logger().info(f"Start ble client")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None
            time.sleep(1)
            logger().info(f"Start scanning and connect to ble client")
            self.wifi_dut.interfaces.wifi.ble_start_scanning(
                ble_client_address=bt_client_address, timeout=30
            )
            timeout = 120
            logger().info(f"connect")
            self.wifi_dut.interfaces.wifi.ble_connect(
                ble_remote_dev_address=bt_client_address, timeout=timeout
            )
            time.sleep(60)
            logger().info(f"Get the state of the dut")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected
            logger().info(f"Disconnect")
            self.wifi_dut.interfaces.wifi.ble_disconnect(
                ble_remote_dev_address=bt_client_address
            )
            time.sleep(60)
            logger().info(f"Get the state of the dut")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert not state_int == BLEDeviceState.Connected
            logger().info(f"*****BLE sniffer validation is pending*******")

        if self.mode == "ble_slave":
            logger().info(f" this is ble thread, start DUT as a slave")
            logger().info(f"Set up DUT for BLE advertising")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            self.wifi_dut.interfaces.wifi.ble_start_advertising()
            logger().info(f"Begin Scanning for BLE devices")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None
            logger().info("keeping the time sleep to complete smp scan")
            time.sleep(4)
            self.ble_client.interfaces.bluetooth.stop_scanning()
            logger().info(f"See that we found our device")
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            logger().info(f"{found_devices}")
            dut_ble_address = self.wifi_dut.interfaces.wifi.ble_address
            logger().info(f"dut_ble_address: {dut_ble_address}")
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
            logger().info(f"connect")
            self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
            logger().info(f"fetching the connection status after 60 secs of sleep")
            time.sleep(60)
            logger().info(f"Get the state of the dut")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, f"device disconnected"
            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
            time.sleep(60)
            logger().info(f"To check the ble disconnection after 60secs")
            logger().info(f"Get the state of the dut")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert not state_int == BLEDeviceState.Connected
            logger().info(f"*****BLE sniffer validation is pending*******")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode ,
        "bt_features": RS9116BTFeatureBitMap.Default
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_threading_sta_ble_dns_C20360(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
    mode = "ble_master"
    testcase1 = "dnsquery"
    testcase2 = ""
    testcase3 = ""
    testcase = "dns Query with ble"
    dns_obj = DNSThread(wifi_dut, wifi_access_point, wifi_sniffer, testcase1=testcase1, testcase2=testcase2,
                   testcase3=testcase3, testcase=testcase)
    ble_obj = BleThread_connection(wifi_dut, ble_client, mode)
    ble_obj.start()
    dns_obj.start()
    ble_obj.wait_for_exit()
    dns_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode ,
        "bt_features": RS9116BTFeatureBitMap.Default
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
    dns_obj = DNSThread(wifi_dut, wifi_access_point, wifi_sniffer, testcase1=testcase1, testcase2=testcase2,
                        testcase3=testcase3, testcase=testcase)
    ble_obj = BleThread_connection(wifi_dut, ble_client, mode)
    ble_obj.start()
    dns_obj.start()
    ble_obj.wait_for_exit()
    dns_obj.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode ,
        "bt_features": RS9116BTFeatureBitMap.Default
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
    dns_obj = DNSThread(wifi_dut, wifi_access_point, wifi_sniffer, testcase1=testcase1, testcase2=testcase2,
                        testcase3=testcase3, testcase=testcase)
    ble_obj = BleThread_connection(wifi_dut, ble_client, mode)
    ble_obj.start()
    dns_obj.start()
    ble_obj.wait_for_exit()
    dns_obj.wait_for_exit()



