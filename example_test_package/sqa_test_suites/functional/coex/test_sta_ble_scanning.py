import pytest
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.wifi import WlanError
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
    DeviceConstants,
    RS9116CustomFeatureBitMap, RS9116BTFeatureBitMap
)
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.thread_base import ThreadBase
import time
import string
import random
from random import randint

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
Test Steps:    
        Step1 : Configuration of DUT in BT/Wlan.
        Step2 : Verify the connection to AP
        Step3 : Verify the Bleconnection

Author:
        Jyothi Nagireddy
"""

ping_count = 300
iteration_count = 10

class WifiThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer

    def run(self):
        validation = True
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        self.wifi_sniffer.interfaces.capture.start_capture('sta+ble scanning testcase')
        logger().info(f"this thread is used for wifi join")
        with TimeMeasurer() as t:
            logger().info(f"Scan for the AP's")
            ap_mac = self.wifi_dut.interfaces.wifi.scan(ssid=None, channel=self.wifi_access_point.interfaces.wifi.channel)
            ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
            logger().info(f'AP BSSID = {ap_bssid}')
            logger().info(f"Join Wi-Fi Access Point")
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            logger().info(f"This API Enables the DHCP in DUT")
            result = self.wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(
                result, self.wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
            device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
            logger().info(f"Fetches the DUT mac address")
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")
            logger().info("DUT to power save in Wifi+bluetooth mode")
            logger().info("enabling wifi power save")
            enable_wifi_ps = self.wifi_dut.interfaces.wifi.power_save(2, 1)
            assert enable_wifi_ps, 'failed to enable'
            logger().info("enabling bt power save")
            enable_bt_ps = self.wifi_dut.interfaces.wifi.bt_power_save(2, 1)
            assert enable_bt_ps, 'failed to enable'
            logger().info(
                f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol"
            )
            packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                         f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                         f'(wlan.fc.type_subtype == 0x000b)) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'
            logger().info(f"Validating the power management bit")
            packet_filter2 = f"wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}"
            logger().info(f"Validate dhcp")
            packet_filter3 = f"wlan_radio.channel == {self.wifi_access_point.interfaces.wifi.channel} or dhcp"
            logger().info(f"Validate more data bit")
            packet_filter4 = f"wlan.ta == {ap_bssid} && wlan.da=={dut_mac_address} && wlan.fc.moredata==1"
            logger().info(f"Initiate ping from third party wifi-client to DUT")
            status = ping(device_ip, ping_count)
            assert status == 1, f"DUT not responding for ping request......"
        logger().info(f"Associated and ping, Scan in {t.duration} seconds")
        self.wifi_dut.interfaces.wifi.leave()
        self.wifi_sniffer.interfaces.capture.stop_capture()
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                validation, packet_filter1
            )["packet_count"], (
                "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet "
                "in sniffer"
            )
        logger().info(" Validate power management bit 1")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                validation, packet_filter2
            )["packet_count"], "Unable to find power management bit 1 in sniffer "
        logger().info(" Validate dhcp")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
                'packet_count'], 'Unable to find dhcp in sniffer '
        logger().info(" Validate more data bit")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find more data bit in sniffer '


class BleThread_connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client

    def run(self):
        logger().info(f"this thread used for ble scanning")
        logger().info(f"Set up DUT for BLE advertising")
        bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        self.wifi_dut.interfaces.wifi.ble_start_advertising()
        logger().info(f"Begin Scanning for BLE devices")
        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None
        time.sleep(5)
        logger().info(f"See that we found our device")
        found_devices = self.ble_client.interfaces.bluetooth.get_devices()
        logger().info(f"{found_devices}")
        assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (
                found_devices[self.wifi_dut.interfaces.wifi.ble_address]
                == self.wifi_dut.interfaces.wifi.ble_advertising_data
        )

def wifi_connection(wifi_dut, wifi_access_point, wifi_sniffer):
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    logger().info(
        "start capturing with Sniffer by giving the test case name as filename"
    )
    wifi_sniffer.interfaces.capture.start_capture('sta+ble scanning testcase_iteration')
    logger().info(f"this thread is used for wifi join")
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave()
        logger().info(f"Scan for the AP's")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')
        logger().info(f"Join Wi-Fi Access Point")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info(f"This API Enables the DHCP in DUT")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
        logger().info(f"Fetches the DUT mac address")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")
        logger().info("DUT to power save in Wifi+bluetooth mode")
        logger().info("enabling wifi power save")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(2, 1)
        assert enable_wifi_ps, 'failed to enable'
        logger().info("enabling bt power save")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(2, 1)
        assert enable_bt_ps, 'failed to enable'
        logger().info(
            f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol"
        )
        packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                         f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                         f'(wlan.fc.type_subtype == 0x000b)) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

        logger().info(f"Validating the power management bit")
        packet_filter2 = f"wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}"
        logger().info(f"Validate dhcp")
        packet_filter3 = f"wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} or dhcp"
        logger().info(f"Validate more data bit")
        packet_filter4 = f"wlan.ta == {ap_bssid} && wlan.da=={dut_mac_address} && wlan.fc.moredata==1"
        logger().info(f"Initiate ping from third party wifi-client to DUT")
        status = ping(device_ip, ping_count)
        assert status == 1,"DUT not responding for ping request......"
        wifi_dut.interfaces.wifi.leave()
    logger().info(f"Associated and ping, Scan in {t.duration} seconds")
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(
        validation, packet_filter1
    )["packet_count"], (
        "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet "
        "in sniffer"
    )
    logger().info(" Validate power management bit 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(
        validation, packet_filter2
    )["packet_count"], "Unable to find power management bit 1 in sniffer "
    logger().info(" Validate dhcp")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find dhcp in sniffer '
    logger().info(" Validate more data bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'Unable to find more data bit in sniffer '

@pytest.mark.config(
     "wifi_dut",
     wifi={
         "oper_mode": 0,
         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
         "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
         "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
         "custom_features": RS9116CustomFeatureBitMap.Default,
         "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
         "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
         "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
         "bt_features": RS9116BTFeatureBitMap.Default | RS9116BTFeatureBitMap.A2DPProfileEnable | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
         "band": 0,
     },
 )
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_threading_sta_ble_dut_C20184(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
    with WifiThread(wifi_dut, wifi_access_point, wifi_sniffer), BleThread_connection(wifi_dut, ble_client):
        time.sleep(2)
    logger().info("Repeating test for 9 iterations")
    for i in range(1, iteration_count):
        logger().info(f"Iteration {i} started")
        wifi_connection(wifi_dut, wifi_access_point, wifi_sniffer)
        logger().info(f"Iteration {i} ended")