import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.thread_base import ThreadBase
import time
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, DeviceConstants, RS9116CustomFeatureBitMap
from utf.interfaces.wifi import WlanError

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

class WifiDeeppowersave(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer= None, testcase= None):
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
        logger().info(f"use the corresponding hex file when using gpio and msg based")
        logger().info(f"this thread is used for wifi join")
        with TimeMeasurer() as t:
          logger().info("Setting DUT in wlan power save...")
          self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
          logger().info("Setting DUT in bt power save...")
          self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
          time.sleep(5)
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
          time.sleep(10)
          logger().info(f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol")
          packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                           f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                           f'(wlan.fc.type_subtype == 0x000b))'
          logger().info(f"Initiate ping from third party wifi-client to DUT")
          status = ping(device_ip, 100)
          assert status == 1
        logger().info(f"Associated and ping, Scan in {t.duration} seconds")
        self.wifi_sniffer.interfaces.capture.stop_capture()
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'

        logger().info(" Validate power management bit 1")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

class WifiConnectedpowersave(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer= None, testcase= None):
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
        logger().info(f"use the corresponding hex file when using gpio and msg based")
        logger().info(f"this thread is used for wifi join ")
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
          self.wifi_dut.interfaces.wifi.power_save(2, 0)
          self.wifi_dut.interfaces.wifi.bt_power_save(
              power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
          )
          time.sleep(15)
          logger().info(f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol")
          packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or ' \
                           f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                           f'(wlan.fc.type_subtype == 0x000b))'

          logger().info(f"Validating the power management bit")
          packet_filter2 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'
          logger().info(f"Initiate ping from third party wifi-client to DUT")
          status = ping(device_ip, 100)
          assert status == 1
        logger().info(f"Associated and ping, Scan in {t.duration} seconds")
        self.wifi_sniffer.interfaces.capture.stop_capture()
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'

        logger().info(" Validate power management bit 1")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

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
            logger().info(f"connect")
            self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
            logger().info(f"disconnect")
            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)

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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_threading_sta_bleC20274(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
    mode = "ble_slave"
    testcase = "sta + ble connection as a slave with gpio based deep sleep"
    with WifiDeeppowersave(wifi_dut, wifi_access_point, wifi_sniffer, testcase= testcase), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)