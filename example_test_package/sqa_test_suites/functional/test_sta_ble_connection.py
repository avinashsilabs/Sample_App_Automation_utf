import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
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
    DeviceConstants,
    RS9116CustomFeatureBitMap, RS9116BTFeatureBitMap
)
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.thread_base import ThreadBase
import time

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

iter_count = 5

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


class ScanThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer, channel_2_4_list, channel_5_list, select_channel_all,testcase=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.channel_2_4_list = channel_2_4_list
        self.channel_5_list = channel_5_list
        self.select_channel_all = select_channel_all

    def run(self):
        logger().info(f"thread for scan functionality")
        channel_bitmap_2_4 = 0
        channel_bitmap_5 = 0
        if len(self.channel_2_4_list):
            channel_list = self.channel_2_4_list
            scan_expected_time = 0
            for count in channel_list:
                channel_bitmap_2_4 += 1 << (count - 1)
                scan_expected_time += 100
            channel_bitmap_5 = 0
            scan_feature_extend = 0
            for channel in channel_list:
                logger().info(f"initiates the access point with channel given in list")
                self.wifi_access_point.interfaces.wifi.start_ap(channel=channel)
                validation = True
                logger().info("configuring the Sniffer with the channel")
                self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel
                    )
                logger().info(
                        "start capturing with Sniffer by giving the test case name as filename"
                    )
                self.wifi_sniffer.interfaces.capture.start_capture(
                        capture_file=self.testcase
                    )
                self.wifi_dut.interfaces.wifi.rejoin(rejoin_max= 0,
                                                 scan_interval=4,
                                                 beacon_missedcount=40,
                                                 first_time_retry=0)
                logger().info(f"Fetches the DUT mac address")
                dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
                logger().info(f"Device mac address: {dut_mac_address}")
                logger().info("Setting DUT in wlan power save...")
                self.wifi_dut.interfaces.wifi.power_save(
                        RS9116PowerSaveModes.PowerSaveMode8, 1
                    )
                logger().info("Setting DUT in bt power save...")
                self.wifi_dut.interfaces.wifi.bt_power_save(
                        RS9116PowerSaveModes.PowerSaveMode8, 1
                    )
                logger().info(
                        f"enables the scan in DUT with the given channel bitmap value"
                    )
                ap_mac = self.wifi_dut.interfaces.wifi.scan_selective_channel(
                        channel=0,
                        ssid=None,
                        scan_bitmap_2_4=channel_bitmap_2_4,
                        scan_feature=scan_feature_extend,
                    )
                logger().info(ap_mac)
                assert len(ap_mac) >= 1
                channel_selected = 0
                for count in ap_mac:
                    for device_channel in channel_list:
                        if count.rf_channel == device_channel:
                                channel_selected = channel_selected + 1
                logger().info(f"Validating Broadcast Probe request")
                packet_filter1 = f'wlan_radio.channel == {self.wifi_access_point.interfaces.wifi.channel} and ' \
                                     f'wlan.sa == {dut_mac_address} and wlan.fc.type_subtype == 0x0004 ' \
                                     f'and wlan.da == ff:ff:ff:ff:ff:ff'

                time.sleep(2)
                self.wifi_sniffer.interfaces.capture.stop_capture()
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                        validation, packet_filter1
                    )[
                        "packet_count"
                    ], "Unable to find Broadcast Probe request packet in sniffer"
                assert channel_selected == len(ap_mac)

        if len(self.channel_5_list):
            channel_list = self.channel_5_list
            logger().info(f" {channel_list}")
            scan_expected_time = 0
            for count in channel_list:
                channel_bitmap_5 += 1 << (count - 1)
                scan_expected_time += 100
            scan_feature_extend = 0
            for channel in channel_list:
                logger().info(f"initiates the access point with channel given in list")
                self.wifi_access_point.interfaces.wifi.start_ap(
                    channel=channel_list[channel]
                )
                with TimeMeasurer() as t:
                    validation = True
                    logger().info("configuring the Sniffer with the channel")
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel
                    )
                    logger().info(
                        "start capturing with Sniffer by giving the test case name as filename"
                    )
                    self.wifi_sniffer.interfaces.capture.start_capture(
                        capture_file=self.testcase
                    )
                    logger().info("Setting DUT in wlan power save...")
                    self.wifi_dut.interfaces.wifi.power_save(
                        RS9116PowerSaveModes.PowerSaveMode8, 1
                    )
                    logger().info("Setting DUT in bt power save...")
                    self.wifi_dut.interfaces.wifi.bt_power_save(
                        RS9116PowerSaveModes.PowerSaveMode8, 1
                    )
                    logger().info(
                        f"enables the scan in DUT with the given channel bitmap value"
                    )
                    ap_mac = self.wifi_dut.interfaces.wifi.scan_selective_channel(
                        channel=0,
                        ssid=None,
                        scan_bitmap_5=channel_bitmap_5,
                        scan_feature=scan_feature_extend,
                    )
                    logger().info(ap_mac)
                    assert len(ap_mac) >= 1
                    channel_selected = 0
                    for count in ap_mac:
                        for device_channel in channel_list:
                            if count.rf_channel == device_channel:
                                channel_selected = channel_selected + 1

                    logger().info(f"Validating Broadcast Probe request")
                    packet_filter1 = f"wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff"
                    time.sleep(5)
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    logger().info("Validating Broadcast Probe request")
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                        validation, packet_filter1
                    )[
                        "packet_count"
                    ], "Unable to find Broadcast Probe request packet in sniffer"
                assert t.duration < 25
                logger().info(f"Scan in {t.duration} seconds")

        if self.select_channel_all:
            validation = True
            logger().info("configuring the Sniffer with the channel")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel
            )

            logger().info(
                "start capturing with Sniffer by giving the test case name as filename"
            )
            self.wifi_sniffer.interfaces.capture.start_capture(
                capture_file=self.testcase
            )
            with TimeMeasurer() as t:
                logger().info("Setting DUT in wlan power save...")
                self.wifi_dut.interfaces.wifi.power_save(
                    RS9116PowerSaveModes.PowerSaveMode8, 1
                )
                logger().info("Setting DUT in bt power save...")
                self.wifi_dut.interfaces.wifi.bt_power_save(
                    RS9116PowerSaveModes.PowerSaveMode8, 1
                )
                time.sleep(5)
                logger().info(f"enables the scan in dut on channel 0")
                logger().info(f"Scan for the AP's")
                ap_mac = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                packet_filter1 = (
                    f"wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff"
                )
                logger().info(ap_mac)
                assert len(ap_mac) >= 1
                logger().info(f"Validating Broadcast Probe request")
            assert t.duration < 20
            time.sleep(5)
            self.wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Validating Broadcast Probe request")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                validation, packet_filter1
            )[
                "packet_count"
            ], "Unable to find Broadcast Probe request packet in sniffer"

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
        logger().info(f"Scan for the AP's")
        ap_mac = self.wifi_dut.interfaces.wifi.scan(ssid=None,channel=self.wifi_access_point.interfaces.wifi.channel)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        logger().info(f"This API Enables the DHCP in DUT")
        result = self.wifi_dut.interfaces.wifi.start_ip()
        logger().info(f"{result}")
        assert isinstance(
                result, self.wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        logger().info("DUT to power save in Wifi+bluetooth mode")
        logger().info("enabling wifi power save")
        enable_wifi_ps = self.wifi_dut.interfaces.wifi.power_save(2, 1)
        assert enable_wifi_ps, 'failed to enable'
        logger().info("enabling bt power save")
        enable_bt_ps = self.wifi_dut.interfaces.wifi.bt_power_save(2, 1)
        assert enable_bt_ps, 'failed to enable'
        logger().info(f"*****Enable Max PSP in DUT******")
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        logger().info(f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol")
        packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                         f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                         f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'
        logger().info(f"Validating the power management bit")
        packet_filter2 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'
        logger().info(f"To verify the dhcp packets")
        packet_filter3 = f'wlan_radio.channel == {self.wifi_access_point.interfaces.wifi.channel} or dhcp && (wlan.addr == {dut_mac_address})'
        time.sleep(2)
        for i in range(0, iter_count):
            self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
            time.sleep(2)
            logger().info("This API used to get the http data from the server")
            status, content = self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path)
            logger().info(status)
            logger().info(content)
        self.wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Validating Probe req(Broadcast/Unicast)")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast) in sniffer'
        logger().info(" Validate association request")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find association request pakcets in sniffer '
        logger().info(" Validate association response")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find association response in sniffer '

class Cleanupactivity(ThreadBase):
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut

    def run(self):
        self.wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
     "wifi_dut",
     wifi={
         "oper_mode": 0,
         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
         "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
         "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
         "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
         "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W |
                                                   RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
         "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
         "band": 0,
     },
 )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_threading_selective_channels_2_4_C20208(wifi_dut, wifi_access_point, wifi_sniffer, ble_client):
     select_channel_all = False
     channel_2_4_list = [1, 6, 11]
     channel_5_list = []
     mode = "ble_slave"
     testcase = "sta + ble connection as a slave"
     scan_obj = ScanThread(wifi_dut, wifi_access_point, wifi_sniffer, channel_2_4_list, channel_5_list, select_channel_all, testcase=testcase)
     ble_client_obj = BleThread_connection(wifi_dut, ble_client, mode)
     ble_client_obj.start()
     scan_obj.start()
     ble_client_obj.wait_for_exit()
     scan_obj.wait_for_exit()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default | RS9116BTFeatureBitMap.BLEFeatureBitmapValid,
        "band": 0
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_crlf.html"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_threading_httpgetfunctionality_ble_C20339(wifi_dut, wifi_access_point, http_server, index_path, wifi_sniffer, ble_client):
    mode = "ble_slave"
    testcase = "testcase for http get download with ble"
    httpget_obj = httpgetThread(wifi_dut, wifi_access_point, http_server,  index_path, wifi_sniffer, testcase=testcase)
    ble_client_obj = BleThread_connection(wifi_dut, ble_client, mode)
    cleanup_obj = Cleanupactivity(wifi_dut)
    ble_client_obj.start()
    httpget_obj.start()
    cleanup_obj.start()
    ble_client_obj.wait_for_exit()
    httpget_obj.wait_for_exit()
    cleanup_obj.wait_for_exit()