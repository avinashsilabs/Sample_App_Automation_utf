import pytest
import test_apmode_sdk as ap
from utf.utils.iperf.iperf_utils import print_dict
from utf_wiseconnect.devices.rs911x import RS9116OperatingMode, RS9116CoexMode, RS9116Band, RS9116FeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116CustomFeatureBitMap, RS9116ExtCustomFeatureBitMap, \
    RS9116ExtTCPIPFeatureBitMap, RS9116AsyncEventType, SocketParams, RS9116ConfigFeatureBitMap, RS9116PowerSaveModes, \
    RS9116PowerSaveProcedureTypes, DeviceConstants
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
import time
from typing import Dict
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from datetime import datetime
import uuid
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf_wiseconnect_3.tests.sl_status import SLStatus

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)(Note:ap_mac will work only with ASUS ap)
    Test Steps:
        1. Configure the DUT in concurrent mode
        2. create DUT as access point and join DUT to 3rd party access point
        3. Initiate ping from the dut and vice versa
        4.Disconnect dut and connect again

    Note:1.EFR reset is used  as DUT reset is not working
        2.execute_number fixture used to run test case multiple times
    Author: Jyothi Nagireddy
"""

def logger():
    return get_logger(__name__)


class WifiJoin(ThreadBase):
    def __init__(self, utf_constants, wifi_dut, wifi_access_point, wifi_sniffer, ap_bssid, power_save=None):
        super().__init__()
        self.utf_constants = utf_constants
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.ap_bssid = ap_bssid
        self.power_save = power_save

    def run(self):
        ping_count = self.utf_constants.get("ping_count")
        self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, thread=True)
        logger().info(".... Connecting to Wi-Fi AP....")
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point, thread=True)
        logger().info("....DUT configures the IP Address....")
        ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=10, thread=True)
        device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(thread=True)
        logger().info(f"DUT MAC ADDRESS :  {dut_mac_address} IP ADDRESS : {device_ip}")
        self.ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {self.ap_bssid}')
        logger().info(f"ping to DUT before power_save")
        status = self.ping(device_ip=device_ip, ping_count=ping_count)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        if self.power_save:
            mode = 'power_save_low_latency'
            logger().info(f"....Applying performance profile mode : {mode}")
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode, thread=True)
            logger().info("....Pinging DUT after power-save....")
            status = self.ping(device_ip=device_ip, ping_count=ping_count)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

    def sniffer_validation(self, dut_mac_address=None):
        packet_filter1 = self.wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                                 filter_name="probe_request")
        packet_filter2 = self.wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                                 da_mac_address=self.ap_bssid,
                                                                                 filter_name='association_request')
        packet_filter3 = self.wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=self.ap_bssid,
                                                                                 da_mac_address=dut_mac_address,
                                                                                 filter_name='association_response')
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  probe request in Sniffer'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find Association req packets'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find Association response packets'
        logger().info("passing passphrase and ssid to decrypt dhcp packets")
        decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"
        logger().info("DHCP decryption is in progress")
        status = self.wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
        logger().info(f'DHCP packet from DUT found: {status}')
        assert status, "DHCP packets not found"


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19314", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP_C19314", "passphrase": "12345678", "channel": 8, "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
def test_wifi_sdk_concurrent_mode_c19314(firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, ssid, utf_constants, channel):
    """ Verify Dut Behaviour When We Disconnect the STA's to AP in concurrent mode"""
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_19314')
    time.sleep(3)
    ap_dut_obj = ap.ApMode_SingleClientConn(wifi_dut, wifi_client, ssid=ssid, channel=channel, leave=False)
    dut_mac_address = ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    sta_obj = WifiJoin(utf_constants, wifi_dut, wifi_access_point, power_save=True)
    sta_obj.start()
    sta_obj.wait_for_exit()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    logger().info("Disconnecting 3rd party station from AP")
    wifi_client.interfaces.wifi.leave()
    logger().info("Reconnecting 3rd party station from AP")
    wifi_client.interfaces.wifi.join()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info("Deinitialize Dut")
    wifi_dut.interfaces.wifi.sl_net_deinit()
    sta_obj.sniffer_validation(dut_mac_address=dut_mac_address)



@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19315", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP_C19315", "passphrase": "12345678", "channel": 8, "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
def test_wifi_sdk_concurrent_mode_c19315(firmware_loader, utf_constants, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, ssid, channel):
    """ DUT Behaviour When We Disconnect and Connect the STA in Concurrent mode"""
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_19315')
    time.sleep(3)
    ap_dut_obj = ap.ApMode_SingleClientConn(wifi_dut, wifi_client, ssid=ssid, channel=channel, leave=False)
    dut_mac_address = ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    sta_obj = WifiJoin(utf_constants, wifi_dut, wifi_access_point, power_save=True)
    sta_obj.start()
    sta_obj.wait_for_exit()
    logger().info("Disconnecting DUT station from 3rd party AP")
    wifi_dut.interfaces.wifi.leave()
    logger().info("reconnecting DUT station from 3rd party AP")
    wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      security=wifi_access_point.interfaces.wifi.security,
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(5)
    logger().info("fetching ip address through DHCP")
    wifi_dut.interfaces.wifi.start_ip()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info("Deinitialize Dut")
    wifi_dut.interfaces.wifi.sl_net_deinit()
    sta_obj.sniffer_validation(dut_mac_address=dut_mac_address)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.Default,
        "security": 'WPA2', "ssid": "RASPI_AP", "channel": 8, "passphrase": "12345678"
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'DUT_AP',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RASPI_AP", "channel": 8, "passphrase": "12345678"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.skip()
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config('wifi_access_point',
                    wifi={"dhcp_start": "192.168.50.12", "dhcp_end": "192.168.50.20", "dhcp_lease": "180"})
def test_wifi_sdk_concurrent_mode_c19316(firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                      ssid, channel, utf_constants):
    """ Verify Whether STA is getting IP change notification when change the DHCP range in concurrent mode"""
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_19316')
    time.sleep(3)
    ap_dut_obj = ap.ApMode_SingleClientConn(wifi_dut, wifi_client, ssid=ssid, channel=channel, leave=False)
    dut_mac_address = ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    sta_obj = WifiJoin(utf_constants, wifi_dut, wifi_access_point, power_save=True)
    logger().info(f"preparing wifi_dut as STA - STA Mode")
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    access_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=access_point_ip)
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(access_point_ip))
    wifi_access_point.interfaces.wifi.enable_dhcp_ap(
            dhcp_start="192.168.50.50",
            dhcp_end="192.168.50.60",
            dhcp_lease=120)
    time.sleep(120)
    logger().info("Disconnecting DUT station from 3rd party AP")
    wifi_dut.interfaces.wifi.leave()
    logger().info("Deinitialize Dut")
    wifi_dut.interfaces.wifi.sl_net_deinit()
    sta_obj.sniffer_validation(dut_mac_address=dut_mac_address)


@pytest.mark.skip("iperf-dut-support-NA")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19313", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP_C19313", "passphrase": "12345678", "channel": 8}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_concurrent_mode_c19313(firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                      protocol, net_perf_client, ssid, utf_constants, channel):
    """ Verify whether DUT is able to bring up AP mode and then STA when enable concurrent mode"""
    wifi_dut.interfaces.wifi.associated = False
    eth_interface = wifi_client.interfaces.wifi.config["interface"]
    wifi_client.interfaces.wifi.config['interface'] = "wlan0"
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_19313')
    time.sleep(3)
    ap_dut_obj = ap.ApMode_SingleClientConn(wifi_dut, wifi_client, ssid=ssid, channel=channel, leave=False)
    dut_mac_address = ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    sta_obj = WifiJoin(utf_constants, wifi_dut, wifi_access_point, power_save=True)
    sta_obj.start()
    sta_obj.wait_for_exit()
    #iperf code
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info("Deinitialize Dut")
    wifi_dut.interfaces.wifi.sl_net_deinit()
    sta_obj.sniffer_validation(dut_mac_address=dut_mac_address)


@pytest.mark.skip("iperf-dut-support-NA")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 8})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19312", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP_C19312", "passphrase": "12345678", "channel": 8, "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_concurrent_mode_c19312(firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                      protocol, net_perf_client, utf_constants, ssid, channel):
    """Verify whether DUT is able to bring up STA and then AP when enable concurrent mode"""
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_19312')
    time.sleep(3)
    ap_dut_obj = ap.ApMode_SingleClientConn(wifi_dut, wifi_client, ssid=ssid, channel=channel, leave=False)
    dut_mac_address = ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    sta_obj = WifiJoin(utf_constants, wifi_dut, wifi_access_point, power_save=True)
    sta_obj.start()
    sta_obj.wait_for_exit()
    #iperf code
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info("Deinitialize Dut")
    wifi_dut.interfaces.wifi.sl_net_deinit()
    sta_obj.sniffer_validation(dut_mac_address=dut_mac_address)


@pytest.mark.skip("iperf-dut-support-NA")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": 'Open', "ssid": "RS9116_AP_C19318", "channel": 8,
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': '12345678',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "Open", "ssid": "RS9116_AP_C19318", "channel": 8, "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_concurrent_mode_c19318(firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                      protocol, net_perf_client, utf_constants, ssid, channel):
    """Verify whether DUT is able to create AP and STA in 2 different securities when enable concurrent mode"""
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_19318')
    time.sleep(3)
    ap_dut_obj = ap.ApMode_SingleClientConn(wifi_dut, wifi_client, ssid=ssid, channel=channel, leave=False)
    dut_mac_address = ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    sta_obj = WifiJoin(utf_constants, wifi_dut, wifi_access_point, power_save=True)
    sta_obj.start()
    sta_obj.wait_for_exit()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info("Deinitialize Dut")
    wifi_dut.interfaces.wifi.sl_net_deinit()
    sta_obj.sniffer_validation(dut_mac_address=dut_mac_address)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 8})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19319", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP_C19319", "passphrase": "12345678", "channel": 8, "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
def test_wifi_sdk_concurrent_mode_c19319(firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, utf_constants, ssid, channel):
    """Verify concurrent mode functionality when both AP and STA uses WPA2-AES mode"""
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_19319')
    time.sleep(3)
    ap_dut_obj = ap.ApMode_SingleClientConn(wifi_dut, wifi_client, ssid=ssid, channel=channel, leave=False)
    dut_mac_address = ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    sta_obj = WifiJoin(utf_constants, wifi_dut, wifi_access_point, power_save=True)
    sta_obj.start()
    sta_obj.wait_for_exit()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info("Deinitialize Dut")
    wifi_dut.interfaces.wifi.sl_net_deinit()
    sta_obj.sniffer_validation(dut_mac_address=dut_mac_address)


@pytest.mark.skip("iperf-dut-support-NA")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": 'WPA2', "ssid": "RS9116_AP_C19320", "channel": 8, "passphrase": "12345678"
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurrent_AP',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP_C19320", "channel": 8, "passphrase": "12345678"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_concurrent_mode_c19320(firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                      protocol, net_perf_client, ssid, utf_constants, channel):
    """verify whether able to do data transfer between WSC AP and connected STA and between WSC STA and connected AP"""
    wifi_dut.interfaces.wifi.associated = False
    eth_interface = wifi_client.interfaces.wifi.config["interface"]
    wifi_client.interfaces.wifi.config['interface'] = "wlan0"
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_19320')
    time.sleep(3)
    ap_dut_obj = ap.ApMode_SingleClientConn(wifi_dut, wifi_client, ssid=ssid, channel=channel, leave=False)
    dut_mac_address = ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    sta_obj = WifiJoin(utf_constants, wifi_dut, wifi_access_point, power_save=True)
    sta_obj.start()
    sta_obj.wait_for_exit()
    #iperf code
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info("Deinitialize Dut")
    wifi_dut.interfaces.wifi.sl_net_deinit()
    sta_obj.sniffer_validation(dut_mac_address=dut_mac_address)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server
                          | RS9116TCPIPFeatureBitMap.Ping | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19324", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP_C19324", "passphrase": "12345678", "channel": 8, "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
def test_wifi_sdk_concurrent_mode_c19324(firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, utf_constants, ssid, channel):
    """Connect and Disconnect STA multiple times when enable concurrent mode"""
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_19324')
    time.sleep(3)
    ap_dut_obj = ap.ApMode_SingleClientConn(wifi_dut, wifi_client, ssid=ssid, channel=channel, leave=False)
    dut_mac_address = ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    sta_obj = WifiJoin(utf_constants, wifi_dut, wifi_access_point, power_save=True)
    sta_obj.start()
    sta_obj.wait_for_exit()
    for count in range(1, 3):
        wifi_dut.interfaces.wifi.leave()
        logger().info("reconnecting DUT station from 3rd party AP")
        time.sleep(10)
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        time.sleep(5)
        for i in range(3):
             try:
                 logger().info("fetching ip address through DHCP")
                 wifi_dut.interfaces.wifi.start_ip()
                 device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
                 if device_ip:
                     break
             except:
                 logger().info(f"Get IP address through dhcp process is failed. retry count -> {i + 1}")
                 time.sleep(5)

        logger().info(f'connected and disconnected for {count} times')
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info("Deinitialize Dut")
    wifi_dut.interfaces.wifi.sl_net_deinit()
    sta_obj.sniffer_validation(dut_mac_address=dut_mac_address)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19317", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP_C19317", "passphrase": "12345678", "channel": 8, "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
def test_wifi_sdk_concurrent_mode_c19317(firmware_loader, wifi_sniffer, wifi_access_point, utf_constants,
                                                  wifi_client, wifi_dut, switch, ssid, channel):
    """Verify whether module is giving rejoin Failure indication to host or not in concurrent mode"""

    logger().info(f"***************testcase: C19317 *******************")
    logger().info('******* Turn on Access point **********')
    switch.interfaces.pdu_switch.turn_on(delay=60)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c19317')
    wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                             beacon_missed_count=40, first_time_retry_enable=0)
    ap_dut_obj = ap.ApMode_SingleClientConn(wifi_dut, wifi_client, ssid=ssid, channel=channel, leave=False)
    dut_mac_address = ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    sta_obj = WifiJoin(utf_constants, wifi_dut, wifi_access_point, power_save=True)
    sta_obj.start()
    sta_obj.wait_for_exit()
    logger().info("******* Turn off access point and waiting for Rejoin error*******")
    switch.interfaces.pdu_switch.turn_off(delay=150)
    """validate rejoin retry failure"""
    logger().info("Checking for rejoin fail event from dut, this may take some time....")
    sw = Stopwatch()
    rejoin_msg = 0
    end_time = 500
    while sw.elapsed_sec <= end_time:
        # events = wifi_dut.interfaces.wifi.get_async_events()
        # if len(events):
        # for event in events:
        #  if event.event_type == RS9116AsyncEventType.RejoinError:
        #      rejoin_msg = 1
        #      logger().info(
        #          "******** Rejoin error found from DUT, which is expected as per the test step ********")
        if rejoin_msg:
            break
        assert rejoin_msg == 1, "rejoin fail event not found even after AP is switched off for 350 seconds"
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Deinitialize Dut")
    wifi_dut.interfaces.wifi.sl_net_deinit()
    logger().info("Stop Sniffer finally")
    sta_obj.sniffer_validation(dut_mac_address=dut_mac_address)
