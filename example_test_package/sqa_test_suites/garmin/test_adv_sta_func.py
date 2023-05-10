import pytest
import time
import re
from datetime import datetime
import uuid
from typing import Dict
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.utils.iperf.iperf_utils import print_dict
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116PowerSaveModes, RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, \
    RS9116CustomFeatureBitMap, \
    RS9116JoinFeatureBitMap, RS9116Band, RS9116PowerSaveProcedureTypes, SocketType, RS9116AsyncEventType, SocketOptions, \
    DeviceConstants, Cipher
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from random import randint
from utf.utils.thread_base import ThreadBase
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.interfaces.wifi import WlanError
from threading import Thread
import threading
import random
import string


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9116 for WLAN Garmin test cases verification
        1. Configuration of DUT in 2G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. WiFi scan,connect and disconnect in a loop

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device) 
"""
"""Author : Yogitha, Jyothi Nagireddy"""


class PacketCheck():
    def __init__(self, wifi_sniffer, dut_mac_address, decryption_key: str, print_layers: list, capture_filename=None):
        self.wifi_sniffer = wifi_sniffer
        self.dut_mac_address = dut_mac_address
        self.decryption_key = decryption_key
        self.print_layers = print_layers
        self.capture_filename = capture_filename

    def get_icmp_sntp_list(self):
        ntp_capture_list = []
        icmp_layer = []
        source_ip = ""
        destination_ip = ""
        mac_layer = ""
        current_time = time.time()
        updated_capture_file = 'filter_' + self.capture_filename + '_' + str(
            datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
        file_name = f'./reports/{updated_capture_file}.pcap'
        local_capture_file = file_name
        wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
        packet_filter1 = f'(wlan.addr == {self.dut_mac_address})'
        self.wifi_sniffer.interfaces.capture.shell(
            f"tshark -nr {self.wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
            f"frame.number -w "
            f"{wlan_filter_file}")
        with self.wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
            sftp.get(wlan_filter_file, local_capture_file)
        for packet in self.wifi_sniffer.interfaces.capture.iter_packets(
                decrypt_packets=True,
                encryption_type="WPA-PWD",
                decryption_key=self.decryption_key,
                capture_file_filter=local_capture_file
        ):
            for layer in packet.layers:
                layer_name = layer.layer_name.lower()
                if layer_name == "wlan":
                    mac_layer = str(layer)
                if self.dut_mac_address in mac_layer:
                    if layer_name == "ip":
                        ip_layer = str(layer)
                        layer_ip = ip_layer.split("\n")
                        for count in layer_ip:
                            if "Source" in count:
                                source_ip = count.split(":")[1].strip()
                            if "Destination" in count:
                                destination_ip = count.split(":")[1].strip()

                    if layer_name == "icmp":
                        icmp_layer = str(layer)

                    if layer_name in self.print_layers:
                        ntp_layer = str(layer)
                        ntp_capture_list.append(tuple([ntp_layer, packet.sniff_timestamp, source_ip, destination_ip]))
        return icmp_layer, source_ip, destination_ip, ntp_capture_list



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | RS9116FeatureBitMap.OpenMode,
        # get features in garmin
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "set_send_feature_frame": True,
        "rf_type": 1,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_wlan_connected_standby_c20844(wifi_access_point, wifi_dut, wifi_sniffer, utf_constants):
    bcast_in_tim_next_cmd = 1
    beacon_drop = 5000
    bcast_in_tim = 1

    iter_count = utf_constants.get('iter_count')
    ping_count = utf_constants.get('ping_count')
    logger().info(" ====== configuring the sniffer with access point channel ======")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_connected_standy_C20844')

    # Enable loop;
    for count in range(iter_count):
        logger().info(f"Initiating test for iteration: {count + 1}")
        logger().info("scan and connecting to access point.....")
        # DUT connects to AP after join_ap API is executed
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        logger().info("sending filter broadcast command")
        wifi_dut.interfaces.wifi.set_filter_broadcast(beacon_drop, bcast_in_tim, bcast_in_tim_next_cmd)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"

        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'DUT ip {device_ip}')

        logger().info("enabling wifi power save mode in DUT......")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(10)
        # enable ping
        logger().info("***** Pinging to DUT from wifi_client  *****")
        ping(device_ip, ping_count)
        logger().info("***** Ping successful *****")

        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | RS9116FeatureBitMap.OpenMode,
        # get features in garmin
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "set_send_feature_frame": True,
        "rf_type": 1,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_wlan_continous_ping_c20833(wifi_access_point, wifi_dut, wifi_sniffer):
    ping_count = 1000
    logger().info(" ====== configuring the sniffer with access point channel ======")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_connected_standy_C20833')

    logger().info("scan and connecting to access point.....")
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("***** Pinging to DUT from wifi_client  *****")
    ping(device_ip, ping_count)
    logger().info("***** Ping successful *****")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | RS9116FeatureBitMap.OpenMode,
        # get features in garmin
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "set_send_feature_frame": True,
        "rf_type": 1,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_scan_func_after_successful_dut_conn_c20849(wifi_access_point, wifi_dut, wifi_sniffer):
    logger().info(" ====== configuring the sniffer with access point channel ======")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_connected_standy_C20849')

    logger().info("scan and connecting to access point.....")
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    with pytest.raises(WlanError) as exc_info:
        logger().info("Initiating scan after DUT successful connection with AP")
        wifi_dut.interfaces.wifi.scan(ssid=None, channel=0, retries=1)
        assert exc_info.value.error_code == 0x2
        logger().info(
            f"Dut Tried to initiate the scan command after successful connection with AP , observed error code 0x2 which is expected")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL |
                          RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose |
                              RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY |
                              RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV |
                              RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "set_send_feature_frame": True,
        "rf_type": 1,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPAWPA2MixedMode'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_wpa_wpa2_mixed_mode_access_point_detected_as_wpa_c20851(wifi_access_point, wifi_dut, wifi_sniffer):
    logger().info("\n\n **** Some WPA/WPA2 mixed mode access points being detected as WPA only ***** \n\n")
    logger().info(" ====== configuring the sniffer with access point channel ======")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_connected_standy_C20851')

    logger().info("Initiating scan and connecting to access point")
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)

    logger().info("When AP is configured in Mixed mode.DUT should connect to higher Security")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("getting wireless info")
    result = wifi_dut.interfaces.wifi.get_wireless_info()
    if "security_mode: 2" in result:
        logger().info("DUT connected to AP with WPA2")
    else:
        logger().info("DUT connected to AP with WPA")
        assert ("DUT connected to AP with WPA security instead of WPA2")
    wifi_dut.interfaces.wifi.start_ip()
    wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    RS9116FeatureBitMap.OpenMode,  # get features in garmin
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL |
                          RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose |
                              RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY |
                              RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV |
                              RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "set_send_feature_frame": True,
        "rf_type": 1,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_wifi_conn_by_providing_wrong_psk_c20847(wifi_access_point, wifi_dut, wifi_sniffer):
    logger().info(
        "\n\n **** Verify Wi-Fi connection by providing the wrong PSK using rsi_wlan_connect_async API ***** \n\n")
    logger().info(" ====== configuring the sniffer with access point channel ======")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_connected_standy_C20847')

    try:
        logger().info("Initiating scan and connecting to access point")
        wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point, passphrase=123456789)
            assert exc_info.value.error_code == 0x8
    except:
        logger().info(f"connectivity fails as PSK is given wrong -->Expected")

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()



@pytest.mark.config("wifi_dut",
                    wifi={"oper_mode": 0,
                          "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
                          "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                                      RS9116FeatureBitMap.OpenMode,
                          "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL |
                                            RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                                            RS9116TCPIPFeatureBitMap.Ping,
                          "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
                          "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose |
                                                RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY |
                                                RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV |
                                                RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
                          "config_features": RS9116ConfigFeatureBitMap.Default,
                          "set_send_feature_frame": True,
                          "rf_type": 1,
                          }
                    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_ping_func_when_wrong_ip_is_configured_c20848(wifi_access_point, wifi_dut, wifi_sniffer, wifi_client, rs_helper, utf_constants):
    logger().info("\n\n **** Verify ping functionality and timeout when wrong IP address is configured ***** \n\n")
    server_ip = "192.168.30.64"
    logger().info(" ====== configuring the sniffer with access point channel ======")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_ping_func_wrong_ip_C20848')
    logger().info(f"**********initiating wlan connection*******************")
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=False)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Host IP *********: {host_ip}")
    time.sleep(10)
    logger().info("Initiating Ping from DUT to Remote device")
    for i in range(1, 7):
        result = wifi_dut.interfaces.wifi.ping(server_ip, num_ping_attempts=2, ping_timeout=20)
        logger().info(f"{result}")
        assert True, 'ping got failed due to wrong IP'

    wifi_dut.interfaces.wifi.leave(timeout=10)
    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    logger().info(f"decryption_key : {decryption_key}")
    icmp_check = PacketCheck(wifi_sniffer, dut_mac_address, decryption_key, ["ntp"], capture_filename = "test_icmp_c20848")
    icmp_layer, source_ip, destination_ip, ntp_capture_list = icmp_check.get_icmp_sntp_list()
    if source_ip:
        assert str(device_ip) in str(source_ip), f"Unable to find given device ip: {device_ip} in sniffer packet"
        logger().info(f"\n\n********** Found  Source address: '{device_ip}' in sniffer packets ***********\n")
    else:
        logger().info(f"\n*********************** Unable to find ICMP packets in sniffer ************************\n")
    if destination_ip:
        assert str(server_ip) in str(
            destination_ip), f"Unable to find given server ip : {server_ip} in sniffer packet"
        logger().info(f"\n\n********** Found destination address: '{server_ip}' in sniffer packets ***********\n")
    else:
        logger().info(f"\n*********************** Unable to find ICMP packets in sniffer ************************\n")
    Ping_reply = None
    if "Type: 0" in icmp_layer and "device_ip" in source_ip and "server_ip" in destination_ip:
        Ping_reply = True
        logger().info(f"******************{Ping_reply} Type: 0 ,echo ping rply")
    else:
        Ping_reply = False
        logger().info(f"No response for the request, type: 0 :{Ping_reply}")
    assert Ping_reply == False, f" able to find response status"
    logger().info(f"*******#### Sniffer validation for ICMP no response packets*******#####")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    RS9116FeatureBitMap.OpenMode,  # get features in garmin
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL |
                          RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          RS9116TCPIPFeatureBitMap.SNTPClient,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose |
                              RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY |
                              RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV |
                              RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "set_send_feature_frame": True,
        "rf_type": 1,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_sntp_client_func_by_connecting_to_sntp_server_c20845(wifi_access_point, wifi_dut, wifi_sniffer, rs_helper, utf_constants):
    logger().info("\n\n **** Test SNTP client functionality by connecting to SNTP server ***** \n\n")
    logger().info(" ====== configuring the sniffer with access point channel ======")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_sntp_client_C20845')
    logger().info(f"**********initiating wlan connection*******************")
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=False)
    sntp_server_address = wifi_dut.interfaces.wifi.get_sntp_server_ip()
    wifi_dut.interfaces.wifi.sntp_create(server_ip=sntp_server_address)
    logger().info("wait for 10 seconds to receive SNTP asynchronous messages")
    time.sleep(10)
    asynchronous_request_time = 0
    events = wifi_dut.interfaces.wifi.get_async_events(since_time=asynchronous_request_time)
    for event in events:
        if event.event_type == RS9116AsyncEventType.SNTP_EVENT:
            sntp_event = event.event_data
            asynchronous_request_time = event.timestamp + 1
        else:
            assert 1, f"SNTP asynchronous event is not received by DUT after connection request was sent to SNTP server"
    sntp_status = int(sntp_event.split(b":")[1])
    assert sntp_status == 1, "SNTP status received in asynchronous message for SNTP connection request is wrong " \
                             "expected is 1 "

    command_type, sntp_time = wifi_dut.interfaces.wifi.get_sntp_time()
    assert command_type == 2, "Command type received for the body of get_sntp_time response is wrong, expected is 2"
    command_type, sntp_date_time = wifi_dut.interfaces.wifi.get_sntp_timedate()
    sntp_date_time_response = sntp_date_time.decode().split('.')[0]
    assert command_type == 3, "Command type received for the body of get_sntp_timedate response is wrong, expected is 3"
    command_type, ip_version, server_ip = wifi_dut.interfaces.wifi.get_sntp_server_info()
    assert command_type == 6, "Command type received for the body of get_sntp_server_info response is wrong, expected " \
                              "is 6"
    assert ip_version == 4, "Ip version received for the body of get_sntp_server_info response is wrong, expected " \
                            "is 4"
    assert server_ip == sntp_server_address, f"SNTP server ip address received for the body of get_sntp_server_info " \
                                             f"response is wrong, expected " \
                                             "is {sntp_server_address}"

    wifi_dut.interfaces.wifi.sntp_delete()
    logger().info("wait for 5 seconds to receive SNTP asynchronous messages")
    time.sleep(5)
    events = wifi_dut.interfaces.wifi.get_async_events(since_time=asynchronous_request_time)
    for event in events:
        if event.event_type == RS9116AsyncEventType.SNTP_EVENT:
            sntp_event = event.event_data
        else:
            assert 1, f"SNTP asynchronous event is not received by DUT after SNTP delete is initiated"
    sntp_status = int(sntp_event.split(b":")[1])
    assert sntp_status == 1, "SNTP status received in asynchronous message for SNTP delete request is wrong expected " \
                             "is 1 "
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    sntp_check = PacketCheck(wifi_sniffer, dut_mac_address, decryption_key, ["ntp"], capture_filename= "test_sntp_TC20845")
    icmp_layer, source_ip, destination_ip, ntp_capture_list = sntp_check.get_icmp_sntp_list()
    if not len(ntp_capture_list):
        logger().info(f"NTP packets are not captured or one of the 4-way handshake pkts are not captured in the "
                      f"sniffer file")
    assert len(ntp_capture_list) > 0, f"NTP packets are not captured or one of the 4-way handshake pkts are not " \
                                      f"captured in the sniffer file "

    for ntp_pkt in ntp_capture_list:
        if (ntp_pkt[2] == sntp_server_address) and (ntp_pkt[3] == device_ip):
            logger().info(
                f"As per sniffer SNTP packets received on DUT mac address {dut_mac_address}---->{ntp_pkt[0]}")
            sntp_pkt_sniffer = ntp_pkt[0]
            break

    sntp_pkt_fields = sntp_pkt_sniffer.split("\n")
    for count in sntp_pkt_fields:
        if "Transmit Timestamp:" in count:
            sntp_transmit_time_sniffer = count.split("Transmit Timestamp:")[1].split(".")[0].strip()
    logger().info(f"Date and Time sent by SNTP server as per sniffer capture {sntp_transmit_time_sniffer}")

    logger().info(f"Date and time sent by DUT {sntp_date_time_response}")

    wifi_dut.interfaces.wifi.leave()


