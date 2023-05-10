import pytest
import time
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116CoexMode,RS9116FeatureBitMap, RS9116ConfigFeatureBitMap,RS9116PowerSaveModes, \
    RS9116JoinFeatureBitMap, RS9116Band, RS9116TCPIPFeatureBitMap,RS9116PowerSaveProcedureTypes,RS9116CustomFeatureBitMap,\
    RS9116ExtCustomFeatureBitMap,RS9116ExtTCPIPFeatureBitMap, SocketOptions, SocketType


def logger():
    return get_logger(__name__)
"""
This function runs below test steps for DUT-RS9116 for WLAN Alone Garmin test case verification
        1. Configuration of DUT in 2G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. verify the scan functionality with ....... configured SSID 
        5. verify the passphrase with 63 lenght of PSK

    setup requirement:
        1. DUT(RS9116) Q7 board 1.5
        2. EFR32
        3. Raspberry PI4(raspberry device required to run the complete test cases)
        4. Access Point(Third Party AP's)
"""

"""Author: Benazeer K """


@pytest.mark.config(
        "wifi_dut",
            wifi=
            {
                "oper_mode": 0,
                "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
                "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
                "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient,
                "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
                "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
                "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
                    4),
                "set_send_feature_frame": True,
            }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "............", "standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_ssid_with_dots_c16573(wifi_sniffer, wifi_access_point, wifi_dut, rs_helper, utf_constants, request):
    logger().info(" Verifying scan functionality by configuring the all dots in SSID ")
    test_name = request.node.name
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=False)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC : {ap_mac}")
    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()
    logger().info("Sniffer going to stop the capture")
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
        "wifi_dut",
            wifi=
            {
                "oper_mode": 0,
                "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
                "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
                "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient,
                "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
                "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
                "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
                    4),
                "set_send_feature_frame": True,
            }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "wlan_iop_auto", "passphrase": 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzaaaaaaaaaaa'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_passphrase_with_63_length_c16574(wifi_sniffer, wifi_access_point, wifi_dut, rs_helper, utf_constants, request):
    logger().info("Verifying the passphrase with 63 lenght of PSK")
    test_name = request.node.name
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=False)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC : {ap_mac}")
    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()
    logger().info("Sniffer going to stop the capture")
    wifi_sniffer.interfaces.capture.stop_capture()