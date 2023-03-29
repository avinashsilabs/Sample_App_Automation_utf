import pytest
import time
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.utils.iperf.iperf_utils import print_dict
from utf_wiseconnect.devices.rs911x import RS9116CoexMode,RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116PowerSaveModes,  RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap, \
    RS9116JoinFeatureBitMap, RS9116Band, RS9116PowerSaveProcedureTypes, SocketType
from utf.interfaces.iperf.iperf_constants import IperfConstants,IperfTrafficType
from random import randint
from utf.utils.thread_base import ThreadBase
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.interfaces.wifi import WlanError

def logger():
    return get_logger(__name__)

"""This function runs below test steps for DUT-RS9116 for WLAN+BLE(Coex) Garmin test cases verification
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
"""Author : Yogitha"""

@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE|RS9116CoexMode.ANT,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | RS9116FeatureBitMap.OpenMode, #get features in garmin
            "tcpip_features" : RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL |RS9116TCPIPFeatureBitMap.DNSClient |RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose |RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY|RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV|RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
            "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "set_send_feature_frame": True,
            "rf_type":1,
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_wlan_connected_standby_c20844(wifi_access_point,wifi_dut,wifi_sniffer,utf_constants):

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
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE|RS9116CoexMode.ANT,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | RS9116FeatureBitMap.OpenMode, #get features in garmin
            "tcpip_features" : RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL |RS9116TCPIPFeatureBitMap.DNSClient |RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose |RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY|RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV|RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
            "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "set_send_feature_frame": True,
            "rf_type":1,
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_wlan_continous_ping_c20833(wifi_access_point, wifi_dut,wifi_sniffer):
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
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE|RS9116CoexMode.ANT,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | RS9116FeatureBitMap.OpenMode, #get features in garmin
            "tcpip_features" : RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL |RS9116TCPIPFeatureBitMap.DNSClient |RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose |RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY|RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV|RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
            "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "set_send_feature_frame": True,
            "rf_type":1,
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_scan_func_after_successful_dut_conn_c20849(wifi_access_point, wifi_dut,wifi_sniffer):
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
        wifi_dut.interfaces.wifi.scan(ssid=None,channel=0,retries=1)
        assert exc_info.value.error_code  == 0x2
        logger().info(
        f"Dut Tried to initiate the scan command after successful connection with AP , observed error code 0x2 which is expected")

@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE|RS9116CoexMode.ANT,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                        RS9116FeatureBitMap.OpenMode,
            "tcpip_features" : RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL |
                               RS9116TCPIPFeatureBitMap.DNSClient |RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose |
                                  RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY |
                                  RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV |
                                  RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
            "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "set_send_feature_frame": True,
            "rf_type":1,
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
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE|RS9116CoexMode.ANT,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                        RS9116FeatureBitMap.OpenMode, #get features in garmin
            "tcpip_features" : RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL |
                               RS9116TCPIPFeatureBitMap.DNSClient |RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose |
                                  RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY |
                                  RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV |
                                  RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
            "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "set_send_feature_frame": True,
            "rf_type":1,
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_wifi_conn_by_providing_wrong_psk_c20847(wifi_access_point, wifi_dut, wifi_sniffer):
    logger().info("\n\n **** Verify Wi-Fi connection by providing the wrong PSK using rsi_wlan_connect_async API ***** \n\n")
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


