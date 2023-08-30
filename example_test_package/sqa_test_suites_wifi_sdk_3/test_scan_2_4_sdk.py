import time
import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap

def logger():
    return get_logger(__name__)

""" Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Enable the wlan and bt power save mode in dut after the connection
        3. Initiate the Scan from DUT
        4. Verify the scan results

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC
        
    Author: Abdul Azeez
"""

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0}
)
# This test case verifies All Channels Scan in 2.4 Ghz by giving channel number as Zero
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_all_scan_channels_c19056(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter, sl_collections):
    try:
        test_name = request.node.name
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        for channel in channels_list_2g:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(2)
            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            assert (len(scan_results) >= 1), "Scan failed"
            logger().info(scan_results)
            time.sleep(15)
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                f'Unable to find probe request broadcast packet in channel:{channel}'
            logger().info(f"found Probe req(Broadcast) in channel:{channel}'")
            logger().info("DUT scan success in all channels")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# This test case verifies the scan Response Based on RSSI
def test_wifi_sdk_scan_check_rssi_c19060(wifi_dut, wifi_access_point, sl_collections):
    try:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        logger().info("enable the scan in dut on channel 0...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        logger().info(scan_results)
        scan_count = len(scan_results)
        assert scan_count > 0, "Scan results not found"
        previous_rssi = 0

        for count in scan_results:
            assert previous_rssi >= count.rssi, "scan result is not based on the rssi"
            previous_rssi = count.rssi
            logger().info(f"scan results are based on rssi: {count.rssi}")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_scan_ssid_32bytes_c19064(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter, sl_collections):
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        ssid_list = ['test123test123test123test123test', 'test1*@test1*#test1*@test1*$test',
                     'test12.test12.test12.test12.test',  '了是不了是不了是不了']

        for ssid in ssid_list:
            logger().info(f"configuring the Sniffer with the channel : {wifi_access_point.interfaces.wifi.channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            time.sleep(5)
            # initiates the access point with channel given in list
            logger().info(f"Setting access point with ssid {ssid}...")
            wifi_access_point.interfaces.wifi.start_ap(ssid=ssid)
            time.sleep(10)
            logger().info(f"\n######=====>>>>Configuring the 32byte SSID: {ssid}\n")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=wifi_access_point.interfaces.wifi.channel, ssid=ssid)
            time.sleep(2)
            logger().info("\nscan_results\n")
            assert len(scan_results) >= 1, f"32 bytes ssid not found in scan results"
            logger().info(f"Validate Probe req(Broadcast)")
            wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_ssid', "broadcast_ssid": False})
# This case verifies the scan in hidden mode of AP for all channels
def test_wifi_sdk_hidden_scan_all_channels_c19062(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter, sl_collections):
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        logger().info(f"configuring the Sniffer with the channel : {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                        da_addr=da_addr,
                                                                                        filter_name="probe_request")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        logger().info(scan_results)
        time.sleep(10)
        assert len(scan_results) >= 1, "scan failed"
        for count in scan_results:
            assert count.ssid == wifi_access_point.interfaces.wifi.ssid
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(f"Validate Probe req(Broadcast)")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            f'Unable to find probe request broadcast packet in channel:{wifi_access_point.interfaces.wifi.channel}'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.PSKSecurity,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_scan_us_region_2_4_c19067(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter, sl_collections):
    try:
        logger().info("Configured DUT in US region")
        test_name = request.node.name
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")

        for channel in channels_list_2g:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(2)
            logger().info("enables the scan in dut on channel 0...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(15)
            assert (len(scan_results) >= 1), "scan failed"
            logger().info(scan_results)
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                                                        sa_addr=sa_addr, da_addr=da_addr, filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                f'Unable to find probe request broadcast packet in channel:{channel}'
            logger().info(f"found Probe req(Broadcast) in channel:{channel}'")
            logger().info("DUT scan success in all channels in US region")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
