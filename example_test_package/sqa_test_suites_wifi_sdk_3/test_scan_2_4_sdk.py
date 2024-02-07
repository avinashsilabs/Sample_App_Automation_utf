import time
import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xRegion, Si91xRegionCode, Si91xModuleType, Si91xCustomFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xOperatingMode, Si91xPowerSaveModes
from utf_wiseconnect_3.tests.sl_status import SLStatus

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

    Author: Shaik Abdul Azeez
"""

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
# This test case verifies All Channels Scan in 2.4 Ghz by giving channel number as Zero
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_all_scan_channels_c19056(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                           sl_collections):
    try:
        test_name = request.node.name
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        for channel in channels_list_2g:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(2)
            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(20)
            assert (len(scan_results) >= 1), "Scan failed"
            logger().info(scan_results)
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# This test case verifies the scan Response Based on RSSI
def test_wifi_sdk_scan_check_rssi_c19060(wifi_dut, wifi_access_point, sl_collections):
    try:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        time.sleep(20)
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
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_scan_ssid_32bytes_c19064(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                           sl_collections):
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        ssid_list = ['test123test123test123test123test', 'test1*@test1*#test1*@test1*$test',
                     'test12.test12.test12.test12.test', '了是不了是不了是不了']

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
            time.sleep(20)
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
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_ssid', "broadcast_ssid": False})
# This case verifies the scan in hidden mode of AP for all channels
def test_wifi_sdk_hidden_scan_all_channels_c19062(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                                  sl_collections):
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
                                                                                        filter_name="hidden_ssid_scan")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        time.sleep(20)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "scan failed"
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(f"Validate Probe req(Broadcast)")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            f'Unable to find probe request broadcast packet in channel:{wifi_access_point.interfaces.wifi.channel}'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_scan_us_region_2_4_c19067(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                            sl_collections):
    try:
        logger().info("Configured DUT in US region")
        test_name = request.node.name
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
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
            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(20)
            assert (len(scan_results) >= 1), "scan failed"
            logger().info(scan_results)
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=sa_addr, da_addr=da_addr, filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(f"**** unable to find the Probe requests in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels in US region")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# This test case verifies the scan functionality with max scan of dut
def test_wifi_sdk_scan_max_aps_c19061(wifi_dut, wifi_access_point, sl_collections):
    try:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        channel_bitmap_2_4 = 0
        # enables the scan in DUT with the given channel bitmap value
        logger().info("Initiating selective channel scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4)
        time.sleep(20)
        logger().info(scan_results)
        logger().info(len(scan_results))
        if len(scan_results) == 11:
            assert True, f"Dut has scanned {len(scan_results)} Aps"
        else:
            assert False, f"To scan more number of APs, Need to keep setup in open air environment"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# This test case verifies the scan functionality for channles 1-11
def test_wifi_sdk_all_chan_scan_with_channel_bitmap_c19057(wifi_sniffer, wifi_dut, wifi_access_point, request,
                                                           sl_collections, sniffer_filter):
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        channel_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100

        for channel in channel_list:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_sel_ch_{channel}")
            time.sleep(3)

            logger().info("Initiating the scan in DUT with the given channel bitmap value...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4)
            time.sleep(20)
            logger().info(scan_results)
            assert len(scan_results) >= 1, "Scan results not found"
            channel_selected = 0
            for count in scan_results:
                assert (count.rf_channel in channel_list), "Scan should happen only in selected channels"

            logger().info("Stop sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in selected channels")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# Verifies the scan functionality with the channel 1,6,8
def test_wifi_sdk_scan_selective_channel_c19058(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                                sl_collections):
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        channel_list = [1, 6, 8]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100

        for channel in channel_list:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_sel_ch_{channel}")
            time.sleep(3)
            logger().info("Initiating the scan in DUT with the given channel bitmap value...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4, )
            time.sleep(20)
            logger().info(scan_results)
            assert len(scan_results) >= 1, "scan results not found"
            for count in scan_results:
                assert (count.rf_channel in channel_list), f"Scan should happen only in selected channels"

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")

            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in selected channels")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# Verifies the scan functionality with the channel 1,3,6,11
def test_wifi_sdk_scan_selective_channel_c19059(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                                sl_collections):
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        channel_list = [1, 3, 6, 11]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100

        for channel in channel_list:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_sel_ch_{channel}")
            time.sleep(5)

            logger().info("Initiating the scan in DUT with the given channel bitmap value...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4)
            time.sleep(20)
            logger().info(scan_results)
            assert len(scan_results) >= 1, "Scan results not found"
            for count in scan_results:
                assert (count.rf_channel in channel_list), "Scan should happen only in selected channels"

            logger().info("Stop sniffer capture")
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in selected channels")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code":"europe"
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
def test_wifi_sdk_scan_all_channels_in_EU_region_c19070(wifi_dut, wifi_sniffer, wifi_client, request, sl_collections,
                                                        sniffer_filter):
    try:
        test_name = request.node.name
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")

        for channel in channels_list_2g:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(5)
            logger().info("enable the scan in dut on channel 0...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(20)
            assert (len(scan_results) >= 1), "scan failed"
            logger().info(scan_results)

            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels")
        logger().info("Dut is able to scan successfully in Europe region")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code":"japan"
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_scan_all_channels_in_japan_region_c19071(wifi_dut, wifi_sniffer, wifi_client, request, sniffer_filter,
                                                           sl_collections):
    try:
        test_name = request.node.name
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")

        for channel in channels_list_2g:
            if channel == 14:
                logger().info(f"channel : {channel} not supported by NUC,skipping the channel")
                continue
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(5)

            logger().info("enable the scan in dut on channel 0...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(20)
            assert (len(scan_results) >= 1), "Scan Failed"
            logger().info(scan_results)

            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels")
        logger().info("Dut is able to scan successfully in Japan region")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "hidden_ssid", "broadcast_ssid": False})
# Verifies the scan in selected channels with the ap set in hidden mode
def test_wifi_sdk_hidden_scan_sel_chan_c19063(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                              sl_collections):
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        channel_list = [1, 5, 9]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100

        for channel in channel_list:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")

            logger().info("Starting the access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(5)
            logger().info("Initiating the scan in DUT with the given channel bitmap value...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None,
                                                         scan_bitmap_2_4=channel_bitmap_2_4)
            time.sleep(20)
            logger().info(scan_results)
            assert len(scan_results) >= 1

            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="hidden_ssid_scan")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 4,
        "region_code":"worldwide"
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_scan_all_channels_in_worldwide_region_c148601(wifi_dut, wifi_sniffer, wifi_client, request, sniffer_filter,sl_collections):
    try:
        test_name = request.node.name
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")

        for channel in channels_list_2g:
            if channel == 14:
                logger().info(f"channel : {channel} not supported by NUC,skipping the channel")
                continue
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(5)

            logger().info("enable the scan in dut on channel 0...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(20)
            assert (len(scan_results) >= 1), "Scan Failed"
            logger().info(scan_results)

            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels")
        logger().info("Dut is able to scan successfully in worldwide region")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# This test case verifies the scan in us region with cahnnels 12,13,14
def test_wifi_sdk_scan_in_US_region_for_channel_12_13_14_c19068(wifi_dut, wifi_access_point, sl_collections):

    try:
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")

        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode8)

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        channel_list = [12, 13, 14]
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100
            logger().info(f"Initiating the scan in DUT with the given channel bitmap value ---->>>{count}")
            wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4, expected_status=SLStatus.SL_STATUS_SI91X_INVALID_CHANNEL)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)