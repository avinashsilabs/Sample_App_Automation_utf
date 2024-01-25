import time
import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xRegion, Si91xRegionCode, Si91xModuleType, Si91xCustomFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xOperatingMode, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.iperf.iperf_utils import ping

def logger():
    return get_logger(__name__)

"""
setup requirement:
        1. DUT(SiWG917) - 1
        2. Si-MB4002A -1
        3. Raspberry PI4 - 1
        4. Access Point(Third Party AP's) - 2
        5. NUC

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Initiate the Scan from DUT
        3. Verify the scan results

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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
             'ssid': 'same-security',
             'security': 'WPA2',
             'passphrase': '123123123',
             'channel': 1
        },
        1: {
             'ssid': 'same-security',
             'security': 'WPA2',
             'passphrase': '123123123',
             'channel': 1}
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_2aps_same_security_c19065(wifi_dut, wifi_access_points, sl_collections):
    try:

        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        logger().info("enable the scan in dut on channel 0...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_points[0].interfaces.wifi.ssid)
        time.sleep(20)
        logger().info(scan_results)
        scan_list = list(scan_results)
        ssid_count = 0
        logger().info(f"scan_list : {scan_list}")
        logger().info("Validating the scan list...")
        for item in scan_list:
            ssid = str(item).split(" ")[9]
            if (ssid == wifi_access_points[0].interfaces.wifi.ssid) or (ssid == wifi_access_points[1].interfaces.wifi.ssid):
               ssid_count = ssid_count + 1
        logger().info(f"ssid count:{ssid_count}")
        assert ssid_count == 2, "Two aps are not scanned "
        logger().info(f'2 Aps with same ssid: {wifi_access_points[0].interfaces.wifi.ssid} are scanned successfully')
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
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
            'ssid': 'diff_security',
            'security': 'WPA2',
            'passphrase': '123123123',
            'channel': 11,
            'region': 'US'
        },
        1: {
            'ssid': 'diff_security',
            'security': 'Open',
            'passphrase': '123123123',
            'channel': 1,
            'region': 'US'
        }
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_2aps_diff_security_c19066(wifi_dut, wifi_access_points, sl_collections):
    try:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        logger().info("enable the scan in dut on channel 0...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_points[0].interfaces.wifi.ssid)
        time.sleep(20)
        logger().info("scan_results...")
        scan_list = list(scan_results)
        ssid_count = 0
        logger().info(f"scan_list : {scan_list}")
        logger().info("Validating the scan list...")
        for item in scan_list:
            security = str(item).split(" ")[3]
            ssid = str(item).split(" ")[9]
            if (ssid == wifi_access_points[0].interfaces.wifi.ssid) or (
                    ssid == wifi_access_points[1].interfaces.wifi.ssid):
                ssid_count = ssid_count + 1
        logger().info(f"ssid count:{ssid_count}")
        assert ssid_count == 2, "Two aps are not scanned "
        logger().info(
            f'2 aps with same ssid :{wifi_access_points[1].interfaces.wifi.ssid}and different password :WPA2 and '
            f'WPA scanned successfully')
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'TESTTESTTEST2',
        'security': 'WPA2',
        'passphrase': '123123123',
        'region': 'Europe'
    }
)
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_regional_scan_in_EU_region_c19069(wifi_sniffer, wifi_dut, wifi_access_point, sniffer_filter, request, sl_collections):

    try:
        test_name = request.node.name
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        channel_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            logger().info("Initiating scan...")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
            logger().info("Initiating scan...")
            scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
            time.sleep(20)
            logger().info(scan_results)
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count'], \
                f'Unable to find probe request broadcast packet in channel:{channel}'

            logger().info(f"found Probe req(Broadcast) in channel:{channel}'")
        logger().info("DUT scan success in all channels")
        logger().info("Dut is able to scan successfully in Europe region")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
             'ssid': 'EU_TEST',
             'security': 'WPA2',
             'passphrase': '123123123',
              'channel': 13,
              'region': 'Europe'

        },
        1: {
             'ssid': 'TESTTESTTEST2',
             'security': 'WPA2',
             'passphrase': '123123123',
             'channel': 1,
             'region': 'US'
        }
    }
)
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
        "region_code":"worldwide"
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_scan_and_connect_in_world_domain_c19075(wifi_dut, utf_constants, wifi_access_points, wifi_sniffer, request, sniffer_filter, sl_collections):
    try:
        test_name = request.node.name
        mode = "power_save_low_latency"
        ping_count = utf_constants.get("ping_count")
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[1].interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(20)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "scan results not found"
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")
        ap_bssid = wifi_access_points[1].interfaces.wifi.bssid
        logger().info(f"AP MAC: {ap_bssid}")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_points[1])
        ip_config = wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

        logger().info(f"....Applying performance profile mode : {mode}")
        wifi_dut.interfaces.wifi.set_performance_profile(mode)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        logger().info(f"Initiating ping to DUT ip {device_ip} after power save")
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(20)
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address, da_addr=ap_bssid,
                                                                                        filter_name="assoc_req_resp_eapol_4_way_handshake")
        # validating ps poll with power managment bit set to 1
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                        filter_name="ps_poll")
        logger().info(f"Validate Assoc req, resp & eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            f'Unable to find Association response packet  in sniffer'
        logger().info(f"Validate PS poll packet)")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            f'Unable to find ps poll with power management bit set to 1 packet  in sniffer'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
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
        "region_code":"worldwide"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 6, "standard": '11n', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_scan_and_connect_in_world_domain_c19078(wifi_dut, utf_constants, wifi_access_point, request, wifi_sniffer, sniffer_filter, sl_collections):
    try:
        test_name = request.node.name
        mode = "power_save_low_latency"
        ping_count = utf_constants.get("ping_count")
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # Scan for the AP's
        logger().info("DUT initiated unicast probe request to fetch ap mac")
        time.sleep(10)
        scan_result = wifi_dut.interfaces.wifi.scan(channel=6, ssid=wifi_access_point.interfaces.wifi.ssid)
        time.sleep(20)
        logger().info(f'Scan results are : {scan_result}')
        assert len(scan_result) >= 1, "scan results not found"
        # This API connects STA to the third party AP
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        ip_config = wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        wifi_dut.interfaces.wifi.set_performance_profile(mode=mode)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        logger().info(f"Initiating ping to DUT ip {device_ip} after power save")
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        # Fetches the DUT mac address
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        time.sleep(20)
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                        da_addr=da_addr,
                                                                                        filter_name="assoc_req_resp_eapol_4_way_handshake")
        # validating ps poll with power managment bit set to 1
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                        filter_name="ps_poll")

        logger().info(f"Validate Assoc req, resp & eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            f'Unable to find Association response packet  in sniffer'

        logger().info(f"Validate PS poll packet)")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            f'Unable to find ps poll with power management bit set to 1 packet  in sniffer'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
             'ssid': 'EU_TEST',
             'security': 'WPA2',
             'passphrase': '123123123',
             'channel': 13,
             'region': 'Europe'

        },
        1: {
             'ssid': 'US_TEST',
             'security': 'WPA2',
             'passphrase': '123123123',
             'channel': 1,
             'region': 'US'
        },

        2: {
             'ssid': 'JAPAN_TEST',
             'security': 'WPA2',
             'passphrase': '123123123',
             'channel': 6,
             'region': 'japan'
        }
    }
)
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
        "region_code":"worldwide"
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_scan_and_connect_in_world_domain_c19076(wifi_dut, utf_constants, wifi_access_points, wifi_sniffer, request, sniffer_filter, sl_collections):
    try:
        test_name = request.node.name
        mode = "power_save_low_latency"
        ping_count = utf_constants.get("ping_count")
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[0].interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.scan(ssid=wifi_access_points[1].interfaces.wifi.ssid, channel=1)
        time.sleep(2)
        wifi_dut.interfaces.wifi.scan(ssid=wifi_access_points[2].interfaces.wifi.ssid, channel=6)
        time.sleep(2)
        logger().info("Initiating scan...")
        logger().info("enable the scan in dut on channel 0...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_points[0].interfaces.wifi.ssid,
                                      security="wpa2",
                                      passphrase=wifi_access_points[0].interfaces.wifi.passphrase,
                                      channel=0, timeout=60)

        time.sleep(20)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "scan results not found"
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")
        ap_bssid = wifi_access_points[0].interfaces.wifi.bssid
        logger().info(f"AP MAC: {ap_bssid}")
        ip_config = wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

        logger().info(f"....Applying performance profile mode : {mode}")
        wifi_dut.interfaces.wifi.set_performance_profile(mode)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        logger().info(f"Initiating ping to DUT ip {device_ip} after power save")
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(20)
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address, da_addr=ap_bssid,
                                                                                        filter_name="assoc_req_resp_eapol_4_way_handshake")
        # validating ps poll with power managment bit set to 1
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                        filter_name="ps_poll")
        logger().info(f"Validate Assoc req, resp & eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            f'Unable to find Association response packet  in sniffer'
        logger().info(f"Validate PS poll packet)")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            f'Unable to find ps poll with power management bit set to 1 packet  in sniffer'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)