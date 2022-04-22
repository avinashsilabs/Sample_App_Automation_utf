import time
import pytest
from utf.utils.iperf.iperf_utils import ping
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.wifi import WlanError
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116CustomFeatureBitMap


def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 5Ghz
        2. Enable the wlan and bt power save mode in dut after the connection
        3. Configure the region and rejoin parameters in dut
        4. Initiate the Scan from DUT
        5. Verify the scan results 

    Author: RaviNemali
"""
logger().info(" ********* READ DESCRIPTION AT LINE-31,FOR HARNESS CHANGES AND CONFIG'S **********")
""""
++++++++ Harness Changes & test limit's ++++++++

    Harness configs:
                 CONFIG1: configure DUT type  -- rs9116_sapi in default section of harness.
                 CONFIG2: Ap details -- IP addr, Port,login details in ap section of harness.
                 CONFIG3: Default Ap -- Set your ap name as default ap for tests in harness.
                 CONFIG4: Sniffer -- Set IP addr,login details of NUC in airpcap fields of harness.
    Test Limits: This test plan limits to the 5ghz band of dut for DFS and Non-DFS channels.
    AP Configs: Access point is configured from 36 - 64, above that ap support ends.

"""

# configure the ping count for dut
ping_count = 10

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_scan_5Ghz_usregion_C19400(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        logger().info("This test case is not supported with 100-140 channels as AP doe's not have support")
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_5Ghz_usregion_C19400"

        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        channel_list = [36,40,44,48,52,56,60,64,149,153,157,161,165]
        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(80)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            #validating beacons from AP
            packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(2)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

            for count in range(1, 3):
                try:
                    scan_fail = 1
                    # DUT connects to AP after join_ap API is executed
                    logger().info("Scanning to the Wifi Access Point")
                    time.sleep(5)
                    wifi_dut.interfaces.wifi.scan(ssid=None,channel=0)
                    scan_fail = 0
                    break
                except:
                    logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
                    time.sleep(1)
            if scan_fail:
                logger().info(f"Scanning to the AP has failed")
                assert scan_fail == 0, "ap is beaconning, scanning to the AP is failed, might be fw issue !"

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter2 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
                'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 2,
        "module_type": 1,
    }
)
@pytest.mark.config('wifi_access_point',wifi ={"region": 'Europe'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_5Ghz_euregion_C19401(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        logger().info("This test case is not supported with 100-140 channels as AP doe's not have support")
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_5Ghz_euregion_C19401"

        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        channel_list = [36,40,44,48,52,56,60,64]
        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(70)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            #validating beacons from AP
            packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(2)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(3)
            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

            for count in range(1, 3):
                try:
                    scan_fail = 1
                    # DUT connects to AP after join_ap API is executed
                    logger().info("Scanning to the Wifi Access Point")
                    time.sleep(5)
                    wifi_dut.interfaces.wifi.scan(ssid=None,channel=0)
                    scan_fail = 0
                    break
                except:
                    logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
                    time.sleep(1)
            if scan_fail:
                logger().info(f"Scanning to the AP has failed")
                assert scan_fail == 0, "ap is beaconning, scanning to the AP is failed, might be fw issue !"

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter2 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info(" Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
                'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.skip(reason="Limitation from japan region ap")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 3,
        "module_type": 1,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_5Ghz_jp_region_C19402(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        validation = True

        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap bssid: {ap_bssid}")

        channel_list = [36, 52]
        for channel in channel_list:
            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(5)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file='test_scan_5Ghz_jp_region_C19402')

            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(90)
            logger().info("scan for the ap's.....")
            time.sleep(5)
            ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
            logger().info(f"scan list is:{ap_mac}")
            ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
            logger().info(f'AP BSSID = {ap_bssid}')

            assert len(ap_mac) > 0, "failed to scan...."

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets

            packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info(" Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 2,
        "module_type": 1,

    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_all_channels_connect_56_5Ghz_DFS_euregion_C19404_case1(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        validation = True
        testcase = "test_scan_all_channels_connect_56_5Ghz_DFS_euregion_C19404_case1"


        channel = 56
        wifi_access_point.interfaces.wifi.start_ap(channel=channel)
        time.sleep(80)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap bssid: {ap_bssid}")

        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
        time.sleep(10)

        # validating beacons from AP
        packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
        logger().info("fetched ap beacons, Initiating scan in DUT")
        time.sleep(10)

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

        time.sleep(5)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        logger().info("Initiating scan")
        time.sleep(5)
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        assert scan_results, "failed to scan...."

        logger().info("Joining ap...")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        time.sleep(5)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info("pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validating the probe request packets
        packet_filter2 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validate probe request packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 2,
        "module_type": 1,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 64})
def test_scan_all_channels_connect_64_5Ghz_DFS_euregion_C19404_case2(wifi_dut, wifi_access_point,wifi_sniffer):
    logger().info("******* Channel limitation for 104, running this test with channel 64 *******")
    rejoin_max = 10
    scan_interval = 6
    beacon_missedcount = 40
    first_time_retry = 0
    timeout = 10
    validation = True
    testcase = "test_scan_all_channels_connect_64_5Ghz_DFS_euregion_C19404_case2"

    channel = 64
    wifi_access_point.interfaces.wifi.start_ap(channel=channel)
    time.sleep(80)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"ap bssid: {ap_bssid}")
    time.sleep(10)

    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
    time.sleep(10)

    # validating beacons from AP
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
    logger().info("fetched ap beacons, Initiating scan in DUT")
    time.sleep(10)

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    time.sleep(5)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

    logger().info("Setting DUT in wlan power save...")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
    assert enable_wifi_ps, 'failed to enable'

    logger().info("Setting DUT in bt power save...")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    assert enable_bt_ps, 'failed to enable'

    logger().info("Enabling rejoin...")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                    beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                    timeout=timeout)

    logger().info("Initiating scan")
    time.sleep(5)
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    assert scan_results, "failed to scan...."

    logger().info("Joining ap...")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    time.sleep(5)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    # Fetches the DUT mac address
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # Validating the probe request packets
    packet_filter2 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Validate probe request packet")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
    'packet_count'], 'Unable to find probe request packet in sniffer '

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 2,
        "module_type": 1,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_104_channel_5Ghz_DFS_euregion_C19404_case3(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        logger().info("******* Channel limitation for 104, running this test with channel 52 *******")
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        validation = True
        testcase = "test_scan_104_channel_5Ghz_DFS_euregion_C19404_case3"

        channel = 64
        wifi_access_point.interfaces.wifi.start_ap(channel=channel)
        time.sleep(80)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap bssid: {ap_bssid}")

        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
        time.sleep(10)

        # validating beacons from AP
        packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
        logger().info("fetched ap beacons, Initiating scan in DUT")
        time.sleep(10)

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

        time.sleep(5)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        logger().info("Initiating scan")
        time.sleep(5)
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=52)
        assert scan_results, "failed to scan...."


        logger().info("Joining ap...")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"

        time.sleep(5)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info("pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validating the probe request packets
        packet_filter2 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validate probe request packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 2,
        "module_type": 1,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_connect_5Ghz_DFS_euregion_C19404_case4(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        logger().info("******* Channels limitation for 100,104,149, running this test with channel 56,60,64 *******")
        logger().info("This test case is not supported with 100-140 channels as AP doe's not have support")
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_connect_5Ghz_DFS_euregion_C19404_case4"

        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        channel_list = [36,48,52,149]
        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(70)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            # validating beacons from AP
            packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(2)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

            for count in range(1, 3):
                try:
                    scan_fail = 1
                    # DUT connects to AP after join_ap API is executed
                    logger().info("Scanning to the Wifi Access Point")
                    time.sleep(5)
                    wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
                    scan_fail = 0
                    break
                except:
                    logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
                    time.sleep(1)
            if scan_fail:
                logger().info(f"Scanning to the AP has failed")
                assert scan_fail == 0, "ap is beaconning, scanning to the AP is failed, might be fw issue !"

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter2 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
                'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.skip(reason="skipping this test, limitation for japan region access point ")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 3,
        "module_type": 1,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 56})
def test_scan_all_channels_connect_56_5Ghz_DFS_jpregion_C19405_case1(wifi_dut, wifi_access_point):
    logger().info("Setting DUT in wlan power save...")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
    assert enable_wifi_ps, 'failed to enable'

    logger().info("Setting DUT in bt power save...")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    assert enable_bt_ps, 'failed to enable'

    logger().info("Enabling rejoin...")
    wifi_dut.interfaces.wifi.rejoin()

    logger().info("Initiating scan....")
    time.sleep(5)
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    logger().info(scan_results)
    assert scan_results, "No ap found....."

    logger().info("Joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

@pytest.mark.skip(reason="skipping this test, limitation for japan region access point ")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 3,
        "module_type": 1,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 64})
def test_scan_all_channels_connect_104_5Ghz_DFS_jpregion_C19405_case2(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()

        logger().info("Initiating scan...")
        time.sleep(5)
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        logger().info("Joinig ap...")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(scan_results)

@pytest.mark.skip(reason="skipping this test, limitation for japan region access point ")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 3,
        "module_type": 1,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 64})
def test_scan_104_channel_5Ghz_DFS_jpregion_C19405_case3(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Initiating selective chnnel scan...")
        scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=64, ssid=None)
        logger().info("Joining ap...")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info(scan_results)
    logger().info(f"Associated in {t.duration} seconds")

@pytest.mark.skip(reason="skipping this test, limitation for japan region access point ")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 3,
        "module_type": 1,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"channel": 36})
def test_scan_connect_channels_36_48_52_100_149_jpregion_C19405_case4(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        channel_list = {1: 36, 2: 48, 3: 52, 4: 100, 5: 104, 6: 149}
        channel_bitmap_5 = 0
        scan_feature_extend = 0
        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()

        for count in channel_list:
            channel_bitmap_5 += 1 << (count - 1)
            logger().info("Initiating selective channel scan...")
            time.sleep(5)
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                           scan_bitmap_5=channel_bitmap_5,
                                                                           scan_feature=scan_feature_extend)
            logger().info(scan_results)
            assert len(scan_results) >= 1
            logger().info("Joining ap...")
        result = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        assert result
    logger().info(f"Associated in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_all_channels_in_5Ghz_C19406(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        logger().info("This test case is not supported with 100-140 channels as AP doe's not have support")
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_all_channels_in_5Ghz_C19406"

        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        channel_list = [36,40,44,48,52,56,60,64,149,153,157,161,165]

        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(70)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            # validating beacons from AP
            packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(2)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

            for count in range(1, 3):
                try:
                    scan_fail = 1
                    # DUT connects to AP after join_ap API is executed
                    logger().info("Scanning to the Wifi Access Point")
                    wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
                    scan_fail = 0
                    break
                except:
                    logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
                    time.sleep(1)
            if scan_fail:
                logger().info(f"Scanning to the AP has failed")
                assert scan_fail == 0, "ap is beaconning, scanning to the AP is failed, might be fw issue !"

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter2 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
                'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "testscan"})
def test_all_channels_scan_by_giving_channel_as_zero_C19407(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        logger().info("This test case is not supported with 100-140 channels as AP doe's not have support")
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_all_channels_scan_by_giving_channel_as_zero_C19407"

        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        channel_list = [36,40,44,48,52,56,60,64,149,153,157,161,165]
        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(70)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            # validating beacons from AP
            packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(2)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

            for count in range(1, 3):
                try:
                    scan_fail = 1
                    # DUT connects to AP after join_ap API is executed
                    logger().info("Scanning to the Wifi Access Point")
                    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
                    scan_fail = 0
                    break
                except:
                    logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
                    time.sleep(1)
            if scan_fail:
                logger().info(f"Scanning to the AP has failed")
                assert scan_fail == 0, "ap is beaconning, scanning to the AP is failed, might be fw issue !"

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter2 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
                'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_all_channels_by_giving_channels_in_bitmap_C19409(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_test_scan_all_channels_by_giving_channels_in_bitmap_C19409"

        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        channel_list = {0:36,1:40,2:44,3:48,4:52,5:56,6:60,7:64,20:149,21:153,22:157,23:161,24:165}
        channel_bitmap_5 = 0
        scan_feature_extend = 0

        for count in channel_list:
            channel_bitmap_5 += 1 << (count)

        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel_list[channel])
            time.sleep(70)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list[channel])
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            # validating beacons from AP
            packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(2)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list[channel])

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

            logger().info("Initiating selective channel scan...")
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                           scan_bitmap_2_4=0,
                                                                           scan_bitmap_5=channel_bitmap_5,
                                                                           scan_feature=scan_feature_extend)
            logger().info(scan_results)
            assert len(scan_results) >= 1, "failed to scan...."
            channel_selected = 0

        for count1 in scan_results:
            for device_channel in channel_list:
                if count1.rf_channel == channel_list[device_channel]:
                    channel_selected = channel_selected + 1

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validating the probe request packets
        packet_filter2 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel =={channel_list[channel]}'

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validate probe request packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
                    'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 2,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    }
)
def test_scan_all_channels_in_dual_band_C19408(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_all_channels_in_dual_band_C19408"

        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        channel_list = [1,2,3,4,5,6,7,8,9,10,11,36,40,44,48,52,56,60,64,149,153,157,161,165]
        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(70)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            # validating beacons from AP
            packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(2)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

            for count in range(1, 3):
                try:
                    scan_fail = 1
                    # DUT connects to AP after join_ap API is executed
                    logger().info("Scanning to the Wifi Access Point")
                    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
                    scan_fail = 0
                    break
                except:
                    logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
                    time.sleep(1)
            if scan_fail:
                logger().info(f"Scanning to the AP has failed")
                assert scan_fail == 0, "ap is beaconning,scanning to the AP is failed, might be fw issue !"

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter2 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
                'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 2
    }
)
def test_all_channels_scan_by_setting_all_channels_in_bitmap_dual_band_C19410(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        channel_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        channel_list1 = {0:36,1:40,2:44,3:48,4:52,5:56,6:60,7:64,20:149,21:153,22:157,23:161,24:165}

        scan_expected_time = 0
        channel_bitmap_2_4 = 0
        channel_bitmap_5 = 0
        scan_feature_extend = 0
        testcase = "test_all_channels_scan_by_setting_all_channels_in_bitmap_dual_band_C19410"

        for count in channel_list1:
            channel_bitmap_5 += 1 << (count)
            scan_expected_time += 100

        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100

        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(70)
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            # validating beacons from AP
            packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(2)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

            logger().info("Initiating selective channel scan...")
            time.sleep(5)
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                           scan_bitmap_2_4=channel_bitmap_2_4,
                                                                           scan_bitmap_5=channel_bitmap_5,
                                                                           scan_feature=scan_feature_extend)

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter3 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
                'packet_count'], 'Unable to find probe request packet in sniffer '

        logger().info(f"scan list is {scan_results}")
        assert scan_results, "failed to scan..."

        for channel in channel_list1:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel_list1[channel])
            time.sleep(70)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list1[channel])
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            # validating beacons from AP
            packet_filter2 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(5)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list1[channel])

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')
            logger().info("Initiating selective channel scan...")
            time.sleep(5)
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                           scan_bitmap_2_4=channel_bitmap_2_4,
                                                                           scan_bitmap_5=channel_bitmap_5,
                                                                           scan_feature=scan_feature_extend)
            logger().info(f"scan list is {scan_results}")
            assert scan_results, "failed to scan..."

            # Validating the probe request packets
            packet_filter4 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel_list1[channel]}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
                'packet_count'], 'Unable to find probe request packet in sniffer '

        assert len(scan_results) >= 1
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    }
)
def test_scan_for_channels_36_40_48_52_100_149_157_161_165_C19411(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_for_channels_36_40_48_52_100_149_157_161_165_C19411"

        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        channel_list = {0:36,1:40,3:48,4:52,20:149,22:157,23:161,24:165}
        channel_bitmap_5 = 0
        scan_feature_extend = 0

        for count in channel_list:
            channel_bitmap_5 += 1 << (count)

        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel_list[channel])
            time.sleep(70)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list[channel])
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            # validating beacons from AP
            packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(2)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list[channel])

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

            logger().info("Initiating selective channel scan...")
            time.sleep(5)
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                           scan_bitmap_2_4=0,
                                                                           scan_bitmap_5=channel_bitmap_5,
                                                                           scan_feature=scan_feature_extend)

        logger().info(scan_results)
        assert len(scan_results) >= 1, "failed to scan....  "

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validating the probe request packets
        packet_filter4 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel_list[channel]}'

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validate probe request packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 2,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    }
)
def test_scan_in_dual_band_for_AP_channels_6_and_36_by_setting_channel_as_1_in_dut_C19412(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_in_dual_band_for_AP_channels_6_and_36_by_setting_channel_as_1_in_dut_C19412"

        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        channel_list = [6]
        channel_list1 = {0:36}
        channel_bitmap_2_4 = 0
        channel_bitmap_5 = 0
        scan_feature_extend = 0

        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(70)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            # validating beacons from AP
            packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(2)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

            logger().info("Initiating selective channel scan....")
            time.sleep(5)
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0,ssid=None,
                                                                           scan_bitmap_2_4=channel_bitmap_2_4,
                                                                           scan_bitmap_5=0,
                                                                           scan_feature=scan_feature_extend)
            logger().info(f"scan list: {scan_results}")

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter4 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
                'packet_count'], 'Unable to find probe request packet in sniffer'
        assert len(scan_results) >= 1, "failed to scan...."

        for channel in channel_list1:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel_list1[channel])
            time.sleep(70)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list1[channel])
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            # validating beacons from AP
            packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(2)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list1[channel])

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

            logger().info("Initiating selective channel scan...")
            time.sleep(5)
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0,ssid=None,
                                                                           scan_bitmap_2_4=0,
                                                                           scan_bitmap_5=channel_bitmap_5,
                                                                           scan_feature=scan_feature_extend)
            logger().info(f"scan list: {scan_results}")
            assert len(scan_results) >= 1, "failed to scan...."

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter4 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel_list1[channel]}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
                'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    }
)
def test_scan_5ghz_band_for_channels_36_40_52_56_149_161_165_C19413(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_5ghz_band_for_channels_36_40_52_56_149_161_165_C19413"

        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        channel_list = {0:36,1:40,4:52,5:56,20:149,23:161,24:165}
        channel_bitmap_5 = 0
        scan_feature_extend = 0

        for count in channel_list:
            channel_bitmap_5 += 1 << (count)

        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel_list[channel])
            time.sleep(70)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list[channel])
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            # validating beacons from AP
            packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(2)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list[channel])
            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

            logger().info("Initiating selective channel scan...")
            time.sleep(5)
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                           scan_bitmap_2_4=0,
                                                                           scan_bitmap_5=channel_bitmap_5,
                                                                           scan_feature=scan_feature_extend)
            logger().info(f"scan list: {scan_results}")
            assert len(scan_results) >= 1, "failed to scan..."

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter4 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel_list[channel]}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
                'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 2,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    }
)
def test_scan_selective_channels_in_dual_bands_C19414(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_selective_channels_in_dual_bands_C19414"

        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        channel_list = [1,3,6,11]
        channel_list1 = {0:36,3:48,20:149,23:161,24:165}
        channel_bitmap_2_4 = 0
        channel_bitmap_5 = 0
        scan_feature_extend = 0

        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)

        for count in channel_list1:
            channel_bitmap_5 += 1 << (count)

        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(70)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            # validating beacons from AP
            packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(2)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')
            logger().info("Initiating selective channel scan...")
            time.sleep(5)
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=channel, ssid=None,
                                                                           scan_bitmap_2_4=channel_bitmap_2_4,
                                                                           scan_bitmap_5=0,
                                                                           scan_feature=scan_feature_extend)
            logger().info(f"scan list: {scan_results}")
            assert scan_results, "failed to scan...."

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter4 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validate probe request packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'Unable to find probe request packet in sniffer '

        for channel in channel_list1:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel_list1[channel])
            time.sleep(70)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list1[channel])
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            # validating beacons from AP
            packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(2)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list1[channel])

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req_5g')
            logger().info("Initiating selective channel scan...")
            time.sleep(5)
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0,ssid=None,
                                                                           scan_bitmap_2_4=0,
                                                                           scan_bitmap_5=channel_bitmap_5,
                                                                           scan_feature=scan_feature_extend)
            logger().info(f"scan list: {scan_results}")
            assert scan_results, "failed to scan...."

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter5 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel_list1[channel]}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
                'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    }
)
def test_scan_for_selective_channels_in_5GHZ_C19415(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_for_selective_channels_in_5GHZ_C19415"

        logger().info("******* limitation from ap side using channels 56,64 instead 100,140 ********")
        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        channel_list = {4:52,5:56,7:64}
        channel_bitmap_2_4 = 0
        channel_bitmap_5 = 0
        scan_feature_extend = 0

        for count in channel_list:
            channel_bitmap_5 += 1 << (count)

        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel_list[channel])
            time.sleep(70)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list[channel])
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            # validating beacons from AP
            packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(2)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list[channel])

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')
            logger().info("Initiating selective channel scan...")
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                           scan_bitmap_2_4=0,
                                                                           scan_bitmap_5=channel_bitmap_5,
                                                                           scan_feature=scan_feature_extend)
            logger().info(f"scan list:{scan_results}")
            assert len(scan_results) >= 1, "failed to scan"

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter4 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel_list[channel]}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
                'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    }
)
def test_scan_for_selective_channels_in_5GHZ_C19416(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_for_selective_channels_in_5GHZ_C19416"
        logger().info("******* limitation from ap side using channels 56,64 instead 100,140 ********")
        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        channel_list = {0:36,4:52,5:56,7:64}
        channel_bitmap_5 = 0
        scan_feature_extend = 0
        for count in channel_list:
            channel_bitmap_5 += 1 << (count)

        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel_list[channel])
            time.sleep(70)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap bssid: {ap_bssid}")

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list[channel])
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_beacons")
            time.sleep(10)

            # validating beacons from AP
            packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {ap_bssid})'
            wifi_sniffer.interfaces.capture.stop_capture()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], "ap beacons not found in sniffer capture,terminating test execution"
            logger().info("fetched ap beacons, Initiating scan in DUT")
            time.sleep(2)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel_list[channel])

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')
            logger().info("Initiating selective channel scan...")
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                           scan_bitmap_2_4=0,
                                                                           scan_bitmap_5=channel_bitmap_5,
                                                                           scan_feature=scan_feature_extend)
            logger().info(f"scan list:{scan_results}")
            assert len(scan_results) >= 1, "failed to scan"

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter4 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel_list[channel]}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
                'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"Associated in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 4,
        "module_type": 1,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"channel": 44})
@pytest.mark.config('wifi_access_point', wifi={"ssid": "testssid"})
def test_regional_scan_world_mode_in_5GHZ_C19418(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        time.sleep(70)

        logger().info("Setting DUT in wlan power save...")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_wifi_ps, 'failed to enable'

        logger().info("Setting DUT in bt power save...")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        assert enable_bt_ps, 'failed to enable'

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                        beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                        timeout=timeout)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap bssid: {ap_bssid}")

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        time.sleep(3)
        validation = True
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_regional_scan_world_mode_in_5GHZ_C19418_probe_req')
        logger().info("Initiating selective channel scan...")

        time.sleep(10)
        logger().info("Initiating selective channel scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        logger().info(f"scan list:{scan_results}")
        assert len(scan_results) >= 1, "failed to scan"

        # Fetches the DUT mac address
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validating the probe request packets
        packet_filter4 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validate probe request packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")