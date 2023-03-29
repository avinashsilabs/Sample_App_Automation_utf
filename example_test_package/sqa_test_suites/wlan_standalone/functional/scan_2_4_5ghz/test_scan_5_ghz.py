import time
import pytest
from utf.utils.iperf.iperf_utils import ping
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.wifi import WlanError
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
            RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap
from utf import UtfDatabaseProperties
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
""" ********* READ DESCRIPTION AT LINE-31,FOR HARNESS CHANGES AND CONFIG'S ********** """
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
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_scan_5Ghz_US_NonDFS_C19400(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_5Ghz_US_NonDFS_C19400"

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

        channel_list = [36, 40, 44, 48, 149, 153, 157, 161, 165]
        for channel in channel_list:

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            time.sleep(1)
            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}')

            for i in range(0, 2):
                # enables the scan in dut on channel 0
                logger().info("Initiating scan from dut...")
                scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                assert (len(scan_results) >= 1), "Scan failed"
                logger().info(scan_results)
                time.sleep(15)
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
@pytest.mark.config('wifi_access_point', wifi={"region": 'Europe',"channel": 36})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_5Ghz_EU_NonDFS_C19401(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
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

        channel_list = [36, 40, 44, 48]
        for channel in channel_list:

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(1)
            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}')

            for i in range(0, 2):
                # enables the scan in dut on channel 0
                logger().info("Initiating scan from dut...")
                scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                assert (len(scan_results) >= 0), "Scan failed"
                logger().info(scan_results)
                time.sleep(15)

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
@pytest.mark.config('wifi_access_point', wifi={"channel": 36})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_5Ghz_JP_NonDFS_C19402(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_5Ghz_JP_NonDFS_C19402"

        logger().info("AP doesn't have support for JP region,verifying in sniffer")

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

        channel_list = [36, 40, 44, 48]
        for channel in channel_list:

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(1)
            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}')

            for i in range(0, 2):
                # enables the scan in dut on channel 0
                logger().info("Initiating scan from dut...")
                scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                assert (len(scan_results) >= 0), "Scan failed"
                logger().info(scan_results)
                time.sleep(15)
                for count1 in scan_results:
                    logger().info("validating channels in scan response")
                    assert int(count1.rf_channel) < 149, "unexpected channel found in scan results"

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
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_response_in_5Ghz_C19406(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_response_in_5Ghz_C19406"

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

        channel_2_4g = [channel for channel in range(1, 15)]
        # enables the scan in dut on channel 0
        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        assert (len(scan_results) >= 1), "Scan failed"
        logger().info(scan_results)
        for count in scan_results:
            logger().info(f"count: {count}")
            logger().info(f"validating scan response with fields:channel,security_mode,rssi,network_type,ssid,bssid")
            assert (count.rf_channel not in channel_2_4g), "2.4 channel found in scan results"
            fields_list = ["rf_channel", "security_mode", "rssi", "network_type", "ssid", "bssid"]
            for field in fields_list:
                assert field in dir(count), "scan response is not as mentioned to PRM"

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
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_all_chan_scan_in_5Ghz_by_chan_0_C19407(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_all_chan_scan_in_5Ghz_by_chan_0_C19407"

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

        channel_list = [36, 40, 44, 48, 149, 153, 157, 161, 165]
        for channel in channel_list:

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            time.sleep(1)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}')

            for i in range(0, 2):
                # enables the scan in dut on channel 0
                logger().info("Initiating scan from dut...")
                scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                assert (len(scan_results) >= 1), "Scan failed"
                logger().info(scan_results)
                time.sleep(15)

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
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_all_chan_by_chan_in_bitmap_C19409(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_all_chan_by_chan_in_bitmap_C19409"

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

        channel_list = {0: 36, 1: 40, 2: 44, 3: 48, 19: 149, 20: 153, 21: 157, 22: 161, 23: 165}
        channel_list_5g = [36, 40, 44, 48, 149, 153, 157, 161, 165]
        channel_bitmap_5 = 0
        scan_feature_extend = 0

        for count in channel_list:
            channel_bitmap_5 += 1 << (count)

        for channel in channel_list_5g:

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(2)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}')

            for i in range(0, 2):

                logger().info("Initiating selective channel scan...")
                scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                               scan_bitmap_2_4=0,
                                                                               scan_bitmap_5=channel_bitmap_5,
                                                                               scan_feature=scan_feature_extend)
                logger().info(scan_results)
                time.sleep(15)
                assert len(scan_results) >= 1, "failed to scan...."

                for count1 in scan_results:
                        logger().info("validating channels in scan response")
                        assert count1.rf_channel in channel_list_5g, "unexpected channel found in scan results"

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter2 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel =={channel}'

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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_scan_all_channels_in_dual_band_C19408(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
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

        channel_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 149, 153, 157, 161, 165]
        for channel in channel_list:
            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}')

            for i in range(0, 2):
                # enables the scan in dut on channel 0
                logger().info("Initiating scan from dut...")
                scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                assert (len(scan_results) >= 1), "Scan failed"
                logger().info(scan_results)
                time.sleep(20)

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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_all_chan_scan_by_all_chan_in_bitmap_dual_band_C19410(wifi_dut, wifi_access_point,wifi_sniffer):
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
        channel_list1 = {0: 36, 1: 40, 2: 44, 3: 48, 19: 149, 20: 153, 21: 157, 22: 161, 23: 165}
        channel_list_dual = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 149, 153, 157, 161, 165]

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

        for channel in channel_list_dual:
            validation = True
            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}')

            for i in range(0, 2):
                logger().info("Initiating selective channel scan...")
                time.sleep(5)
                scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                               scan_bitmap_2_4=channel_bitmap_2_4,
                                                                               scan_bitmap_5=channel_bitmap_5,
                                                                               scan_feature=scan_feature_extend)

                assert len(scan_results) >= 1,"Failed to scan"
                logger().info(f"scan list is {scan_results}")
                for count1 in scan_results:
                    logger().info("validating channels in scan response")
                    assert count1.rf_channel in channel_list_dual,"unexpected channel found in scan results"

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter3 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_scan_for_channels_36_40_48_149_157_161_165_C19411(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_for_channels_36_40_48_149_157_161_165_C19411"

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


        channel_list = {0: 36, 1: 40, 3: 48, 19: 149, 21: 157, 22: 161, 23: 165}
        sel_channel_list = {36, 40, 48, 149, 157, 161, 165}
        channel_bitmap_5 = 0
        scan_feature_extend = 0

        for count in channel_list:
            channel_bitmap_5 += 1 << (count)

        for channel in sel_channel_list:
            validation =True

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}')

            logger().info("Initiating selective channel scan...")
            time.sleep(1)
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                           scan_bitmap_2_4=0,
                                                                           scan_bitmap_5=channel_bitmap_5,
                                                                           scan_feature=scan_feature_extend)

            logger().info(scan_results)
            assert len(scan_results) >= 1, "failed to scan....  "
            time.sleep(10)
            for count1 in scan_results:
                logger().info("validating channels in scan response")
                assert count1.rf_channel in sel_channel_list, "unexpected channel found in scan results"

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter4 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi ={"channel": 36})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_scan_in_dual_band_for_channels_6_and_36_C19412(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_in_dual_band_for_channels_6_and_36_C19412"

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

        sel_channel_list = [6, 36]

        for channel in sel_channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(10)

            validation = True
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')
            time.sleep(2)

            logger().info("Initiating selective channel scan....")
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=channel, ssid=None)
            time.sleep(10)
            assert len(scan_results) >= 1, "failed to scan....  "
            for count1 in scan_results:
                logger().info("validating channels in scan response")
                assert count1.rf_channel in sel_channel_list, "unexpected channel found in scan results"

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter4 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
                'packet_count'], 'Unable to find probe request packet in sniffer'

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
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_scan_5ghz_band_for_channels_36_40_149_161_165_C19413(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_5ghz_band_for_channels_36_40_149_161_165_C19413"

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

        channel_list = {0: 36, 1: 40, 19: 149, 22: 161, 23: 165}
        sel_channel_list = [36, 40, 149, 161, 165]
        channel_bitmap_5 = 0
        scan_feature_extend = 0

        for count in channel_list:
            channel_bitmap_5 += 1 << (count)

        for channel in sel_channel_list:

            validation = True
            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}')

            for i in range(0, 2):
                logger().info("Initiating selective channel scan...")
                scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                               scan_bitmap_2_4=0,
                                                                               scan_bitmap_5=channel_bitmap_5,
                                                                               scan_feature=scan_feature_extend)
                logger().info(f"scan list: {scan_results}")
                assert len(scan_results) >= 1, "failed to scan..."
                time.sleep(10)
                for count1 in scan_results:
                    logger().info("validating channels in scan response")
                    assert count1.rf_channel in sel_channel_list, "unexpected channel found in scan results"

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter4 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address}' \
                             f' and wlan_radio.channel == {channel}'

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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_scan_selective_channels_in_dual_bands_C19414(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_selective_channels_in_dual_bands_C19414"
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

        channel_list = [1, 3, 6, 11]
        channel_list1 = {0: 36, 3: 48, 19: 149, 22: 161, 23: 165}

        sel_channel_list = [1, 3, 6, 11, 36, 48, 149, 161, 165]

        channel_bitmap_2_4 = 0
        channel_bitmap_5 = 0
        scan_feature_extend = 0

        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)

        for count in channel_list1:
            channel_bitmap_5 += 1 << (count)

        for channel in sel_channel_list:

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            time.sleep(2)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}')

            for i in range(0, 2):
                logger().info("Initiating selective channel scan...")
                time.sleep(5)
                scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                               scan_bitmap_2_4=channel_bitmap_2_4,
                                                                               scan_bitmap_5=channel_bitmap_5,
                                                                               scan_feature=scan_feature_extend)
                logger().info(f"scan list: {scan_results}")
                assert len(scan_results) >= 1, "failed to scan..."
                time.sleep(15)
                for count1 in scan_results:
                    logger().info("validating channels in scan response")
                    assert count1.rf_channel in sel_channel_list, "unexpected channel found in scan results"

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter4 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find probe request packet in sniffer '

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd
        | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_scan_in_DFS_from_52_to_68_AND_100_to_140_C19415(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_in_DFS_from_52_to_68_AND_100_to_140_C19415"

        logger().info("******* limitation from ap side so verifying only from 52 to 68 ********")
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


        channel_list = {4: 52, 5: 56, 6: 60, 7: 64}
        dfs_channel_list = [52, 56, 60, 64]
        channel_bitmap_2_4 = 0
        channel_bitmap_5 = 0
        scan_feature_extend = 0

        for count in channel_list:
            channel_bitmap_5 += 1 << (count)

        for channel in dfs_channel_list:
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

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

            for i in range(0, 2):
                logger().info("Initiating selective channel scan...")
                scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                               scan_bitmap_2_4=0,
                                                                               scan_bitmap_5=channel_bitmap_5,
                                                                               scan_feature=scan_feature_extend)
                logger().info(f"scan list:{scan_results}")
                assert len(scan_results) >= 1, "failed to scan"
                time.sleep(10)
                for count1 in scan_results:
                    logger().info("validating channels in scan response")
                    assert count1.rf_channel in dfs_channel_list, "unexpected channel found in scan results"

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter4 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_scan_for_selective_channels_in_5GHZ_C19416(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_for_selective_channels_in_5GHZ_C19416"
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

        channel_list = {0: 36, 19: 149}
        sel_channel_list = [36, 149]
        channel_bitmap_5 = 0
        scan_feature_extend = 0
        for count in channel_list:
            channel_bitmap_5 += 1 << (count)

        for channel in sel_channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(10)
            validation = True

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            time.sleep(3)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')

            for i in range(0, 2):
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
            packet_filter4 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address}'\
                             f' and wlan_radio.channel == {channel}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
                'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"testcase completed in {t.duration} seconds")

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
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_scan_5Ghz_US_DFS_C61170(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        logger().info("This test case is not supported with 100-140 channels as AP doe's not have support")
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_5Ghz_US_DFS_C61170"

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

        channel_list = [52, 56, 60, 64]
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

            for i in range(0, 2):
                # enables the scan in dut on channel 0
                logger().info("Initiating scan from dut...")
                scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                assert (len(scan_results) >= 1), "Scan failed"
                logger().info(scan_results)
                time.sleep(15)

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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_scan_5Ghz_EU_DFS_C61171(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        logger().info("This test case is not supported with 100-140 channels as AP doe's not have support")
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_5Ghz_EU_DFS_C19401"

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

        channel_list = [52, 56, 60, 64]
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

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')
            time.sleep(2)
            for i in range(0, 2):
                # enables the scan in dut on channel 0
                logger().info("Initiating scan from dut...")
                scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                assert (len(scan_results) >= 1), "Scan failed"
                logger().info(scan_results)
                time.sleep(15)

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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_scan_5Ghz_JP_DFS_C61172(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        logger().info("This test case is not supported with 100-140 channels as AP doe's not have support")
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_scan_5Ghz_JP_DFS_C61172"
        logger().info("AP doesn't have support for JP region,verifying in sniffer")

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

        channel_list = [52, 56, 60, 64]
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

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')
            time.sleep(2)

            for i in range(0, 2):
                # enables the scan in dut on channel 0
                logger().info("Initiating scan from dut...")
                scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                assert (len(scan_results) >= 1), "Scan failed"
                logger().info(scan_results)
                time.sleep(15)
                for count1 in scan_results:
                    logger().info("validating channels in scan response")
                    assert int(count1.rf_channel) < 149, "unexpected channel found in scan results"

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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_regional_scan_dfs_world_mode_in_5GHZ_C61173(wifi_dut, wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        testcase = "test_regional_scan_dfs_world_mode_in_5GHZ_C61173"
        dfs_channel_list = [52, 56, 60, 64]

        logger().info(f"Limitation from AP side ,so verifying only in {dfs_channel_list}")
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

        for channel in dfs_channel_list:
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

            logger().info(" ====== configuring the sniffer with access point channel ====== ")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'{testcase}_probe_req')
            time.sleep(2)

            for i in range(0, 2):
                logger().info("Initiating selective channel scan...")
                scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None)
                logger().info(f"scan list:{scan_results}")
                assert len(scan_results) >= 1, "failed to scan"
                time.sleep(15)

            # Fetches the DUT mac address
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

            # Validating the probe request packets
            packet_filter4 = f'wlan.fc.type_subtype == 0x0004 and wlan.sa == {dut_mac_address} and wlan_radio.channel == {channel}'

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Validate probe request packet")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
                'packet_count'], 'Unable to find probe request packet in sniffer '
    logger().info(f"test completed in {t.duration} seconds")