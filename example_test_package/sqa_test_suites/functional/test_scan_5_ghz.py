import pytest
from utils.logger import get_logger
from utils.time_measurer import TimeMeasurer
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
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


pytestmark = [
    pytest.mark.config(
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
    ]
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
# This Test case verifies the scan functionality in 5ghz band for all channels in US region
def test_scan_5Ghz_usregion(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        logger().info(" ***** Configuring DUT in US region *****")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=1, module_type=1)
        channel_list = [36, 52, 100, 165]
        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            logger().info("Initiating scan...")
            scan_results = wifi_dut.interfaces.wifi.scan(ssid=None,channel=0)
            logger().info(scan_results)
            assert len(scan_results) > 0
    logger().info(f"Scan in {t.duration} seconds")


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# This Test case verifies the scan functionality in 5ghz band for all channels in EU region
def test_scan_5Ghz_euregion(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        logger().info(" ***** Configuring DUT in EU region ***** ")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=2, module_type=1)
        channel_list = [36, 52, 100]
        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            logger().info("Initiating Scan...")
            scan_results = wifi_dut.interfaces.wifi.scan(ssid=None,channel=0)
            logger().info(scan_results)
            assert len(scan_results) > 0
    logger().info(f"Scan in {t.duration} seconds")


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# This Test case verifies the scan functionality in 5ghz band for all channels in Japan region
def test_scan_5Ghz_jp_region(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        logger().info(" ***** Configuring DUT in Japan region ***** ")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=3, module_type=1)
        channel_list = [36, 52, 100]
        for channel in channel_list:
            logger().info("Starting access point with custom channels...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            logger().info("Initiating scan...")
            scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
            logger().info(scan_results)
            assert len(scan_results) > 0
    logger().info(f"Scan in {t.duration} seconds")


#test scan_connect in eu for the channels 56 -- case1
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 56})
def test_scan_all_channels_connect_56_5Ghz_DFS_euregion(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        logger().info(" ***** Configuring DUT in EU region ***** ")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=2, module_type=1)
        logger().info("Initiating scan")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        logger().info("Joining ap...")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(scan_results)
    assert scan_results is not None


#test scan_connect in eu for the channels 104,104 channel is not available setting channel 64 -- case2
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 64})
def test_scan_all_channels_connect_64_5Ghz_DFS_euregion(wifi_dut, wifi_access_point):
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        logger().info(" ***** Configuring DUT in EU region ***** ")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=2, module_type=1)
        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None,channel=0)
        logger().info("Joining ap...")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info(scan_results)
        assert scan_results is not None


#test scan_connect in eu for the channels 104, 104 channel is not available setting channel 36 -- case3
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
def test_scan_104_channel_5Ghz_DFS_euregion(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        logger().info(" ***** Configuring DUT in EU region ***** ")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=2, module_type=1)
        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=36, ssid=None)
        logger().info("Joining ap...")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(scan_results)
    assert scan_results is not None
    logger().info(f"Associated in {t.duration} seconds")


#test scan_connect in eu for the channels 36,48,52,100,104,149] -- case4
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
def test_scan_connect_5Ghz_DFS_euregion(wifi_dut, wifi_access_point):
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        logger().info(" ***** Configuring DUT in EU region ***** ")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=2, module_type=1)
        logger().info("Starting access point...")
        wifi_access_point.interfaces.wifi.start_ap()
        channel_list = {36:0, 48:3 , 52:4, 100:8, 104:9, 149:20}
        scan_expected_time = 0
        channel_bitmap_5 = 0
        scan_feature_extend = 0
        for count in channel_list:
            channel_bitmap_5 += 1 << (channel_list[count])
            scan_expected_time += 100
        with TimeMeasurer() as t:
            logger().info("Initiating selective channel scan...")
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                       scan_bitmap_5=channel_bitmap_5,
                                                                       scan_feature=scan_feature_extend)
            logger().info(scan_results)
            assert len(scan_results) >= 1
            channel_selected = 0

            for count in scan_results:

                for device_channel in channel_list:
                    if count.rf_channel == device_channel:
                        channel_selected = channel_selected + 1
            logger().info("Joining ap...")
            result= wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            assert result
        logger().info(f"Associated in {t.duration} seconds")


#test scan_connect in jp for the channels 56 -- case1
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 56})
def test_scan_all_channels_connect_56_5Ghz_DFS_jpregion(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        logger().info(" ***** Configuring DUT in JP region ***** ")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=3, module_type=1)
        logger().info("Initiating scan....")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        logger().info("Joining ap....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(scan_results)
    assert scan_results is not None


#test scan_connect in jp for the channels 104, 104 channel is not available setting channel 64 -- case2
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 64})
def test_scan_all_channels_connect_104_5Ghz_DFS_jpregion(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        logger().info(" ***** Configuring DUT in JP region ***** ")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=3, module_type=1)
        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        logger().info("Joinig ap...")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(scan_results)


#test scan_connect in jp for the channels 104, using channel 64 as channel 104 is not available -- case3
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 64})
def test_scan_104_channel_5Ghz_DFS_jpregion(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info(" ***** Configuring DUT in JP region ***** ")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=3, module_type=1)
        logger().info("Initiating selective chnnel scan...")
        scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=64, ssid=None)
        logger().info("Joining ap...")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info(scan_results)
    logger().info(f"Associated in {t.duration} seconds")


#test scan_connect in jp for the channels 36,48,52,100,104,149] -- case4
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
def test_scan_connect_channels_36_48_52_100_149_jpregion(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        channel_list = {1:36, 2:48, 3:52, 4:100, 5:104, 6:149}
        channel_bitmap_5 = 0
        scan_feature_extend = 0
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        logger().info(" ***** Configuring DUT in JP region ***** ")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=3, module_type=1)

        for count in channel_list:
            channel_bitmap_5 += 1 << (count - 1)
            logger().info("Initiating selective channel scan...")
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,scan_bitmap_5=channel_bitmap_5, scan_feature=scan_feature_extend)
            logger().info(scan_results)
            assert len(scan_results) >= 1
            logger().info("Joining ap...")
        result= wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        assert result
    logger().info(f"Associated in {t.duration} seconds")


#test ID: 2.1.5.2, This test case verifies the scan functionality in all channels of 5ghz
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_all_channels_in_5Ghz(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        assert scan_results is not None
    logger().info(f"Associated in {t.duration} seconds")


#test ID: 2.1.5.4, Verifies the scan response
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_all_channels_scan_by_giving_channel_as_zero(wifi_dut):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        assert scan_results is not None
        logger().info(scan_results)
    logger().info(f"Scan in {t.duration} seconds")


# This Test case verifies the all channels scan in 5ghz by givig all channle in bitmap
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_all_channels_by_giving_channels_in_bitmap(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        channel = 0
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        logger().info(" ***** Configuring DUT in US region ***** ")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=1, module_type=1)
        channel_list = {1:36, 2:40, 3:44, 4:48, 5:52,6:56, 7:60, 8:64, 9:149, 10:153, 11:157, 12:161, 13:165}
        channel_bitmap_5 = 0
        scan_feature_extend = 0

        for count in channel_list:
            channel_bitmap_5 += 1 << (count - 1)

        for channel in channel_list:
                logger().info("Starting access point with custom channel...")
                wifi_access_point.interfaces.wifi.start_ap(channel=channel)
                logger().info("Initiating selective channel scan...")
                scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None, scan_bitmap_5=channel_bitmap_5, scan_feature=scan_feature_extend)
                logger().info(scan_results)
                assert len(scan_results) >= 1
                channel_selected = 0
        for count1 in scan_results:
            for device_channel in channel_list:
                if count1.rf_channel == channel_list[device_channel]:
                    channel_selected = channel_selected + 1
    logger().info(f"Associated in {t.duration} seconds")


pytestmark = [
    pytest.mark.config(
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
    ]
# This Test case verifies the scan functionality in 2_4ghz and 5ghz bands for all channels
def test_scan_all_channels_in_dual_band(wifi_dut):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Initiating selective channel scan...")
        scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(ssid=None)
        assert scan_results is not None
        logger().info(scan_results)
    logger().info(f"Scan in {t.duration} seconds")


pytestmark = [
    pytest.mark.config(
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
    ]
# This Test case verifies the scan functionality in 2_4ghz and 5ghz bands for all channels
def test_all_channels_scan_by_setting_all_channels_in_bitmap(wifi_dut,wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        channel_list = [1,2,3,4,5,6,7,8,9,10,11]
        channel_list1 = {1: 36, 2: 40, 3: 44, 4: 48, 5: 52, 6: 56, 7: 60, 8: 64, 9: 149, 10: 153, 11: 157, 12: 161, 13: 165}
        scan_expected_time = 0
        channel_bitmap_2_4 = 0
        channel_bitmap_5 = 0
        scan_feature_extend = 0
        logger().info(" ***** Configuring DUT in JP region ***** ")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=3, module_type=1)

        for count in channel_list1:
            channel_bitmap_5 += 1 << (count - 1)
            scan_expected_time += 100

        for count in channel_list:
                channel_bitmap_2_4 += 1 << (count - 1)
                scan_expected_time += 100

        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            logger().info("Initiating selective channel scan...")
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4, scan_bitmap_5=channel_bitmap_5, scan_feature=scan_feature_extend)
            logger().info(scan_results)

        for channel in channel_list1:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            logger().info("Initiating selective channel scan...")
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4, scan_bitmap_5=channel_bitmap_5, scan_feature=scan_feature_extend)
            logger().info(scan_results)

        assert len(scan_results) >= 1
    logger().info(f"Associated in {t.duration} seconds")


pytestmark = [
    pytest.mark.config(
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
    ]
# This Test case verifies the scan functionality in 5ghz band for channels 36,40,48,52,100,149,157,161,165
def test_scan_for_channels_36_40_48_52_100_149_157_161_165(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        logger().info(" ***** Configuring DUT in US region ***** ")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=1, module_type=1)
        channel_list = {1: 36, 2: 40,3: 48,4: 52,5: 100,6: 149,7: 157,8: 161,9: 165}
        channel_bitmap_5 = 0
        scan_feature_extend = 0

        for count in channel_list:
            channel_bitmap_5 += 1 << (count - 1)

        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel= channel)
            logger().info("Initiating selective channel scan...")
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None, scan_bitmap_5=channel_bitmap_5, scan_feature=scan_feature_extend)
        logger().info(scan_results)
        assert len(scan_results) >= 1
    logger().info(f"Associated in {t.duration} seconds")


pytestmark = [
    pytest.mark.config(
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
    ]
# This Test case verifies the scan functionality in dual band for channels 6,36
def test_scan_in_dual_band_for_AP_channels_6_and_36_by_setting_channel_as_1_in_dut(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        channel_list = [6]
        channel_list1 = [36]
        channel_bitmap_2_4 = 0
        channel_bitmap_5 = 0
        scan_feature_extend = 0
        logger().info(" ***** Configuring DUT in JP region *****")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=3, module_type=1)
        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel= channel)
            logger().info("Initiating selective channel scan....")
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=1, ssid=None,scan_bitmap_2_4=channel_bitmap_2_4,scan_bitmap_5=channel_bitmap_5,scan_feature=scan_feature_extend)
            logger().info(scan_results)
            assert len(scan_results) >= 1

        for channel in channel_list1:
                logger().info("Starting access point with custom channel...")
                wifi_access_point.interfaces.wifi.start_ap(channel=channel)
                logger().info("Initiating selective channel scan...")
                scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4, scan_bitmap_5=channel_bitmap_5, scan_feature=scan_feature_extend)
                logger().info(scan_results)
    logger().info(f"Associated in {t.duration} seconds")


pytestmark = [
    pytest.mark.config(
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
    ]
# This Test case verifies the scan functionality in 5ghz selective channels of 36,40,52,56,149,161,165
def test_scan_5ghz_band_for_channels_36_40_52_56_149_161_165(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        logger().info(" **** Configuring DUT in JP region ***** ")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=3, module_type=1)
        channel_list = {1: 36,2: 40,3: 52,4: 56,5: 149,6: 161,7: 165}
        channel_bitmap_5 = 0
        scan_feature_extend = 0

        for count in channel_list:
            channel_bitmap_5 += 1 << (count - 1)

        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel= channel)
            logger().info("Initiating selective channel scan...")
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,scan_bitmap_5=channel_bitmap_5,scan_feature=scan_feature_extend)
            logger().info(scan_results)
            assert len(scan_results) >= 1
    logger().info(f"Associated in {t.duration} seconds")


pytestmark = [
    pytest.mark.config(
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
    ]
# This Test case verifies the scan functionality in dual bands selective channels
def test_scan_selective_channels_in_dual_bands(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        logger().info(" ***** Configuring DUT in JP region ***** ")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=3, module_type=1)
        channel_list = [1,3,6,11]
        channel_list1 = {1: 36,2: 48,3: 149,4: 161,5: 165}
        channel_bitmap_2_4 = 0
        channel_bitmap_5 = 0
        scan_feature_extend = 0

        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)

        for count in channel_list1:
            channel_bitmap_5 += 1 << (count - 1)

        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel= channel)
            logger().info("Initiating selective channel scan...")
            wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4, scan_bitmap_5=channel_bitmap_5, scan_feature=scan_feature_extend)

        for channel in channel_list1:
                logger().info("Starting access point with custom channel...")
                wifi_access_point.interfaces.wifi.start_ap(channel=channel)
                logger().info("Initiating selective channel scan...")
                scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4, scan_bitmap_5=channel_bitmap_5, scan_feature=scan_feature_extend)
                logger().info(scan_results)
                assert scan_results is not None
    logger().info(f"Associated in {t.duration} seconds")


pytestmark = [
    pytest.mark.config(
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
    ]
# This Test case verifies the scan functionality in 5ghz selective channels of 36,52,100,149
def test_scan_for_selective_channels_in_5GHZ(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        logger().info(" ***** Configuring DUT in EU region ***** ")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=2, module_type=1)
        channel_list = {1: 36, 2: 52, 3: 100, 4: 149}
        channel_bitmap_5 = 0
        scan_feature_extend = 0
        for count in channel_list:
            channel_bitmap_5 += 1 << (count - 1)

        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel= channel)
            logger().info("Initiating selective channel scan...")
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None, scan_bitmap_5=channel_bitmap_5, scan_feature=scan_feature_extend)
            logger().info(scan_results)
            assert len(scan_results) >= 1
    logger().info(f"Associated in {t.duration} seconds")