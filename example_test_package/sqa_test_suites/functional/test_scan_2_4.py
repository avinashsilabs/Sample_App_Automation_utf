import pytest
from utils.logger import get_logger
from utils.time_measurer import TimeMeasurer
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap
from interfaces.wifi import WlanError
from devices.rs911x import RS9116PowerSaveModes

def logger():
    return get_logger(__name__)

"""setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Enable the wlan and bt power save mode in dut after the connection
        3. Initiate the Scan from DUT
        4. Verify the scan results

    Author: Ravi Nemali
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
            }
        )
    ]
# This test case verifies All Channels Scan in 2.4 Ghz by giving channel number as Zero
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan(wifi_dut, wifi_access_point):
    # Enables the wifi power save in DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    with TimeMeasurer() as t:

        # enables the scan in dut on channel 0
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    assert (len(scan_results) > 1 and (t.duration < (1.2 + 0.2)))
    logger().info(scan_results)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# This test case verifies the scan Response Based on RSSI
def test_scan_check_rssi(wifi_dut, wifi_access_point):
    # Enables the wifi power save in DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    with TimeMeasurer() as t:
        # enables the scan in dut on channel 0
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    logger().info(scan_results)
    scan_count = len(scan_results)

    assert scan_count > 0
    previous_rssi = 0
    for count in scan_results:
        assert previous_rssi >= count.rssi
        previous_rssi = count.rssi
    logger().info(f"Scan in {t.duration} seconds")

# This test case verifies the scan with 32 byte SSID name
def test_scan_ssid_32bytes(wifi_dut, wifi_access_point):
    # Enables the wifi power save in DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    scan_ssid = "test123test123test123test123"
    start_ap_args = {'ssid': scan_ssid}

    # api starts the access point with the given argument ssid
    wifi_access_point.interfaces.wifi.start_ap(**start_ap_args)
    with TimeMeasurer() as t:

        # enables the scan in DUT with the given channel bitmap value
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=scan_ssid)
    logger().info(scan_results)
    assert len(scan_results) == 1
    logger().info(f"Scan in {t.duration} seconds")

# This test case verifies the scan functionality on channles 1,6,8
def test_scan_selective_channel_1_6_8(wifi_dut, wifi_access_point):
    # Enables the wifi power save in DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    channel_list = [1, 6, 8]
    channel_bitmap_2_4 = 0
    scan_expected_time = 0
    for count in channel_list:
        channel_bitmap_2_4 += 1 << (count - 1)
        scan_expected_time += 100

    channel_bitmap_5 = 0
    scan_feature_extend = 0
    for channel in channel_list:

        # initiates the access point with channel given in list
        wifi_access_point.interfaces.wifi.start_ap(channel=channel)

        with TimeMeasurer() as t:

            # enables the scan in DUT with the given channel bitmap value
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                           scan_bitmap_2_4=channel_bitmap_2_4,
                                                                           scan_bitmap_5=channel_bitmap_5,
                                                                           scan_feature=scan_feature_extend)
            logger().info(scan_results)
            assert len(scan_results) >= 1
            channel_selected = 0
            for count in scan_results:
                for device_channel in channel_list:
                    if count.rf_channel == device_channel:
                        channel_selected = channel_selected + 1

        assert (channel_selected == len(scan_results))
        logger().info(f"Scan in {t.duration} seconds")

# Verifies the scan functionality with the channel 1,3,6,11
def test_scan_selective_channel_1_3_6_11(wifi_dut, wifi_access_point):
    # Enables the wifi power save in DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    channel_list = [1, 3, 6, 11]
    channel_bitmap_2_4 = 0
    scan_expected_time = 0
    for count in channel_list:
        channel_bitmap_2_4 += 1 << (count - 1)
        scan_expected_time += 100

    channel_bitmap_5 = 0
    scan_feature_extend = 0
    for channel in channel_list:

        # initiates the access point with channel given in list
        wifi_access_point.interfaces.wifi.start_ap(channel=channel)

        with TimeMeasurer() as t:

            # enables the scan in DUT with the given channel bitmap value
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                           scan_bitmap_2_4=channel_bitmap_2_4,
                                                                           scan_bitmap_5=channel_bitmap_5,
                                                                           scan_feature=scan_feature_extend)

            logger().info(scan_results)
            assert len(scan_results) >= 1
            channel_selected = 0
            for count in scan_results:
                for device_channel in channel_list:
                    if count.rf_channel == device_channel:
                        channel_selected = channel_selected + 1

        assert (channel_selected == len(scan_results))
        logger().info(f"Scan in {t.duration} seconds")

# This test case verifies the scan functionality for channles 1-11
def test_scan_selective_channel_1_to_11(wifi_dut, wifi_access_point):
        # Enables the wifi power save in DUT
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

        # Enables the bt power save in DUT
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
        channel_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100

            channel_bitmap_5 = 0
            scan_feature_extend = 0

        for channel in channel_list:

            # initiates the access point with channel given in list
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)

            # enables the scan in DUT with the given channel bitmap value
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                           scan_bitmap_2_4=channel_bitmap_2_4,
                                                                           scan_bitmap_5=channel_bitmap_5,
                                                                           scan_feature=scan_feature_extend)
            logger().info(scan_results)
            assert len(scan_results) >= 1
            channel_selected = 0
            for count in scan_results:
                for device_channel in channel_list:
                    if count.rf_channel == device_channel:
                        channel_selected = channel_selected + 1
        assert (channel_selected <= len(scan_results))

# Verifies the scan functionality in us region
def test_scan_us_region_2_4(wifi_dut, wifi_access_point):
    # Enables the wifi power save in DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    channel = 11
    wifi_access_point.interfaces.wifi.start_ap(channel=channel)

    with TimeMeasurer() as t:

        # Sets the DUT with the us region
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=1, module_type=1)

        # enables the scan in DUT with the given channel bitmap value
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    logger().info(scan_results)
    assert (len(scan_results) >= 1)

#test ID: 2.1.5.3
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# This test case verifies the scan functionality with the selective channel as 0
def test_scan_selective_channel_0(wifi_dut, wifi_access_point):
    # Enables the wifi power save in DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # enables the rejoin in dut
    wifi_dut.interfaces.wifi.rejoin()
    channel = 0
    channel_bitmap_2_4 = 0
    scan_feature_extend = 0

    # initiates the access point with given arguments
    wifi_access_point.interfaces.wifi.start_ap()
    with TimeMeasurer() as t:
        # enables the scan in DUT with the given channel bitmap value
        scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=channel,ssid=None,scan_bitmap_2_4=channel_bitmap_2_4,scan_feature=scan_feature_extend)
        logger().info(scan_results)
        assert len(scan_results) >= 1
    logger().info(f"Scan in {t.duration} seconds")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# This test case verifies the scan functionality by giving the channel bitmap field
def test_scan_channel_bitmap_field(wifi_dut,wifi_access_point):
        # Enables the wifi power save in DUT
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

        # Enables the bt power save in DUT
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        # Enables the rejoin feature in dut
        wifi_dut.interfaces.wifi.rejoin()
        channel = 0
        channel_list = [1,2,3,4,5,6,7,8,9,10,11]
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        scan_feature_extend = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100
        with TimeMeasurer() as t:

            # enables the scan in DUT with the given channel bitmap value
            scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=channel, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4, scan_feature=scan_feature_extend)
            logger().info(scan_results)
            assert len(scan_results) >= 1
            channel_selected = 0
            for count in scan_results:
                for device_channel in channel_list:
                    if count.rf_channel == device_channel:
                        channel_selected = channel_selected + 1
                        assert (channel_selected <= len(scan_results))
        logger().info(f"Scan in {t.duration} seconds")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',wifi ={"broadcast_ssid": False})
# This case verifies the scan in hidden mode of AP for all channels
def test_scan_hidden_mode_scan_with_all_channels(wifi_dut,wifi_access_point):
    # Enables the wifi power save in DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the rejoin feature on DUT
    wifi_dut.interfaces.wifi.rejoin()
    channel = 0
    channel_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    channel_bitmap_2_4 = 0
    scan_expected_time = 0
    for count in channel_list:
        channel_bitmap_2_4 += 1 << (count - 1)
        scan_expected_time += 100
        scan_feature_extend = 0
        with TimeMeasurer() as t:

                # enables the scan in DUT with the given channel bitmap value
                scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=channel,ssid=None,
                                                                       scan_bitmap_2_4=channel_bitmap_2_4,
                                                                       scan_feature=scan_feature_extend)
                logger().info(scan_results)
                assert len(scan_results) >= 1
                channel_selected = 0
                for count1 in scan_results:
                    for device_channel in channel_list:
                        if count1.rf_channel == device_channel:
                            channel_selected = channel_selected + 1
                            assert (channel_selected <= len(scan_results))
        logger().info(f"Scan in {t.duration} seconds")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',wifi ={"broadcast_ssid": False})
# Verifies the scan in selected channels with the ap set in hidden mode
def test_scan_hidden_mode_scan_with_selected_channels(wifi_dut,wifi_access_point):
    # Enables the wifi power save in DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the rejoin feature on DUT
    wifi_dut.interfaces.wifi.rejoin()
    channel = 0
    channel_list = [1,5,9]
    channel_bitmap_2_4 = 0
    scan_expected_time = 0
    for count in channel_list:
        channel_bitmap_2_4 += 1 << (count - 1)
        scan_expected_time += 100
    scan_feature_extend = 0

    with TimeMeasurer() as t:

        # enables the scan in DUT with the given channel bitmap value
        scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=channel, ssid=None,scan_bitmap_2_4=channel_bitmap_2_4,scan_feature=scan_feature_extend)
        logger().info(scan_results)
        assert len(scan_results) >= 1
        channel_selected = 0
        for count1 in scan_results:
            for device_channel in channel_list:
                if count1.rf_channel == device_channel:
                    channel_selected = channel_selected + 1

            assert (channel_selected <= len(scan_results))
    logger().info(f"Scan in {t.duration} seconds")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# This test case verifies the scan in us region with cahnnels 12,13,14
def test_scan_in_US_region_for_channel_12_13_14(wifi_dut,wifi_access_point):
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=1, module_type=1)
    # Enables the wifi power save in DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the rejoin feature on DUT
    wifi_dut.interfaces.wifi.rejoin()
    channel = [12,13,14]
    channel_list =[12,13,14]
    channel_bitmap_2_4 = 0
    scan_expected_time = 0
    scan_feature_extend = 0
    for count in channel_list:
        channel_bitmap_2_4 += 1 << (count - 1)
        scan_expected_time += 100
    for channel in channel:
        # initiates the access point with channel given in list
        wifi_access_point.interfaces.wifi.start_ap(channel=channel)
        with TimeMeasurer() as t:
            with pytest.raises(WlanError) as exc_info:
                # enables the scan in DUT with the given channel bitmap value
                wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                           scan_bitmap_2_4=channel_bitmap_2_4,
                                                                           scan_feature=scan_feature_extend)
            assert exc_info.value.error_code == 0x03,"Observing wrong error expected error code is 0x03"
        logger().info(f"Scan in {t.duration} seconds")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# Verifies scan on all channels in by setting EU region on DUT
def test_scan_all_channels_in_EU_region(wifi_dut,wifi_access_point):
    # enables the region to europe in DUT
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=2, module_type=1)
    # Enables the wifi power save in DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # initiates the rejoin in dut
    wifi_dut.interfaces.wifi.rejoin()
    channel = 13

    # Enables and assign the dhcp in DUT
    wifi_access_point.interfaces.wifi.start_ap(channel=channel)

    with TimeMeasurer() as t:
        # enables the scan in DUT with the given channel bitmap value
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    logger().info(scan_results)
    assert (len(scan_results) >= 1)
    logger().info(f"Scan in {t.duration} seconds")


