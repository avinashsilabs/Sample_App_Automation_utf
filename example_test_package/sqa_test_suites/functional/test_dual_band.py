import pytest
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap
from utf_wiseconnect.devices.rs911x import RS9116PowerSaveModes
from utf.utils.iperf.iperf_utils import ping

def logger():
    return get_logger(__name__)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE ,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 2,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    }
)

# This test case verifies All Channels Scan in Dual band by giving  different region codes(US,EU,JP,WORLD) and channel number as Zero
# This test case covers T2243,T2244,T2245,T2246
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_dual_band_scan_with_US_regions_c19011(wifi_access_point, wifi_dut):
    channel = 149
    # set_region_code is used to set region code,those  values are US=1,EU=2,JP=3,WORLD=4
    set_region_code = 2
    # Enables the wifi power save in DUT
    channel_list = [12, 13, 14]
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    logger().info("DUT region is set to US")
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    logger().info(scan_results)
    assert (len(scan_results) >= 1), 'unable to scan the results'
    for count in scan_results:
        assert (count.rf_channel not in channel_list), f"Scan should not happen in channels {channel_list}"



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE ,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 2,
        "region": 1,
        "region_code": 2,
        "module_type": 1,
    }
)



# This test case verifies All Channels Scan in Dual band by giving  different region codes(US,EU,JP,WORLD) and channel number as Zero
# This test case covers T2243,T2244,T2245,T2246
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_dual_band_scan_with_EU_regions_c19012(wifi_access_point, wifi_dut):

    # set_region_code is used to set region code,those  values are US=1,EU=2,JP=3,WORLD=4
    set_region_code = 2
    # Enables the wifi power save in DUT
    channel_list = [14,149, 151, 157, 161, 165]
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    logger().info("DUT region is set to Europe")
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    logger().info(scan_results)
    assert (len(scan_results) >= 1), 'unable to scan the results'
    for count in scan_results:
        assert (count.rf_channel not in channel_list), f"Scan should not happen in channels {channel_list}"



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE ,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 2,
        "region": 1,
        "region_code": 3,
        "module_type": 1,
    }
)



# This test case verifies All Channels Scan in Dual band by giving  different region codes(US,EU,JP,WORLD) and channel number as Zero
# This test case covers T2243,T2244,T2245,T2246
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_dual_band_scan_with_JP_regions_c19013(wifi_access_point, wifi_dut):

    # set_region_code is used to set region code,those  values are US=1,EU=2,JP=3,WORLD=4
    set_region_code = 2
    channel_list = [149, 153, 157, 161, 165]
    # Enables the wifi power save in DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)

    logger().info("DUT region is set to Japan")
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    logger().info(scan_results)
    assert (len(scan_results) >= 1), 'unable to scan the results'
    for count in scan_results:
        assert (count.rf_channel not in channel_list), f"Scan should not happen in channels {channel_list}"




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE ,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 2,
        "region": 1,
        "region_code": 4,
        "module_type": 1,
    }
)



# This test case verifies All Channels Scan in Dual band by giving  different region codes(US,EU,JP,WORLD) and channel number as Zero
# This test case covers T2243,T2244,T2245,T2246
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_dual_band_scan_with_World_regions_c19014(wifi_access_point, wifi_dut):

    # set_region_code is used to set region code,those  values are US=1,EU=2,JP=3,WORLD=4
    channel_list = [14]
    # Enables the wifi power save in DU
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)

    logger().info("DUT region is set to World region")
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    logger().info(scan_results)
    assert (len(scan_results) >= 1), 'unable to scan the results'
    for count in scan_results:
        assert (count.rf_channel not in channel_list), f"Scan should not happen in channels {channel_list}"



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE ,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 2,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    }
)
#In Dual band mode, 2.4GHz and 5GHz Country IE mismatching and check DUT is able to connect to US region AP or not
# This case required 2 AP's Support.
@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point1", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_dual_band_connection_with_country_IE_Mismatch(wifi_access_point, wifi_dut):
    channel = 11
    wifi_access_point.interfaces.wifi.start_ap(channel=channel)
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=4, module_type=1)
        # enables the scan in DUT with the given channel bitmap value
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        logger().info(scan_results)
        assert (len(scan_results) >= 1), 'unable to scan the results'
        # This API connects STA to the third party AP
        result = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        assert result
        # This API Enables the DHCP in DUT
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        # This API Enables the wifi power save mode in DUT
        wifi_dut.interfaces.wifi.power_save(2)

        # This API Enables the bt power save mode in DUT
        wifi_dut.interfaces.wifi.bt_power_save(2)

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1
    logger().info(f"Associated in {t.duration} seconds")


