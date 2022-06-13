import pytest
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116PowerSaveProcedureTypes
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 2,
        "region": 1,
        "region_code": 4,
        "module_type": 1,
    }
)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
             'ssid': 'Codecom123',
             'security': 'WPA2',
             'passphrase': '123123123',
             'channel': 1
        },
        1: {
             'ssid': 'Codecom123',
             'security': 'WPA2',
             'passphrase': '123123123',
             'channel': 36
        }
    }
)

@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_dual_band_connection_with_country_IE_Mismatch(wifi_access_points, wifi_dut):

        ssid= 'Codecom123'
        security= 'WPA2'
        passphrase= '123123123'
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        logger().info(scan_results)
        assert (len(scan_results) >= 1), 'unable to scan the results'
        # This API connects STA to the third party AP
        result=wifi_dut.interfaces.wifi.join(channel=0, ssid=ssid,
                                      security=security,
                                      passphrase=passphrase)
        assert result
        # This API Enables the DHCP in DUT
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        # This API Enables the power save mode in DUT
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        # logger().info("getting wireless info")
        result = wifi_dut.interfaces.wifi.get_wireless_info()
        logger().info("getting wireless info to validate whether the DUT is connected to 2.4ghz AP or 5ghz AP")
        assert f"rf_channel: {wifi_access_points[0].interfaces.wifi.channel}" in result, 'DUT is not connected to 2.4ghz AP ssid '





