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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 2,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    }
)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])

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
        logger().info(f"rf_channel : {count.rf_channel}")
        assert (count.rf_channel not in channel_list), f"Scan should not happen in channels {channel_list}"
    logger().info(f" channels which are not supported in US region are :{channel_list}")
    logger().info(
        f"DUT is scanned only supported channels in US region and channels which are in channel list are not there in scan results hence test case passed ")

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

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])

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
        logger().info(f"rf_channel : {count.rf_channel}")
        assert (count.rf_channel not in channel_list), f"Scan should not happen in channels {channel_list}"
    logger().info(f" channels which are not supported in EU region are :{channel_list}")
    logger().info(
        f"DUT is scanned only supported channels in EU region and channels which are in channel list are not there in scan results hence test case passed ")

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

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])

def test_dual_band_scan_with_JP_regions_c19013(wifi_access_point, wifi_dut):
    channel_list = [149, 153, 157, 161, 165]
    # Enables the wifi power save in DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)

    logger().info("DUT region is set to Japan")
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    assert (len(scan_results) >= 1), 'unable to scan the results'
    for count in scan_results:
        logger().info(f"rf_channel : {count.rf_channel}")
        assert (count.rf_channel not in channel_list), f"Scan should not happen in channels {channel_list}"
    logger().info(f" channels which are not supported in JP region are :{channel_list}")
    logger().info(
        f"DUT is scanned only supported channels in JP region and channels which are in channel list are not there in scan results hence test case passed ")


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

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])

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
        logger().info(f"rf_channel : {count.rf_channel}")
        assert (count.rf_channel not in channel_list), f"Scan should not happen in channels {channel_list}"
    logger().info(f" channels which are not supported in World region are :{channel_list}")
    logger().info(
        f"DUT is scanned only supported channels in World region and channels which are in channel list are not there in scan results hence test case passed ")


ping_count=10
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
def test_dual_band_connection_with_country_IE_Mismatch_C19010(wifi_access_points, wifi_dut):

        ssid= 'Codecom123'
        security= 'WPA2'
        passphrase= '123123123'
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        logger().info(scan_results)
        assert (len(scan_results) >= 1), 'unable to scan the results'
        result = wifi_dut.interfaces.wifi.join(channel=0, ssid=ssid,
                                      security=security,
                                      passphrase=passphrase)
        assert result
        # This API Enables the DHCP in DUT
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f" ********* enabling enhance max psp in our DUT*******")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        # Initiate ping from third party wifi-client to DUT
        ping(device_ip, ping_count)
        logger().info("getting wireless info to validate whether the DUT is connected to 2.4ghz AP or 5ghz AP")
        result = wifi_dut.interfaces.wifi.get_wireless_info()
        assert f"rf_channel: {wifi_access_points[0].interfaces.wifi.channel}" in result, 'DUT is not connected to 2.4ghz AP ssid '
        logger().info(f" DUT is Connected to 2.4gz AP and channel and which is expected ")

