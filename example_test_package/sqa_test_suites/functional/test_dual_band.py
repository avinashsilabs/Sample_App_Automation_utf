import pytest
from utils.logger import get_logger
from utils.time_measurer import TimeMeasurer
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap
from devices.rs911x import RS9116PowerSaveModes
from utils.iperf.iperf_utils import ping

def logger():
    return get_logger(__name__)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE ,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "band": 2,
        }
    )
]


# This test case verifies All Channels Scan in Dual band by giving  different region codes(US,EU,JP,WORLD) and channel number as Zero
# This test case covers T2243,T2244,T2245,T2246
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_dual_band_scan_with_different_regions(wifi_dut, wifi_access_point):
    # Enables the wifi power save in DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    channel = 149
    wifi_access_point.interfaces.wifi.start_ap(channel=channel)
    # set_region_code is used to set region code,those  values are US=1,EU=2,JP=3,WORLD=4
    set_region_code = 1
    with TimeMeasurer() as t:
            # This loop enables DUT in different regions.
            while set_region_code < 5:
                logger().info(set_region_code)
                #enables DUT in configured Region
                wifi_dut.interfaces.wifi.set_region(region=1, region_code=set_region_code, module_type=1)
                # enables the scan in DUT with the given channel bitmap value
                scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                logger().info(scan_results)
                assert (len(scan_results) >= 1)
                set_region_code = set_region_code+1
                wifi_dut.interfaces.wifi.reset_soft()
                wifi_dut.interfaces.wifi.init()

#In Dual band mode, 2.4GHz and 5GHz Country IE mismatching and check DUT is able to connect to US region AP or not
# This case required 2 AP's Support.
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point1", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_dual_band_connection_with_country_IE_Mismatch(wifi_dut, wifi_access_point):
    channel = 11
    wifi_access_point.interfaces.wifi.start_ap(channel=channel)
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=4, module_type=1)
        # enables the scan in DUT with the given channel bitmap value
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        logger().info(scan_results)
        assert (len(scan_results) >= 1)
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


