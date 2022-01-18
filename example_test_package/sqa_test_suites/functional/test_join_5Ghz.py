import pytest
from utils.time_measurer import TimeMeasurer
from utils.iperf.iperf_utils import ping
from utils.logger import get_logger
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, RS9116CustomFeatureBitMap


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
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut

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
            "band": 1
            }
        )

    ]
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',wifi ={"channel": 36})
# This test case verifies the dut connect functionality in 5ghz mode of access point
def test_join_11n_mode(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        # Joins the access point with given ssid and password
        logger().info("Joining the AP")
        status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        assert status, 'Unable to join ap '

        # enables the rejoin feature on dut
        logger().info("enabling Re-joining")
        status = wifi_dut.interfaces.wifi.rejoin()
        assert status

        # assigns and enables the dhcp in dut
        logger().info("Starting dhcp")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        # Enables the wifi power save in dut
        logger().info("enabling wifi power save")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        assert enable_wifi_ps, 'failed to enable'

        # Enables the bt power save in dut
        logger().info("enabling bt powersave")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        assert enable_bt_ps, 'failed to enable'

        # initiates the ping in dut
        logger().info("pinging to dut ip")
        status = ping(device_ip, 10)
        assert status == 1
    logger().info(f"Asociated and ping in {t.duration} seconds")

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "custom_features": RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
            "band": 1
            }
        )
    ]
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2', "channel": 56})
# This test case verifies the dut connect functionality in 5ghz dfs channel mode of access point
def test_join_5ghz_dfs_channel(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        # enables the rejoin feature on dut
        logger().info("enabling Re-joining")
        status = wifi_dut.interfaces.wifi.rejoin()
        assert status

        # Joins the access point with given ssid and password
        logger().info("Joining the AP")
        status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        assert status, 'Unable to join ap '

        # assigns and enables the dhcp in dut
        logger().info("Starting dhcp")
        result = wifi_dut.interfaces.wifi.start_ip()

        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        # Enables the wifi power save in dut
        logger().info("enabling wifi power save")
        enable_wifi_ps= wifi_dut.interfaces.wifi.power_save(8)
        assert enable_wifi_ps, 'failed to enable'

        # Enables the bt power save in dut
        logger().info("enabling bt power save")
        enable_bt_ps= wifi_dut.interfaces.wifi.bt_power_save(8)
        assert enable_bt_ps, 'failed to enable'

        # initiates the ping in dut
        logger().info("pinging to dut ip")
        status = ping(device_ip, 10)
        assert status == 1
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
            "custom_features": RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
            "band": 1
            }
        )
    ]
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
# This test case verifies the dut connect functionality in 5ghz dfs mode of access point for channels 100 and 140
def test_join_5ghz_dfs_channels_100_and_140(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        channel_list = [149,153]
        for channel in channel_list:

            # initiates the access point with channel given in list
            logger().info("Starting AP...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            # Joins the access point with given ssid and password
            logger().info("Joining the AP")
            status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            assert status, 'Unable to join ap '

            # enables the rejoin feature on dut
            logger().info("enabling Re-joining")
            config = wifi_dut.interfaces.wifi.rejoin()
            assert config

            # assigns and enables the dhcp in dut
            logger().info("Starting dhcp")
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(
                result, wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

            # Enables the wifi power save in dut
            logger().info("enabling wifi power save")
            enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
            assert enable_wifi_ps, 'failed to enable'

            # Enables the bt power save in dut
            logger().info("enabling bt power save")
            enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
            assert enable_bt_ps, 'failed to enable'

            # initiates the ping in dut
            logger().info("pinging to dut ip")
            status = ping(device_ip, 10)
        assert status == 1
    logger().info(f"Associated and ping in {t.duration} seconds")