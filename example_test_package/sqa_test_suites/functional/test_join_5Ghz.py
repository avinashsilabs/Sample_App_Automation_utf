import pytest
from utils.time_measurer import TimeMeasurer
from utils.iperf.iperf_utils import ping
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, RS9116CustomFeatureBitMap

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
@pytest.mark.config('wifi_access_point',wifi ={"standard": '11n', "channel": '36'})
# This test case verifies the dut connect functionality in 5ghz mode of access point
def test_join_11n_mode(wifi_dut, wifi_access_point, logger):
    with TimeMeasurer() as t:
        # Joins the access point with given ssid and password
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # enables the rejoin feature on dut
        wifi_dut.interfaces.wifi.rejoin()

        # assigns and enables the dhcp in dut
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        # Enables the wifi power save in dut
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

        # Enables the bt power save in dut
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        # initiates the ping in dut
        status = ping(device_ip, 10)
        assert status == 1
    logger().info(f"Associated and ping in {t.duration} seconds")


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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2', "channel": 54})
# This test case verifies the dut connect functionality in 5ghz dfs channel mode of access point
def test_join_5ghz_dfs_channel(wifi_dut, wifi_access_point, logger):
    with TimeMeasurer() as t:
        # enables the rejoin feature on dut
        wifi_dut.interfaces.wifi.rejoin()

        # Joins the access point with given ssid and password
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # assigns and enables the dhcp in dut
        result = wifi_dut.interfaces.wifi.start_ip()

        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        # Enables the wifi power save in dut
        wifi_dut.interfaces.wifi.power_save(8)

        # Enables the bt power save in dut
        wifi_dut.interfaces.wifi.bt_power_save(8)
        # initiates the ping in dut
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
            "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
            "band": 1
            }
        )
    ]
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
# This test case verifies the dut connect functionality in 5ghz dfs mode of access point for channels 100 and 140
def test_join_5ghz_dfs_channels_100_and_140(wifi_dut, wifi_access_point, logger):
    with TimeMeasurer() as t:
        channel_list = [100,140]
        for channel in channel_list:

            # initiates the access point with channel given in list
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            # Joins the access point with given ssid and password
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

            # enables the rejoin feature on dut
            wifi_dut.interfaces.wifi.rejoin()

            # assigns and enables the dhcp in dut
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(
                result, wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

            # Enables the wifi power save in dut
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

            # Enables the bt power save in dut
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

            # initiates the ping in dut
            status = ping(device_ip, 10)
        assert status == 1
    logger().info(f"Associated and ping in {t.duration} seconds")


