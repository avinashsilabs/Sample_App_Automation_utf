import pytest
from utils.time_measurer import TimeMeasurer
from utils.logger import get_logger
from utils.iperf.iperf_utils import ping
from interfaces.wifi import WlanError
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap

def logger():
    return get_logger(__name__)

"""setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
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

#test ID: 2.1.6.25

@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n'})
# The test case checks whether the DUT connection works fine in Access point 11n mode
def test_wifi_join_11n_security(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        # This API connects STA to the third party AP
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

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
    logger().info(f"Associated and ping in {t.duration} seconds")

# test.ID: 2.1.16.2

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"passphrase": 'test123@random'})
# The test case checks whether the DUT connection works fine on giving the random passphrase
def test_wifi_join_by_rsi_psk(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
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

# test.ID: 2.1.16.5

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "testingpmk", "passphrase": 'Testing_pmk', "security": 'WPA2'})
# The test case checks whether the DUT connects to Access point with the generated pmk with user given ssid and password
def test_wifi_join_pmk(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        # This API connects STA to the third party AP with the pmk generated
        wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid,wifi_access_point.interfaces.wifi.passphrase)

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

# test.ID: 2.1.16.7

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "pmkwithwrongpsk", "passphrase": 'thisisatestnetwork', "security": 'WPA2'})
# The test case checks whether the DUT connection fails with the wrong psk
def test_wifi_join_pmk_by_giving_wrong_psk(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        with pytest.raises(WlanError) as exc_info:
            # This API connects STA to the third party AP with the pmk generated
            wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid, "12345678")
        assert exc_info.value.error_code == 0x0008
    logger().info(f"Dut Tried to connect to ap with wrong password, observed error code 0x0008 which is expected")
    logger().info(f"test executed in {t.duration} seconds")

# test.ID: 2.1.16.15

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "testwithnossid", "passphrase": 'Testing_pmk', "security": "WPA2"})
# The test case checks whether the DUT connection fails with empty ssid in pmk
def test_wifi_join_pmk_without_SSID(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        with pytest.raises(WlanError) as exc_info:
            # This API connects STA to the third party AP with the pmk generated
            wifi_dut.interfaces.wifi.join_pmk("\"\"", wifi_access_point.interfaces.wifi.passphrase)
            assert exc_info.value.error_code == 0x0003
    logger().info(f"Associated in {t.duration} seconds")

# test.ID: 2.1.16.20

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "redpine", "passphrase": 'Testing_pmk', "security": "WPA2"})
# The test case checks whether the DUT connection fails with space before the redpine ssid in pmk
def test_wifi_join_pmk_with_space_before_redpine_ssid(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        ssid = " redpine"
        with pytest.raises(WlanError) as exc_info:
            # This API connects STA to the third party AP with the pmk generated
            wifi_dut.interfaces.wifi.join_pmk(ssid, "thisisatestnetwork")
        assert exc_info.value.error_code == 0x0008
    logger().info(f"Associated in {t.duration} seconds")

# test.ID: 2.1.16.21

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi=
{"ssid": "Testssid", "passphrase": "1234567890qwertyuioplkjhgfdsazxcvbnmkloirgrgrtyuio1234567890o", "security": "WPA2"}
                    )
# The test case checks whether the DUT connection works with 64 characters of passphrase in pmk
def test_psk_with_64_different_characters(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        # This API connects STA to the third party AP with the pmk generated for the 64 characters of passphrase
        wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid,wifi_access_point.interfaces.wifi.passphrase)

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

# test.ID: 2.1.16.22

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteeetwobytesofsize",
                                               "passphrase": "123456789qwertyuio123456789qwertyuio123456789zxcvbnm123456789zx",
                                               "security": "WPA2"})
# The test case checks whether the DUT connection works with 64 bytes of passphrase and 32 bytes of ssid in pmk
def test_join_pmk_with_64_characters_psk_32_characters_ssid(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        # This API connects STA to the third party AP with the pmk generated for the 64 characters of passphrase and 32 bytes of ssid
        wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid,
                                          wifi_access_point.interfaces.wifi.passphrase)

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

# test.ID: 2.1.6.31

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"broadcast_ssid": False})
# The test case checks whether the DUT connection works with AP hidden mode
def test_connectivity_with_hidden_ap(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        # This API connects STA to the third party AP in hidden mode feature
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

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

# test.ID: 2.1.6..91.1

@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
# The test case checks whether the DUT connection Time on the joining the AP with pmk
def test_pmk_connect_time(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        # This API connects STA to the third party AP with the pmk generated
        wifi_dut.interfaces.wifi.join_pmk(wifi_access_point.interfaces.wifi.ssid,
                                          wifi_access_point.interfaces.wifi.passphrase)
    logger().info(f"join time for pmk connect {t.duration} seconds")

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
    wifi_dut.interfaces.wifi.leave()

# test.ID: 2.1.6..91.1(a)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
# The test case checks whether the DUT connection Time on the joining the AP
def test_psk_connect_time(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        # This API connects STA to the third party AP
        result = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        assert result is not None
    logger().info(f"join time for psk connect {t.duration} seconds")

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
    wifi_dut.interfaces.wifi.leave()

# test.ID: 2.1.6.45

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'testing', "channel": 7})
# The test case checks whether the DUT connection and disconnection  to AP for 30 iterations
def test_wifi_join_and_repeat_in_loop_for_30_times(wifi_dut, wifi_access_point):
    for iteration in range(0, 30):
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
        assert status == 1, "ping failed at %d iteration" % iteration
        wifi_dut.interfaces.wifi.leave()
