import time

from utf_wiseconnect.devices.rs911x import RS9116OperatingMode, RS9116Band, RS9116CoexMode, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116PowerSaveModes
from utf_wiseconnect.utils.rs911x_version import parse_version, extract_version
from utf.utils.time_measurer import TimeMeasurer
import pytest
from utf.utils.logger import get_logger


def logger():
    return get_logger(__name__)


def test_version(wifi_dut):
    expected_version = parse_version()
    if expected_version is None:
        pytest.skip("No firmware version for 9116x in manifest, skipping test_version")

    logger().info(f"Expected FW version: {expected_version}")
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Actual version: {result}")
    assert result == expected_version


def test_scan(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None)
    logger().info(scan_results)
    assert len(scan_results) > 0
    logger().info(f"Scan in {t.duration} seconds")


def test_wifi_join(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        result = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result
    logger().info(f"Associated in {t.duration} seconds")


def test_wifi_dhcp(wifi_associated_dut):
    with TimeMeasurer() as t:
        result = wifi_associated_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_associated_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    logger().info(f"Got {result} via DHCP in {t.duration} seconds")


def test_wifi_ping(wifi_networked_dut):
    with TimeMeasurer() as t:
        wifi_networked_dut.interfaces.wifi.ping()
    logger().info(f"Ping completed in {t.duration} seconds")


def test_wifi_leave(wifi_networked_dut):
    with TimeMeasurer() as t:
        wifi_networked_dut.interfaces.wifi.leave()
    logger().info(f"Leave completed in {t.duration} seconds")


@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": RS9116OperatingMode.AccessPoint},
)
def test_wifi_start_ap(wifi_dut):
    wifi_dut.interfaces.wifi.start_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": RS9116OperatingMode.AccessPoint},
)
def test_wifi_join_9116_ap(wifi_ap_dut, wifi_client):
    wifi_client.interfaces.wifi.join()
    assert (
        wifi_client.interfaces.wifi.ping(
            server_ip=wifi_client.interfaces.wifi.client_gateway_ip
        )
        < 0.1
    )


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        "security": "WPA",
        "ssid": "RS9116_AP",
        "passphrase": "12345678",
        "channel": 36,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA",
        "ssid": "RS9116_AP",
        "passphrase": "12345678",
        "channel": 36,
    },
)
def test_wifi_join_9116_ap_5g(wifi_dut, wifi_client):
    wifi_dut.interfaces.wifi.start_ap()
    wifi_client.interfaces.wifi.join()
    assert (
        wifi_client.interfaces.wifi.ping(
            server_ip=wifi_client.interfaces.wifi.client_gateway_ip
        )
        < 0.1
    )


def test_parse_verion_from_web_server(http_server, http_client):
    server_stat = http_server.interfaces.http.started
    assert server_stat, "server not started"
    status, content = http_client.interfaces.http.http_request(
        http_server.interfaces.http, "GET", '/RS9116.2.5.0.4.rps'
    )
    assert status == 200
    version = extract_version(content)
    assert version == '1610.2.5.0.0.4'

@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            }
        )
@pytest.mark.wifi_access_point("raspi_wifi")
def test_wifi_join_special_char_32bit(wifi_dut, wifi_access_point):
    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
    # Enables the bt power save in DUT
    logger().info("Setting DUT in bt power save...")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    #
    ssid_list = ["*@test1*#test1*@test1*$st1*$st1*", "是不了是不了$*TEST##@12345", "джф-这是书-ئضڪڪ-ඤౠ"]

    for ssid in ssid_list:
        # initiates the access point with channel given in list
        logger().info(f"Setting access point with ssid {ssid}...")
        wifi_access_point.interfaces.wifi.start_ap(ssid=ssid)
        time.sleep(1)
        logger().info(f"Initiating the scan from DUT with ssid {ssid}..")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=ssid)
        logger().info(scan_results)
        assert len(scan_results)>=1,f"32 bytes ssid not found in scan results"
        assert wifi_dut.interfaces.wifi.join(ssid=ssid)
        time.sleep(1)
        wifi_dut.interfaces.wifi.leave()
        time.sleep(1)
