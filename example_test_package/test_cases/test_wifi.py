from devices.rs911x import RS9116OperatingMode
from utils.iperf.Iperf_constants import IperfConstants
from utils.rs911x_version import parse_version
from utils.time_measurer import TimeMeasurer
import time
import pytest
from utils.logger import get_logger


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
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint
    },
)
def test_wifi_start_ap(wifi_dut):
    wifi_dut.interfaces.wifi.start_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint
    },
)
def test_wifi_join_9116_ap(wifi_ap_dut, wifi_client):
    wifi_client.interfaces.wifi.join()
    assert wifi_client.interfaces.wifi.ping(server_ip=wifi_client.interfaces.wifi.client_gateway_ip) < 0.1


@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
             'ssid': 'TESTTESTTEST2'
        },
        1: {
             'ssid': 'Codecom123'
        }
    }
)
def test_multiple_access_points(wifi_dut, wifi_access_points):
    for wifi_ap in wifi_access_points:
        result = wifi_dut.interfaces.wifi.join_ap(wifi_ap)
        assert result
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, no need to provide respective index if there are no test case level config.
        1: {
             'ssid': 'Alia_2G'
        }
    }
)
def test_multiple_access_points(wifi_dut, wifi_access_points):
    for wifi_ap in wifi_access_points:
        result = wifi_dut.interfaces.wifi.join_ap(wifi_ap)
        assert result
        wifi_dut.interfaces.wifi.leave()
