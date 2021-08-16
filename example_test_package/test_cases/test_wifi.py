from utils.iperf.Iperf_constants import IperfConstants
from utils.rs911x_version import parse_version
import time
import pytest
from utils.logger import get_logger


class TimeMeasurer:
    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__duration = time.perf_counter() - self.start_time

    @property
    def duration(self):
        return self.__duration


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


# AP mode tests will fail in SAPI, possibly an actual bug?
@pytest.mark.skip
def test_wifi_start_ap(wifi_dut):
    wifi_dut.interfaces.wifi.start_ap()

# @pytest.mark.skip
def test_wifi_join_9116_ap(wifi_ap_dut, wifi_client):
    wifi_client.interfaces.wifi.join()
    assert wifi_client.interfaces.wifi.ping() < 0.1
