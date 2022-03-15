from utf_wiseconnect.devices.rs911x import RS9116OperatingMode
import time
import pytest
from utf.utils.logger import get_logger

def logger():
    return get_logger(__name__)


@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {"ssid": "TESTTESTTEST2"},
        1: {"ssid": "Codecom123"},
    },
)
def test_multiple_access_points_config_override(wifi_dut, wifi_access_points):
    for wifi_ap in wifi_access_points:
        result = wifi_dut.interfaces.wifi.join_ap(wifi_ap)
        assert result
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, no need to provide respective index if there are no test case level config.
        1: {"ssid": "Alia_2G"}
    },
)
def test_multiple_access_points(wifi_dut, wifi_access_points):
    for wifi_ap in wifi_access_points:
        result = wifi_dut.interfaces.wifi.join_ap(wifi_ap)
        assert result
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config("wifi_dut", wifi={"oper_mode": RS9116OperatingMode.AccessPoint})
def test_multiple_wifi_clients(wifi_dut, wifi_clients):
    wifi_dut.interfaces.wifi.start_ap()
    for wifi_client in wifi_clients:
        wifi_client.interfaces.wifi.join()
        time.sleep(0.5)
        assert (
            wifi_client.interfaces.wifi.ping(
                server_ip=wifi_client.interfaces.wifi.client_gateway_ip
            )
            < 0.1
        )