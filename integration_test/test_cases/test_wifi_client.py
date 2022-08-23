import pytest

from utf_wiseconnect.devices.rs911x import RS9116OperatingMode

pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.dut("rs9116_sapi")
]


def test_wifi_join_ap(wifi_access_point, wifi_client, logger):
    wifi_client.interfaces.wifi.join_ap(wifi_access_point)
    assert wifi_client.interfaces.wifi.client_associated, "WiFi client could not join AP"
    assert (
            wifi_client.interfaces.wifi.ping(
                server_ip=wifi_client.interfaces.wifi.client_gateway_ip
            )
            < 2
    ), "Ping failed"


@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": RS9116OperatingMode.AccessPoint},
)
def test_wifi_join_dut_ap(wifi_ap_dut, wifi_client):
    wifi_client.interfaces.wifi.join()
    assert wifi_client.interfaces.wifi.client_associated, "WiFi client could not join DUT AP"
    assert (
        wifi_client.interfaces.wifi.ping(
            server_ip=wifi_client.interfaces.wifi.client_gateway_ip
        )
        < 2
    ), "Ping failed"
