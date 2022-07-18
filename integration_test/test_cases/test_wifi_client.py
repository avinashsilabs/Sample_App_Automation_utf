import pytest

pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.dut("rs9116_sapi")
]


def test_wifi_client_leave(wifi_access_point, wifi_client, logger):
    wifi_client.interfaces.wifi.join_ap(wifi_access_point)
    assert (
            wifi_client.interfaces.wifi.ping(
                server_ip=wifi_client.interfaces.wifi.client_gateway_ip
            )
            < 0.5
    )
