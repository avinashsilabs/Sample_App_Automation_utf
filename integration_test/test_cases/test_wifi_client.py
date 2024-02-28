import pytest

from utf_wiseconnect.devices.rs911x import RS9116OperatingMode

pytestmark = [
    pytest.mark.framework_integration_test
]


# TODO : Change he security to WPA3 - This requires that we connect WPA3 supported dongle to Raspi. Change my mobile hotspot security to WPA3 Personal
@pytest.mark.wifi_access_point('static_ap')
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "ssid":'Pixel_2180', "passphrase":'19031903'})
@pytest.mark.config('wifi_client', wifi={"security": 'WPA2', "ssid":'Pixel_2180', "passphrase":'19031903'})
@pytest.mark.test_src_map_id('SM00989')
def test_wifi_join_ap_wpa3(wifi_access_point, wifi_client):
    wifi_client.interfaces.wifi.join_ap(wifi_access_point)
    assert wifi_client.interfaces.wifi.client_associated, "WiFi client could not join AP"
    assert (
            wifi_client.interfaces.wifi.ping(
                server_ip=wifi_client.interfaces.wifi.client_gateway_ip
            )
            < 2
    ), "Ping failed"


@pytest.mark.test_src_map_id('SM00992')
def test_wifi_join_ap(wifi_access_point, wifi_client, logger):
    wifi_client.interfaces.wifi.join_ap(wifi_access_point)
    assert wifi_client.interfaces.wifi.client_associated, "WiFi client could not join AP"
    assert (
            wifi_client.interfaces.wifi.ping(
                server_ip=wifi_client.interfaces.wifi.client_gateway_ip
            )
            < 2
    ), "Ping failed"


@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": RS9116OperatingMode.AccessPoint},
)
@pytest.mark.test_src_map_id('SM00996')
def test_wifi_join_dut_ap(wifi_ap_dut, wifi_client):
    wifi_client.interfaces.wifi.join()
    assert wifi_client.interfaces.wifi.client_associated, "WiFi client could not join DUT AP"
    assert (
        wifi_client.interfaces.wifi.ping(
            server_ip=wifi_client.interfaces.wifi.client_gateway_ip
        )
        < 2
    ), "Ping failed"
