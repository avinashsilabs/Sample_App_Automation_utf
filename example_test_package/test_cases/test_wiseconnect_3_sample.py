import pytest


@pytest.mark.start_state('wifi_dut', wifi='init')
def test_wifi_get_mac_address(wifi_dut):
    wifi_dut.interfaces.wifi.get_mac_address()