import pytest


@pytest.mark.start_state('wifi_dut', wifi='init')
@pytest.mark.test_src_map_id('TC1721618446')
def test_wifi_get_mac_address(wifi_dut):
    wifi_dut.interfaces.wifi.get_mac_address()