import pytest

pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.dut("rs9116_sapi"),
    pytest.mark.wifi_access_point("raspi_wifi")
]

@pytest.mark.parametrize("start_address, end_address", [(0, 65), (0, 127), (37, 3457), (60000, 65535)])
@pytest.mark.test_src_map_id('SM11932')
def test_ram_dump(wifi_dut, start_address, end_address):
    ram_data = wifi_dut.interfaces.wifi.get_ram_dump(start_address, end_address)
    assert len(ram_data) == end_address - start_address + 1
