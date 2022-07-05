
def test_ram_dump(wifi_dut, start_address, end_address):
    ram_data = wifi_dut.interfaces.wifi.get_ram_dump(start_address, end_address)
    assert len(ram_data) == end_address - start_address + 1
