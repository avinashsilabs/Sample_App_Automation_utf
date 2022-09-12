import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode
from utf.utils.logger import get_logger


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.config(
    "ble_vulnerability_sniffer",
    ble_vul_sniffer={
        "log_file": "test_config_for_ble_vul_sniffer.log",
        "script": "Telink_key_size_overflow.py"
    },
)
def test_ble_vulnerability_sniffer(
    wifi_dut, wifi_access_point, ble_vulnerability_sniffer, logger
):
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None
    started = ble_vulnerability_sniffer.interfaces.ble_vul_sniffer.start_capture(
        dut_address=bt_dut_address
    )
    assert started
    wifi_dut.interfaces.wifi.ble_start_advertising()

