import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode
from utf.utils.logger import get_logger


def logger():
    return get_logger(__name__)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.parametrize("time_limit", [60, 120])
def test_ble_vulnerable_sniffer(wifi_dut, wifi_access_point, ble_vulnerable_sniffer, time_limit):
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None
    wifi_dut.interfaces.wifi.ble_start_advertising()

    ble_vulnerable_sniffer.interfaces.docker_host.init_sniffer()
    script_path = "telink_key_size_overflow"
    stop_capture_on = ["crash", "error", "exception", "oops"]
    result = ble_vulnerable_sniffer.interfaces.docker_host.start_capture(script_path, bt_dut_address, stop_capture_on, time_limit=time_limit)
    assert result
