import time

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
@pytest.mark.parametrize("time_limit", [60])
def test_cpc(wifi_dut, wifi_access_point, ble_sweynetooth, time_limit):
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None
    wifi_dut.interfaces.wifi.ble_start_advertising()

    ble_sweynetooth.interfaces.docker_host.init()
    result = ble_sweynetooth.interfaces.docker_host.telink_key_size_overflow(bt_dut_address, time_limit=time_limit)
    ble_sweynetooth.interfaces.docker_host.close()
    assert result
