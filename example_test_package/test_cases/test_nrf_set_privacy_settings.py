import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode
from utf.interfaces.bluetooth.nrf_blatann import (
    NRFBLEIoCapabilities
)
import time
from utf.utils.stopwatch import Stopwatch
import time
import pytest
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.wifi import WlanError
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode


def logger():
    return get_logger(__name__)


@pytest.mark.config(
    "ble_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
    },
)
def test_nrf_set_privacy_settings(ble_dut, nrf_ble_client):
    # Start DUT
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address is not None

    # Start scanning
    ble_dut.interfaces.bluetooth.ble_start_scanning()

    nrf_ble_client.interfaces.bluetooth.set_privacy_settings(enabled=True, resolvable_address=True, update_rate_seconds=900)

    # Start ble client
    nrf_ble_client.interfaces.bluetooth.start_advertising(
        timeout_sec=0, auto_restart=True
    )
