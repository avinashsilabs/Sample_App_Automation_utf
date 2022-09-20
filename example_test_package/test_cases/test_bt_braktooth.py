
import time
import pytest

from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.stopwatch import Stopwatch
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
    "bt_vulnerability_sniffer",
    bt_vulnerability_sniffer={
        "log_file": "test_config_for_bt_vulnerability_sniffer.log",
        "bt_exploit_type": "au_rand_flooding"
    },
)
def test_bt_vulnerability_sniffer(
    wifi_dut, bt_client, wifi_access_point, bt_vulnerability_sniffer, logger
):
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    bt_dut_address = wifi_dut.interfaces.wifi.bt_start()
    assert bt_dut_address is not None
    started = bt_vulnerability_sniffer.interfaces.bt_vulnerability_sniffer.start_capture(
        dut_address=bt_dut_address
    )
    assert started
    wifi_dut.interfaces.wifi.bt_start_advertising()

    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = bt_client.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == wifi_dut.interfaces.wifi.bt_advertising_data:
            device_found = True
            break

    bt_client.interfaces.bluetooth.stop_scanning()
    assert device_found

    bt_client.interfaces.bluetooth.connect(bt_dut_address)
    time.sleep(2)
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)