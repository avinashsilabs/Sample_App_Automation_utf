import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116FeatureBitMap,
    RS9116TCPIPFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116PowerSaveModes)
from utf.utils.logger import get_logger
import time
import datetime
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEDeviceState


def logger():
    return get_logger(__name__)


iter_count = 1001


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_scan_1000_times_C19810(wifi_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address, "ble initialization failed in dut"

    for i in range(1, iter_count):
        logger().info("start ble scan in rd_1")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert bt_client_address, "ble initialization failed in remote device_1"
        time.sleep(2)

        scan_results = wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address,
                                                                   timeout=120)
        time.sleep(10)
        logger().info(f'Scan iter_count:{i}')
        logger().info(f" scan result '{scan_results}")
        assert scan_results, "ble devices not found"
        logger().info(f"found BT client address of {bt_client_address}")

        wifi_dut.interfaces.wifi.ble_stop_scanning()
        time.sleep(5)
        ble_client.interfaces.bluetooth.close()
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_scan_continuous_48_hrs_C19829(wifi_dut, ble_client):
    t_end = time.time() + 60 * 2880
    while time.time() < t_end:

        logger().info("start ble in dut")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address, "ble initialization failed in dut"

        logger().info("start ble scan in rd_1")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert bt_client_address, "ble initialization failed in remote device"
        time.sleep(2)

        scan_results = wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address,
                                                                   timeout=120)
        time.sleep(10)

        logger().info(f" scan result '{scan_results}")
        assert scan_results, "ble devices not found"
        logger().info(f"found BT client address of {bt_client_address}")

        wifi_dut.interfaces.wifi.ble_stop_scanning()
        time.sleep(5)
        ble_client.interfaces.bluetooth.close()
    time.sleep(5)