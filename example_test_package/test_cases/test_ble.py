import time
import pytest
from devices.rs911x import RS9116CoexMode
from interfaces.cli.rs_sapi_commands import RSSAPICommands

@pytest.mark.skip
@pytest.mark.parametrize(
    "wifi_dut",
    [
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        }
    ],
    indirect=True,
)
def test_ble_advertisement(wifi_dut, wifi_access_point, ble_client):

    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    # Join Wi-Fi Access Point
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Set up DUT for BLE advertising
    wifi_dut.interfaces.wifi.ble_start()
    wifi_dut.interfaces.wifi.ble_start_advertising()

    # Begin Scanning for BLE devices
    ble_client.interfaces.bluetooth.start_scanning()
    time.sleep(5)

    # Stop advertising and quit scanning
    wifi_dut.interfaces.wifi.ble_stop_advertising()
    ble_client.interfaces.bluetooth.stop_scanning()

    # See that we found our device
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert wifi_dut.interfaces.wifi.ble_address in found_devices
    assert (
        found_devices[wifi_dut.interfaces.wifi.ble_address]
        == wifi_dut.interfaces.wifi.ble_advertising_data
    )


@pytest.mark.parametrize(
    "wifi_dut",
    [
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        }
    ],
    indirect=True,
)
def test_ble_advertisement(wifi_dut, bluez_client):

    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    # Join Wi-Fi Access Point
    # wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    #Set up DUT for BLE advertising
    wifi_dut.interfaces.wifi.ble_start()

    # Begin Scanning for BLE devices
    bluez_client.interfaces.bluetooth.start_advertising()
    bluez_client.interfaces.bluetooth.start()

    wifi_dut.interfaces.wifi.ble_start_scanning()
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address= "B8:27:EB:8E:A9:99")
    wifi_dut.interfaces.wifi.ble_get_device_state()

    # # Stop advertising and quit scanning
    # wifi_dut.interfaces.wifi.ble_stop_advertising()
    # ble_client.interfaces.bluetooth.stop_scanning()
    #
    # # See that we found our device
    # found_devices = ble_client.interfaces.bluetooth.get_devices()
    # assert wifi_dut.interfaces.wifi.ble_address in found_devices
    # assert (
    #     found_devices[wifi_dut.interfaces.wifi.ble_address]
    #     == wifi_dut.interfaces.wifi.ble_advertising_data
    # )
