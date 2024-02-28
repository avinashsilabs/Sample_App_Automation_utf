import time
import pytest
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.wifi import WlanError
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth.blatann import NRFBLEIoCapabilities


def logger():
    return get_logger(__name__)


# Non-secure connection support without data transfer, nrf_ble_client as central
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_blatann_advertisement(wifi_dut, wifi_access_point, nrf_ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    # Join Wi-Fi Access Point
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Set up DUT for BLE advertising
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None
    wifi_dut.interfaces.wifi.ble_start_advertising()

    nrf_ble_client.interfaces.bluetooth.set_default_scan_params(timeout_seconds=4)

    # Begin Scanning for BLE devices
    bt_client_address = nrf_ble_client.interfaces.bluetooth.start_scanning(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None

    device_found = False
    found_devices = nrf_ble_client.interfaces.bluetooth.get_devices()
    if (
        bt_dut_address in found_devices
        and found_devices[bt_dut_address]
        == wifi_dut.interfaces.wifi.ble_advertising_data
    ):
        device_found = True

    assert device_found
    nrf_ble_client.interfaces.bluetooth.stop_scanning()

    # Not legal to start advertising if we're already advertising...
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.ble_start_advertising()
    assert exc_info.value.error_code == 0x4E0C  # "command disallowed"

    nrf_ble_client.interfaces.bluetooth.connect(bt_dut_address)
    time.sleep(1)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # Connecting will automatically stop advertising
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.ble_stop_advertising()
    assert exc_info.value.error_code == 0x4E0C  # "command disallowed"

    nrf_ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


# nrf_ble_client as central
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_central(wifi_dut, wifi_access_point, nrf_ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    # Join Wi-Fi Access Point
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Set up DUT for BLE advertising
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None
    wifi_dut.interfaces.wifi.ble_start_advertising()

    nrf_ble_client.interfaces.bluetooth.set_default_scan_params(timeout_seconds=4)

    # Begin Scanning for BLE devices
    bt_client_address = nrf_ble_client.interfaces.bluetooth.start_scanning(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None

    device_found = False
    found_devices = nrf_ble_client.interfaces.bluetooth.get_devices()
    if (
        bt_dut_address in found_devices
        and found_devices[bt_dut_address]
        == wifi_dut.interfaces.wifi.ble_advertising_data
    ):
        device_found = True

    assert device_found

    nrf_ble_client.interfaces.bluetooth.stop_scanning()

    nrf_ble_client.interfaces.bluetooth.connect(bt_dut_address)
    time.sleep(1)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    nrf_ble_client.interfaces.bluetooth.set_security_params(passcode_pairing=True,
                                                            io_capabilities=NRFBLEIoCapabilities.KEYBOARD_DISPLAY,
                                                            bond=False, out_of_band=False)

    nrf_ble_client.interfaces.bluetooth.register_passkey_entry()

    nrf_ble_client.interfaces.bluetooth.register_peripheral_security_request()

    nrf_ble_client.interfaces.bluetooth.set_connection_parameters(100, 120, 6000)

    nrf_ble_client.interfaces.bluetooth.pair()

    nrf_ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
