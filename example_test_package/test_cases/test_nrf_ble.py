import time
import pytest
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.wifi import WlanError
from utf_wiseconnect.devices.rs911x import RS9116CoexMode
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth.blatann import NRFBLEIoCapabilities
from utf.interfaces.bluetooth.blatann import NRFBLEServiceUuid, NRFBLECharacteristicUuid


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

    found_devices = nrf_ble_client.interfaces.bluetooth.get_devices()

    assert bt_dut_address in found_devices

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

    found_devices = nrf_ble_client.interfaces.bluetooth.get_devices()

    assert bt_dut_address in found_devices

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

    nrf_ble_client.interfaces.bluetooth.pair(bt_dut_address)

    nrf_ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_blatann_scanning(wifi_dut, wifi_access_point, nrf_ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    # Join Wi-Fi Access Point
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None

    # Start ble client
    bt_client_address = nrf_ble_client.interfaces.bluetooth.start_advertising(timeout_sec=0, auto_restart=True)
    assert bt_client_address is not None

    time.sleep(1)

    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(
        ble_client_address=bt_client_address, timeout=30
    )

    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(
        ble_remote_dev_address=bt_client_address, timeout=timeout
    )

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert not state_int == BLEDeviceState.Connected


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_blatann_gatt_server_slave(wifi_dut, nrf_ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
    char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
    data1 = "LzY0"
    data2 = "K09x"
    data3 = "Mx3Y"

    # Join Wi-Fi Access Point
    # wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Set up BLE Server on DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None
    wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
    wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
    wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)

    # Start advertising
    wifi_dut.interfaces.wifi.ble_start_advertising()

    bt_client_address = nrf_ble_client.interfaces.bluetooth.start_scanning(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None

    found_devices = nrf_ble_client.interfaces.bluetooth.get_devices()

    assert bt_dut_address in found_devices

    nrf_ble_client.interfaces.bluetooth.connect(bt_dut_address)
    nrf_ble_client.interfaces.bluetooth.stop_scanning()
    time.sleep(2)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    nrf_ble_client.interfaces.bluetooth.discover_services()
    #wait for 10 seconds to complete service discovery
    time.sleep(10)

    nrf_ble_client.interfaces.bluetooth.find_service(service_uuid=NRFBLEServiceUuid.TEST_SERVICE_UUID.value)

    nrf_ble_client.interfaces.bluetooth.find_characteristic(characteristic_uuid=NRFBLECharacteristicUuid.TEST_CHARACTERISTIC_UUID.value)

    result = nrf_ble_client.interfaces.bluetooth.read_characteristic_value(characteristic_uuid=NRFBLECharacteristicUuid.TEST_CHARACTERISTIC_UUID.value)
    assert result == data1

    nrf_ble_client.interfaces.bluetooth.subscribe_to_notifications(characteristic_uuid=NRFBLECharacteristicUuid.TEST_CHARACTERISTIC_UUID.value)

    # notify only
    wifi_dut.interfaces.wifi.ble_notify_value()

    # write/read new value - Notifications enabled
    nrf_ble_client.interfaces.bluetooth.write_characteristic_value(
        characteristic_uuid=NRFBLECharacteristicUuid.TEST_CHARACTERISTIC_UUID.value, data=data2
    )
    time.sleep(0.1)
    result = nrf_ble_client.interfaces.bluetooth.read_characteristic_value(
        characteristic_uuid=NRFBLECharacteristicUuid.TEST_CHARACTERISTIC_UUID.value
    )
    assert result == data2

    # write value - Notifications enabled
    nrf_ble_client.interfaces.bluetooth.write_characteristic_value(
        characteristic_uuid=NRFBLECharacteristicUuid.TEST_CHARACTERISTIC_UUID.value, data=data3
    )

    # auto notify
    nrf_ble_client.interfaces.bluetooth.subscribe_to_notifications(
        characteristic_uuid=NRFBLECharacteristicUuid.TEST_CHARACTERISTIC_UUID.value
    )
    wifi_dut.interfaces.wifi.ble_start_notify_value(interval_ms=500, count=2)
    time.sleep(1)

    nrf_ble_client.interfaces.bluetooth.unsubscribe_to_notifications(
        characteristic_uuid=NRFBLECharacteristicUuid.TEST_CHARACTERISTIC_UUID.value
    )
    time.sleep(1)
    # notify only - disabled notifications - should raise exception
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.ble_notify_value()
    assert exc_info.value.error_code == 0x21 or exc_info.value.error_code == 0xFFFFFFFD

    # assert received notifications
    notifications = nrf_ble_client.interfaces.bluetooth.notifications[NRFBLECharacteristicUuid.TEST_CHARACTERISTIC_UUID.value]
    logger().info(notifications)
    assert len(notifications) == 6
    assert notifications[0] == data1
    assert notifications[1] == data2
    assert notifications[2] == data2
    assert notifications[3] == data3
    assert notifications[4] == data3
    assert notifications[5] == data3

    # disconnecting from dut
    nrf_ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
