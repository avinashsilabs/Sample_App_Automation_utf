import time
import pytest
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116AsyncEventType
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.wifi import WlanError


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_data_length_advertisement(wifi_dut, wifi_access_point, ble_client, logger):
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

    # Begin Scanning for BLE devices
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == wifi_dut.interfaces.wifi.ble_advertising_data:
            device_found = True
            break

    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found

    # Not legal to start advertising if we're already advertising...
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.ble_start_advertising()
    assert exc_info.value.error_code == 0x4E0C  # "command disallowed"

    ble_client.interfaces.bluetooth.connect(bt_dut_address)
    time.sleep(1)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # setting data length on ble_client
    since_time = time.perf_counter_ns()
    with BleLogs(start_collecting_logs=True, bt_log_path=f"/tmp/test_data_length_advertisement_{int(time.time())}.log") as ble_logs:
        ble_client.interfaces.bluetooth.hci_tool_manager.set_data_length(bt_dut_address, "F7 00 28 08") #251 2088
        time.sleep(2)

    # Checking data length change event on the ble_client side
    events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
    data_length_change_events = [e for e in events if e.event_type == RS9116AsyncEventType.Ble_data_length_change]
    assert len(data_length_change_events) == 1
    [event] = data_length_change_events
    assert event is not None, "Did not receive the data length change event"

    # Checking data length change event on the dut side
    [tx_len, tx_time, rx_len, rx_time] = ble_logs.data_length_change_values()
    assert tx_len
    assert tx_time
    assert rx_len
    assert rx_time

    # Connecting will automatically stop advertising
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.ble_stop_advertising()
    assert exc_info.value.error_code == 0x4E0C  # "command disallowed"

    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_data_length_scanning(wifi_dut, wifi_access_point, ble_client, logger):
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
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None

    time.sleep(1)

    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger.info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # setting data length on dut
    since_time = time.perf_counter_ns()
    with BleLogs(start_collecting_logs=True, bt_log_path=f"/tmp/test_data_length_scanning.log_{int(time.time())}") as ble_logs:
        wifi_dut.interfaces.wifi.ble_set_data_length(bt_client_address, 0x00F7, 0x0848) #247, 2120
        time.sleep(2)

    # Checking data length change event on the ble_client side
    events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
    data_length_change_events = [e for e in events if e.event_type == RS9116AsyncEventType.Ble_data_length_change]
    assert len(data_length_change_events) == 1
    [event] = data_length_change_events
    assert event is not None, "Did not receive the data length change event"

    # Checking data length change event on the dut side
    [tx_len, tx_time, rx_len, rx_time] = ble_logs.data_length_change_values()
    assert tx_len
    assert tx_time
    assert rx_len
    assert rx_time

    # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert not state_int == BLEDeviceState.Connected
