import time
import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryService
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryLevelCharacteristic
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.wifi import WlanError
from utf.interfaces.bluetooth import BLEConnectError


def logger():
    return get_logger(__name__)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_ibeacon_adv_params(wifi_dut, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None

    # Start ble client
    # for more information on hci_adv_params download Specification Details from
    # https://www.bluetooth.com/specifications/specs/core-specification-5-2/
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_ibeacon_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_ibeacon_adv_params="1E " #Number of bytes that follow in the advertisement(payload length)
                               "02 01 02 1A FF 4C 00 02 15 " #iBeacon prefix
                               "FB 0B 57 A2 82 28 44 CD 91 3A 94 A1 22 BA 12 06 " #UUID
                               "11 22 " #Major
                               "33 44 " #Minor
                               "33 " #Tx Power
                               "00 " #append 00s at end, based on length of payload
    )
    assert bt_client_address is not None

    time.sleep(1)

    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_custom_adv_params(wifi_dut, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None

    # Start ble client
    # for more information on hci_adv_params download Specification Details from
    # https://www.bluetooth.com/specifications/specs/core-specification-5-2/
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                       "0x40 0x00 "  # Advertising_Interval_Max
                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                       "0x00 "  # Own_Address_Type
                       "0x00 "  # Peer_Address_Type
                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                       "0x07 "  # Advertising_Channel_Map
                       "0x00"  # Advertising_Filter_Policy
    )
    assert bt_client_address is not None

    time.sleep(1)

    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_conn_params(wifi_dut, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None
    wifi_dut.interfaces.wifi.ble_start_advertising()

    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_scanning()

    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert wifi_dut.interfaces.wifi.ble_address in found_devices
    assert (
            found_devices[wifi_dut.interfaces.wifi.ble_address]
            == wifi_dut.interfaces.wifi.ble_advertising_data
    )

    ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                            min_conn_interval=160,
                                            max_conn_interval=160,
                                            conn_latency=0,
                                            supervision_timeout=2000)
    time.sleep(2)
    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_advertisement(wifi_dut, wifi_access_point, ble_client):
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
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_scanning()

    # See that we found our device
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert wifi_dut.interfaces.wifi.ble_address in found_devices
    assert (
            found_devices[wifi_dut.interfaces.wifi.ble_address]
            == wifi_dut.interfaces.wifi.ble_advertising_data
    )

    # Not legal to start advertising if we're already advertising...
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.ble_start_advertising()
    assert exc_info.value.error_code == 0x4E0C  # "command disallowed"

    ble_client.interfaces.bluetooth.connect(bt_dut_address)

    # Connecting will automatically stop advertising
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.ble_stop_advertising()
    assert exc_info.value.error_code == 0x4E0C  # "command disallowed"

    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)

    # Now, we can restart advertising...
    wifi_dut.interfaces.wifi.ble_start_advertising()
    # ...and stop again
    wifi_dut.interfaces.wifi.ble_stop_advertising()

    # we can't connect if the device is not advertising
    with pytest.raises(BLEConnectError):
        ble_client.interfaces.bluetooth.connect(bt_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_scanning(wifi_dut, wifi_access_point, ble_client):
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
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

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
def test_ble_gatt_server_slave(wifi_dut, wifi_access_point, ble_client):
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
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Set up BLE Server on DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None
    wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
    wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
    wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)

    # Start advertising
    wifi_dut.interfaces.wifi.ble_start_advertising()

    # Begin Scanning for BLE devices
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_scanning()

    # See that we found our device
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert wifi_dut.interfaces.wifi.ble_address in found_devices
    assert (
            found_devices[wifi_dut.interfaces.wifi.ble_address]
            == wifi_dut.interfaces.wifi.ble_advertising_data
    )

    # connecting to dut
    ble_client.interfaces.bluetooth.connect(bt_dut_address)
    time.sleep(2)

    # resolving charecteristic
    bus = ble_client.interfaces.bluetooth.bus
    servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
    assert len(servs) > 0
    assert len(chars) > 0

    char, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus,
                                                                                           services=servs,
                                                                                           service_uid=service_uid,
                                                                                           char_uid=char_uid)
    assert char is not None
    assert len(char_props) > 0

    # read value - Notifications not enabled
    result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
    assert result == data1

    # subscribe to notifications
    ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
    ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char, char_uid=char_uid)

    # notify only
    wifi_dut.interfaces.wifi.ble_notify_value()

    # write/read new value - Notifications enabled
    ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(characteristic=char, data=data2)
    time.sleep(0.1)
    result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
    assert result == data2


    # write value - Notifications enabled
    ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(characteristic=char, data=data3)

    # auto notify
    ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char, char_uid=char_uid)
    wifi_dut.interfaces.wifi.ble_start_notify_value(interval_ms=500, count=2)
    time.sleep(1)

    # subscribe to notifications
    ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(characteristic=char)
    ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)

    # notify only - disabled notifications - should raise exception
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.ble_notify_value()
    assert exc_info.value.error_code == 0x21 or exc_info.value.error_code == 0xFFFFFFFD

    # assert received notifications
    notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
    logger().info(notifications)
    assert len(notifications) == 6
    assert notifications[0] == data1
    assert notifications[1] == data2
    assert notifications[2] == data2
    assert notifications[3] == data3
    assert notifications[4] == data3
    assert notifications[5] == data3

    # disconnecting from dut
    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_gatt_server_master(wifi_dut, wifi_access_point, ble_client):
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
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Set up BLE Server on DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None
    wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
    wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
    wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None

    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=20)
    wifi_dut.interfaces.wifi.ble_stop_scanning()
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # Start advertising
    # characteristics are not visible until advertised
    wifi_dut.interfaces.wifi.ble_start_advertising()
    time.sleep(0.5)

    # resolving charecteristic
    bus = ble_client.interfaces.bluetooth.bus
    servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
    assert len(servs) > 0
    assert len(chars) > 0

    char, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus,
                                                                                           services=servs,
                                                                                           service_uid=service_uid,
                                                                                           char_uid=char_uid)
    assert char is not None
    assert len(char_props) > 0

    # read value - Notifications not enabled
    result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
    assert result == data1

    # subscribe to notifications
    ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
    ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char, char_uid=char_uid)

    # notify only
    wifi_dut.interfaces.wifi.ble_notify_value()

    # write/read new value - Notifications enabled
    ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(characteristic=char, data=data2)
    time.sleep(0.1)
    result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
    assert result == data2

    # write value - Notifications enabled
    ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(characteristic=char, data=data3)

    # auto notify
    ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char, char_uid=char_uid)
    wifi_dut.interfaces.wifi.ble_start_notify_value(interval_ms=500, count=2)
    time.sleep(1)

    # subscribe to notifications
    ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(characteristic=char)
    ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)

    # notify only - disabled notifications - should raise exception
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.ble_notify_value()
    assert exc_info.value.error_code == 0x21 or exc_info.value.error_code == 0xFFFFFFFD

    # assert received notifications
    notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
    logger().info(notifications)
    assert len(notifications) == 6
    assert notifications[0] == data1
    assert notifications[1] == data2
    assert notifications[2] == data2
    assert notifications[3] == data3
    assert notifications[4] == data3
    assert notifications[5] == data3

    # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)


@pytest.mark.skip #This test case needs a separate test agent.
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_gatt_client_master(wifi_dut, wifi_access_point, ble_client):
    # # Join Wi-Fi Access Point
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
    assert bt_dut_address is not None

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=[BatteryService])
    assert bt_client_address is not None

    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    wifi_dut.interfaces.wifi.ble_stop_scanning()
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                         expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # get all profiles
    uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert BatteryService.UUID in uuids

    # resolve battery profile
    start_handle, end_handle = wifi_dut.interfaces.wifi.ble_get_profile_async(ble_remote_dev_address=bt_client_address,
                                                             uuid=int(BatteryService.UUID, 16))
    assert start_handle is not None
    assert end_handle is not None

    # resolve characteristics of battery profile
    uuids, write_handles, char_properties = wifi_dut.interfaces.wifi.ble_get_char_services_async(ble_remote_dev_address=bt_client_address,
                    start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))
    assert BatteryLevelCharacteristic.UUID in uuids
    index = uuids.index(BatteryLevelCharacteristic.UUID)

    assert char_properties[index].isdigit()
    assert BatteryLevelCharacteristic.prop_int == int(char_properties[index])

    write_handle = int(write_handles[index], 16)
    assert write_handle > 0

    # write value
    new_value = 89
    wifi_dut.interfaces.wifi.ble_set_att_value_async(ble_remote_dev_address=bt_client_address,
                                                     char_property=write_handle, value=new_value)

    # read value
    val=wifi_dut.interfaces.wifi.ble_get_att_value_async(ble_remote_dev_address=bt_client_address,
                                                     char_property=write_handle)
    assert val == f'{new_value}'

    # enable notifications
    since_time = time.perf_counter_ns()
    wifi_dut.interfaces.wifi.ble_set_att_value_async(ble_remote_dev_address=bt_client_address,
                                                     char_property=(write_handle+1), value=1)
    time.sleep(6)
    events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
    assert len(events) > 0
    latest_val = events[-1].event_data #capturing the last value notified by Gatt server

    # read value
    val = wifi_dut.interfaces.wifi.ble_get_att_value_async(ble_remote_dev_address=bt_client_address,
                                                                char_property=write_handle)
    assert val == latest_val


    # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
