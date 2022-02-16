import time
import pytest
from devices.rs911x import RS9116CoexMode
from interfaces.bluetooth.bluez import BatteryService
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from interfaces.bluetooth import BLEDeviceState
from utils.logger import get_logger
from interfaces.wifi import WlanError
from interfaces.bluetooth import BLEConnectError


def logger():
    return get_logger(__name__)


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
    wifi_dut.interfaces.wifi.ble_stop_scanning()
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
    time.sleep(0.5)

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
    time.sleep(0.5)

    # notify only - disabled notifications - should raise exception
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.ble_notify_value()
    assert exc_info.value.error_code == 0x21

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

    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None

    # Set up BLE Server on DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None
    wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
    wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
    wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None

    time.sleep(1)

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
    time.sleep(0.5)

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
    time.sleep(0.5)

    # notify only - disabled notifications - should raise exception
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.ble_notify_value()
    assert exc_info.value.error_code == 0x21

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
    #TODO
    bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
    assert bt_dut_address is not None

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=[BatteryService])
    assert bt_client_address is not None

    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    wifi_dut.interfaces.wifi.ble_stop_scanning()
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    #TODO
    #ble_get_profiles_async bt_client_address - expect "RSI_BLE_GATT_PROFILES - resolved"
    #call this, parse the response  and assert for the presence of BatteryService's uuid in the resolved services
    #index value determines how many services we resolved. parse these services into an array

    #TODO
    #ble_get_profile_async B8:27:EB:8E:A9:99 6159 - RSI_BLE_GATT_PROFILE - resolved
    #6159 is the decimal format of BatteryService.UUID
    #call this, parse the response and expect to have start_handle and end_handle greater then 0

    #TODO
    #ble_get_char_services_async B8:27:EB:8E:A9:99 14 18
    #14 and 18 are the start and end handles from the previous call
    #expect RSI_BLE_GATT_CHAR_SERVICES - resolved
    #Index value determines how many characteristics we have resovled
    #for each index value capture the response as one characteristics
    #there should be one uuid 0x2a19, matching the uuid of BatteryLevelCharacteristic.UUID and should also have a write_handle greater then 0

    #TODO
    #ble_set_att_value_async B8:27:EB:8E:A9:99 16 89
    #16 is the write_handle, 89 is any number between 0 and 100 to set the battery level of battery service

    #TODO
    #ble_get_att_value_async B8:27:EB:8E:A9:99 16
    #expect rsi_ble_on_read_resp_event_gatt - att_value
    #read the response and parse the att_value it should be same as the one sent in the previous command

    #TODO
    #call events = wifi_dut.interfaces.wifi.get_async_events()
    #ble_set_att_value_async B8:27:EB:8E:A9:99 17 1
    #call above command to enable notifications
    #time.sleep(some delay, say 6 sec) #battery service sents notification every 2 sec
    # call ble_set_att_value_async B8:27:EB:8E:A9:99 17 0 to disable notifications
    #call events = wifi_dut.interfaces.wifi.get_async_events()
    #sleep for two sec just to be safe side
    #parse events received and look for "rsi_ble_on_gatt_write_event_gatt - att_value - 87" strings
    #assert the expected count of events based on the delay given above
    #capture the latest battery level value from the last event

    #TODO
    #call ble_get_att_value_async B8:27:EB:8E:A9:99 16 to read the battery value again this is already called above
    #assert the value with the latest battery level value read in the above command

    # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
