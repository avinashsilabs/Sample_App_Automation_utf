import time
import pytest

from utf.interfaces.bluetooth.bluez import BatteryService
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryLevelCharacteristic
from utf_wiseconnect.devices.rs911x import RS9116CoexMode
from utf.interfaces.wifi import WlanError
from utf.interfaces.bluetooth import BLEConnectError
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.stopwatch import Stopwatch

# Mark all tests in this module with 'framework_integration_test'
pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.dut("rs9116_sapi"),
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        },
    ),
]


@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "ble_disconnect"])
def test_ble_advertisement(wifi_dut, wifi_access_point, ble_client, logger):
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
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=bt_dut_address
    )
    assert bt_client_address is not None

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == wifi_dut.interfaces.wifi.ble_advertising_data:
            device_found = True
            break
    assert device_found

    # Not valid to start advertising if we're already advertising...
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.ble_start_advertising()
    assert exc_info.value.error_code == 0x4E0C  # "command disallowed"

    ble_client.interfaces.bluetooth.connect(bt_dut_address)
    ble_client.interfaces.bluetooth.stop_scanning()
    time.sleep(1)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # Connecting will automatically stop advertising
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.ble_stop_advertising()
    assert exc_info.value.error_code == 0x4E0C  # "command disallowed"

    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "ble_disconnect"])
def test_ble_scanning(wifi_dut, wifi_access_point, ble_client, logger):

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
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=bt_dut_address
    )
    assert bt_client_address is not None
    time.sleep(1)

    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(
        ble_client_address=bt_client_address, timeout=60
    )
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger.info(f"Initiating connection -- this can take up to {timeout} seconds....")
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


@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "ble_disconnect"])
def test_ble_gatt_server_slave(wifi_dut, wifi_access_point, ble_client, logger):
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

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == wifi_dut.interfaces.wifi.ble_advertising_data:
            device_found = True
            break

    assert device_found

    # connecting to dut
    ble_client.interfaces.bluetooth.connect(bt_dut_address)
    ble_client.interfaces.bluetooth.stop_scanning()
    time.sleep(2)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # resolving charecteristic
    servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
    assert len(servs) > 0
    assert len(chars) > 0

    char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                           service_uid=service_uid,                                                                             char_uid=char_uid)
    assert char_path is not None
    assert len(char_props) > 0

    # read value - Notifications not enabled
    result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
    assert result == data1

    # subscribe to notifications
    ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
    ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path, char_uid=char_uid)

    # notify only
    wifi_dut.interfaces.wifi.ble_notify_value()

    # write/read new value - Notifications enabled
    ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(char_path=char_path, data=data2)
    time.sleep(0.1)
    result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
    assert result == data2


    # write value - Notifications enabled
    ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(char_path=char_path, data=data3)

    # auto notify
    ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path, char_uid=char_uid)
    wifi_dut.interfaces.wifi.ble_start_notify_value(interval_ms=500, count=2)
    time.sleep(1)

    # subscribe to notifications
    ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
    ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
    time.sleep(1)
    # notify only - disabled notifications - should raise exception
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.ble_notify_value()
    assert exc_info.value.error_code == 0x21 or exc_info.value.error_code == 0xFFFFFFFD

    # assert received notifications
    notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
    logger.info(notifications)
    assert len(notifications) == 6
    assert notifications[0] == data1
    assert notifications[1] == data2
    assert notifications[2] == data2
    assert notifications[3] == data3
    assert notifications[4] == data3
    assert notifications[5] == data3

    # disconnecting from dut
    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


# For now as we are not sure about the changes required on the DUT side the start_smp_scan is tested using mobile
@pytest.mark.skip()
def test_ble_gatt_client_slave(ble_client, logger):
    logger.info("""
        Put the mobile in advertising mode.. 
        Make sure that local name is part of advertisement
        Assign the device local name to the local_name variable...""")

    bt_dut_address = None # to be determined once the device is found in scanning
    local_name = "ROG_Phone3"

    # Begin Scanning for BLE devices
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address="0", service_classes=["BatteryService"])
    assert bt_client_address is not None

    logged_devices = [] # to avoid logging the device again
    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 100:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        for key, value in found_devices.items():
            # The following condition can be skipped if you are not interested in logging the devices
            if key not in logged_devices:
                logger.info(f"found_devices[bt_dut_address] - {key} : {value}")
                logged_devices.append(key)
            if found_devices[key] == local_name:
                device_found = True
                bt_dut_address = key
        if device_found:
            break
        time.sleep(0.5)

    assert device_found

    # connecting to dut
    ble_client.interfaces.bluetooth.connect(bt_dut_address)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger.info("Sleeping for 30 sec.. Perform Gatt operations on mobile and check if it is working...")
    time.sleep(60)


@pytest.mark.firmware_app("test_multi_gatt_conn")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "ble_disconnect"])
def test_ble_gatt_client_master(firmware_loader, wifi_dut, wifi_access_point, ble_client, logger):
    # # Join Wi-Fi Access Point
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
    assert bt_dut_address is not None

    # Start ble client
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=["BatteryService"])
    assert bt_client_address is not None

    # Start scanning and connect to ble client
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    wifi_dut.interfaces.wifi.ble_stop_scanning()
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger.info(f"Initiating connection this can take upto {timeout} seconds....")
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
    assert BatteryLevelCharacteristic.BLEVEL_UUID in uuids
    index = uuids.index(BatteryLevelCharacteristic.BLEVEL_UUID)

    assert char_properties[index].isdigit()
    assert BatteryLevelCharacteristic.prop_int == int(char_properties[index])

    write_handle = int(write_handles[index], 16)
    assert write_handle > 0

    # read value
    val=wifi_dut.interfaces.wifi.ble_get_att_value_async(ble_remote_dev_address=bt_client_address,
                                                     char_property=write_handle)
    assert int(val) > 0

    # enable notifications
    since_time = time.perf_counter_ns()
    wifi_dut.interfaces.wifi.ble_set_att_int_value_async(ble_remote_dev_address=bt_client_address,
                                                     char_property=(write_handle+1), value=1)
    time.sleep(6)
    events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
    assert len(events) > 0
    latest_val = events[-1].event_data #capturing the last value notified by Gatt server
    assert int(latest_val) < int(val)

    # read value
    val = wifi_dut.interfaces.wifi.ble_get_att_value_async(ble_remote_dev_address=bt_client_address,
                                                                char_property=write_handle)
    assert int(val) <= int(latest_val)


    # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
