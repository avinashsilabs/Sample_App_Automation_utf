import time
import pytest
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.wifi import WlanError
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116CoexMode
from utf.interfaces.bluetooth.nrf_blatann import NRFBLEIoCapabilities
import threading


# Non-secure connection support without data transfer, nrf_ble_client as central
@pytest.mark.config(
    "ble_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.test_src_map_id("SM07362")
def test_nrf_ble_advertisement(ble_dut, nrf_ble_client):
    # Set up DUT for BLE advertising
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address is not None
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    scan_timeout = 10
    nrf_ble_client.interfaces.bluetooth.set_default_scan_params(
        timeout_seconds=scan_timeout
    )

    # Begin Scanning for BLE devices
    device_found = False
    nrf_ble_client.interfaces.bluetooth.start_scanning()
    sw = Stopwatch()
    while sw.elapsed_sec < scan_timeout:
        found_devices = nrf_ble_client.interfaces.bluetooth.get_devices()
        if (
            bt_dut_address in found_devices
            and found_devices[bt_dut_address]
            == ble_dut.interfaces.bluetooth.ble_advertising_data
        ):
            device_found = True
            break

    nrf_ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found

    # Not legal to start advertising if we're already advertising...
    with pytest.raises(WlanError) as exc_info:
        ble_dut.interfaces.bluetooth.ble_start_advertising()
    assert exc_info.value.error_code == 0x4E0C  # "command disallowed"

    nrf_ble_client.interfaces.bluetooth.connect(bt_dut_address)
    time.sleep(1)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # Connecting will automatically stop advertising
    with pytest.raises(WlanError) as exc_info:
        ble_dut.interfaces.bluetooth.ble_stop_advertising()
    assert exc_info.value.error_code == 0x4E0C  # "command disallowed"

    nrf_ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


@pytest.mark.config(
    "ble_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.test_src_map_id("SM07369")
def test_nrf_ble_scanning(ble_dut, nrf_ble_client):
    # Start DUT
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address is not None

    # Start ble client
    bt_client_address = nrf_ble_client.interfaces.bluetooth.start_advertising(
        timeout_sec=0, auto_restart=True
    )
    assert bt_client_address is not None

    time.sleep(1)

    # Start scanning and connect to ble client
    ble_dut.interfaces.bluetooth.ble_start_scanning(
        ble_client_address=bt_client_address, timeout=30
    )

    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    ble_dut.interfaces.bluetooth.ble_connect(
        ble_remote_dev_address=bt_client_address, timeout=timeout
    )

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(
        ble_remote_dev_address=bt_client_address
    )

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert not state_int == BLEDeviceState.Connected


@pytest.mark.config(
    "ble_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.test_src_map_id("SM07381")
def test_nrf_ble_gatt_server_slave(ble_dut, nrf_ble_client):
    service_uid = nrf_ble_client.interfaces.bluetooth.get_blatann_uuid(
        "6e"
    )  # TODO : This has to be replaced either with 0x006E or 110
    char_uid = nrf_ble_client.interfaces.bluetooth.get_blatann_uuid(
        "6f"
    )  # TODO : This has to be replaced either with 0x006F or 111
    data1 = "LzY0"
    data2 = "K09x"
    data3 = "Mx3Y"

    # Join Wi-Fi Access Point
    # ble_dut.interfaces.bluetooth.join_ap(wifi_access_point)

    # Set up BLE Server on DUT
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address is not None
    ble_dut.interfaces.bluetooth.ble_add_service(uid=0x6E)
    ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x6F)
    ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x6F, data=data1)

    # Start advertising
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    scan_timeout = 10
    nrf_ble_client.interfaces.bluetooth.set_default_scan_params(
        timeout_seconds=scan_timeout
    )

    # Begin Scanning for BLE devices
    device_found = False
    nrf_ble_client.interfaces.bluetooth.start_scanning()
    sw = Stopwatch()
    while sw.elapsed_sec < scan_timeout:
        found_devices = nrf_ble_client.interfaces.bluetooth.get_devices()
        if (
            bt_dut_address in found_devices
            and found_devices[bt_dut_address]
            == ble_dut.interfaces.bluetooth.ble_advertising_data
        ):
            device_found = True
            break

    nrf_ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found

    nrf_ble_client.interfaces.bluetooth.connect(bt_dut_address)
    time.sleep(2)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    nrf_ble_client.interfaces.bluetooth.discover_services()
    # wait for 10 seconds to complete service discovery
    time.sleep(10)

    nrf_ble_client.interfaces.bluetooth.find_service(service_uuid=service_uid)

    nrf_ble_client.interfaces.bluetooth.find_characteristic(
        characteristic_uuid=char_uid
    )

    result = nrf_ble_client.interfaces.bluetooth.read_characteristic_value(
        characteristic_uuid=char_uid
    )
    assert result == data1

    nrf_ble_client.interfaces.bluetooth.subscribe_to_notifications(
        characteristic_uuid=char_uid
    )

    # notify only
    ble_dut.interfaces.bluetooth.ble_notify_value()

    # write/read new value - Notifications enabled
    nrf_ble_client.interfaces.bluetooth.write_characteristic_value(
        characteristic_uuid=char_uid,
        data=data2,
    )
    time.sleep(0.1)
    result = nrf_ble_client.interfaces.bluetooth.read_characteristic_value(
        characteristic_uuid=char_uid
    )
    assert result == data2

    # write value - Notifications enabled
    nrf_ble_client.interfaces.bluetooth.write_characteristic_value(
        characteristic_uuid=char_uid,
        data=data3,
    )

    # auto notify
    nrf_ble_client.interfaces.bluetooth.subscribe_to_notifications(
        characteristic_uuid=char_uid
    )
    ble_dut.interfaces.bluetooth.ble_start_notify_value(interval_ms=500, count=2)
    time.sleep(1)

    nrf_ble_client.interfaces.bluetooth.unsubscribe_to_notifications(
        characteristic_uuid=char_uid
    )
    time.sleep(1)
    # notify only - disabled notifications - should raise exception
    with pytest.raises(WlanError) as exc_info:
        ble_dut.interfaces.bluetooth.ble_notify_value()
    assert exc_info.value.error_code == 0x21 or exc_info.value.error_code == 0xFFFFFFFD

    # assert received notifications
    notifications = nrf_ble_client.interfaces.bluetooth.notifications[char_uid]
    assert len(notifications) == 6
    assert notifications[0] == data1
    assert notifications[1] == data2
    assert notifications[2] == data2
    assert notifications[3] == data3
    assert notifications[4] == data3
    assert notifications[5] == data3

    # disconnecting from dut
    nrf_ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


@pytest.mark.test_src_map_id("SM24449")
def test_central_without_passcode_pairing(ble_client, nrf_ble_client):
    ble_client_address = nrf_ble_client.interfaces.bluetooth.get_ble_address()
    assert ble_client_address is not None

    bt_dut_address = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=ble_client_address
    )
    assert bt_dut_address is not None
    time.sleep(1)

    scan_timeout = 30
    nrf_ble_client.interfaces.bluetooth.set_default_scan_params(
        timeout_seconds=scan_timeout
    )

    # Begin Scanning for BLE devices
    nrf_ble_client.interfaces.bluetooth.start_scanning()  # this is not async
    found_devices = nrf_ble_client.interfaces.bluetooth.get_devices()
    assert (
        str(bt_dut_address) in found_devices
        and found_devices[str(bt_dut_address)]
        == ble_client.interfaces.bluetooth.get_ble_advertising_data()
    )

    nrf_ble_client.interfaces.bluetooth.stop_scanning()

    # Discovery complete, go to a longer connection interval
    nrf_ble_client.interfaces.bluetooth.set_connection_parameters(100, 120, 6000)
    connection_status = False
    try:
        nrf_ble_client.interfaces.bluetooth.connect(bt_dut_address)
        time.sleep(2)
        connection_status = (
            nrf_ble_client.interfaces.bluetooth.get_peer_connection_status(
                bt_dut_address
            )
        )
        assert connection_status
        nrf_ble_client.interfaces.bluetooth.set_peer_security_params(bt_dut_address)

        nrf_ble_client.interfaces.bluetooth.pair(bt_dut_address)
        security_level = (
            nrf_ble_client.interfaces.bluetooth.get_peer_connection_security_status(
                bt_dut_address
            )
        )
        assert security_level == 2
    finally:
        if connection_status:
            nrf_ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


@pytest.mark.test_src_map_id("SM54282")
def test_central_with_passcode_pairing(ble_client, nrf_ble_client):
    pass_key = 432156

    ble_client_address = nrf_ble_client.interfaces.bluetooth.get_ble_address()
    assert ble_client_address is not None

    bt_dut_address = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=ble_client_address, pin_code=pass_key, capability="KeyboardOnly"
    )
    assert bt_dut_address is not None
    time.sleep(1)

    scan_timeout = 30
    nrf_ble_client.interfaces.bluetooth.set_default_scan_params(
        timeout_seconds=scan_timeout
    )

    # Begin Scanning for BLE devices
    nrf_ble_client.interfaces.bluetooth.start_scanning()  # this is not async
    found_devices = nrf_ble_client.interfaces.bluetooth.get_devices()
    assert (
        str(bt_dut_address) in found_devices
        and found_devices[str(bt_dut_address)]
        == ble_client.interfaces.bluetooth.ble_advertising_data()
    )

    nrf_ble_client.interfaces.bluetooth.stop_scanning()

    # Discovery complete, go to a longer connection interval
    nrf_ble_client.interfaces.bluetooth.set_connection_parameters(100, 120, 6000)

    connection_status = False
    try:
        nrf_ble_client.interfaces.bluetooth.connect(bt_dut_address)
        time.sleep(2)
        connection_status = (
            nrf_ble_client.interfaces.bluetooth.get_peer_connection_status(
                bt_dut_address
            )
        )
        assert connection_status

        # nrf_ble_client.interfaces.bluetooth.register_peer_passkey_display(confirm=True) # this can be used with DisplayYesNo capability
        nrf_ble_client.interfaces.bluetooth.register_peer_passkey_entry(
            pass_key=pass_key
        )
        nrf_ble_client.interfaces.bluetooth.register_peer_on_security_level_changed()  # only for information

        # Making lesc_pairing false will change security to MITM (3)
        nrf_ble_client.interfaces.bluetooth.set_peer_security_params(
            bt_dut_address,
            passcode_pairing=True,
            io_capabilities=NRFBLEIoCapabilities.KEYBOARD_ONLY,
            lesc_pairing=True,
            long_term_bonding=True,
        )

        nrf_ble_client.interfaces.bluetooth.pair(bt_dut_address)

        security_level = (
            nrf_ble_client.interfaces.bluetooth.get_peer_connection_security_status(
                bt_dut_address
            )
        )
        assert security_level == 4  # LESC_MITM
    finally:
        if connection_status:
            nrf_ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


@pytest.mark.test_src_map_id("SM03839")
def test_peripheral_without_passcode_pairing( ble_client, nrf_ble_client):
    nrf_ble_client.interfaces.bluetooth.set_security_params()

    # Start ble client
    ble_client_address = nrf_ble_client.interfaces.bluetooth.start_advertising(
        timeout_sec=0, auto_restart=True
    )
    assert ble_client_address is not None

    bt_dut_address = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=ble_client_address
    )
    assert bt_dut_address is not None

    time.sleep(1)

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if (
            ble_client_address in found_devices
            and found_devices[ble_client_address]
            == nrf_ble_client.interfaces.bluetooth.ble_advertising_data
        ):
            device_found = True
            break

    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found

    connected = False
    try:
        connected = ble_client.interfaces.bluetooth.pair_and_connect(ble_client_address)
        time.sleep(1)
        assert connected

        assert nrf_ble_client.interfaces.bluetooth.get_connection_status(bt_dut_address)

        security_level = (
            nrf_ble_client.interfaces.bluetooth.get_connection_security_status(
                bt_dut_address
            )
        )
        assert security_level == 2
    finally:
        if connected:
            ble_client.interfaces.bluetooth.disconnect(ble_client_address)


@pytest.mark.test_src_map_id("SM54975")
def test_peripheral_with_passcode_pairing(ble_client, nrf_ble_client):
    pass_key = 432561
    nrf_ble_client.interfaces.bluetooth.set_security_params(
        passcode_pairing=True,
        io_capabilities=NRFBLEIoCapabilities.KEYBOARD_ONLY,
        long_term_bonding=True,
        lesc_pairing=True,
    )

    # nrf_ble_client.interfaces.bluetooth.register_passkey_display(confirm=True) # this can be used with DisplayYesNo capability
    nrf_ble_client.interfaces.bluetooth.register_passkey_entry(pass_key=pass_key)
    nrf_ble_client.interfaces.bluetooth.register_on_connect()
    nrf_ble_client.interfaces.bluetooth.register_on_disconnect()
    nrf_ble_client.interfaces.bluetooth.register_on_security_level_changed()
    nrf_ble_client.interfaces.bluetooth.register_on_client_pairing_complete()

    # Start ble client
    ble_client_address = nrf_ble_client.interfaces.bluetooth.start_advertising(
        timeout_sec=0, auto_restart=True
    )
    assert ble_client_address is not None

    bt_dut_address = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=ble_client_address, capability="KeyboardOnly", pin_code=pass_key
    )
    assert bt_dut_address is not None

    time.sleep(1)

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if (
            ble_client_address in found_devices
            and found_devices[ble_client_address]
            == nrf_ble_client.interfaces.bluetooth.ble_advertising_data
        ):
            device_found = True
            break

    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found

    connected = False
    try:
        connected = ble_client.interfaces.bluetooth.pair_and_connect(ble_client_address)
        time.sleep(1)
        assert connected

        assert nrf_ble_client.interfaces.bluetooth.get_connection_status(bt_dut_address)

        security_level = (
            nrf_ble_client.interfaces.bluetooth.get_connection_security_status(
                bt_dut_address
            )
        )
        assert security_level == 4
    finally:
        if connected:
            ble_client.interfaces.bluetooth.disconnect(ble_client_address)

@pytest.mark.test_src_map_id('TC8552918573')
def test_nrf_ble_client_adv_with_displayonly_and_ble_client_scan_connect_with_keyboardonly(ble_client, nrf_ble_client):
    nrf_ble_client.interfaces.bluetooth.set_security_params(passcode_pairing=True,
                                                            io_capabilities=NRFBLEIoCapabilities.DISPLAY_ONLY,
                                                            long_term_bonding=True, lesc_pairing=True)

    nrf_ble_client.interfaces.bluetooth.register_on_connect()
    nrf_ble_client.interfaces.bluetooth.register_on_disconnect()
    nrf_ble_client.interfaces.bluetooth.register_on_client_pairing_complete()
    nrf_ble_client.interfaces.bluetooth.register_passkey_display()

    # Start ble client
    ble_client_address = nrf_ble_client.interfaces.bluetooth.start_advertising(
        timeout_sec=0, auto_restart=True
    )
    assert ble_client_address is not None

    bt_dut_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_client_address,
                                                                    capability="KeyboardOnly", pin_code=-8)
    assert bt_dut_address is not None

    time.sleep(1)

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if (
                ble_client_address in found_devices
                and found_devices[ble_client_address]
                == nrf_ble_client.interfaces.bluetooth.get_ble_advertising_data()
        ):
            device_found = True
            break

    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found

    connected = False
    try:
        def connect():
            time.sleep(1)
            connected = ble_client.interfaces.bluetooth.pair_and_connect(ble_client_address)
            
        time.sleep(3)  # Give it time to connect

        # Create and start the connect thread
        connect_thread = threading.Thread(target=connect)
        connect_thread.start()
        time.sleep(10)

        ble_client.interfaces.bluetooth.set_pin(nrf_ble_client.interfaces.bluetooth.get_passkey())
        time.sleep(10)
        assert nrf_ble_client.interfaces.bluetooth.get_connection_status(bt_dut_address)

        security_level = nrf_ble_client.interfaces.bluetooth.get_connection_security_status(bt_dut_address)
        assert security_level == 4
    finally:
        if connected:
            ble_client.interfaces.bluetooth.disconnect(ble_client_address)


@pytest.mark.test_src_map_id('TC4551785578')
def test_nrf_ble_client_adv_with_keyboardonly_and_ble_client_scan_connect_with_displayonly(ble_client, nrf_ble_client):
    nrf_ble_client.interfaces.bluetooth.set_security_params(passcode_pairing=True,
                                                            io_capabilities=NRFBLEIoCapabilities.KEYBOARD_ONLY,
                                                            long_term_bonding=True, lesc_pairing=True)

    nrf_ble_client.interfaces.bluetooth.register_on_connect()
    nrf_ble_client.interfaces.bluetooth.register_on_disconnect()
    nrf_ble_client.interfaces.bluetooth.register_on_client_pairing_complete()
    nrf_ble_client.interfaces.bluetooth.register_passkey_display()
    # nrf_ble_client.interfaces.bluetooth.register_dynamic_passkey_entry()

    # Start ble client
    ble_client_address = nrf_ble_client.interfaces.bluetooth.start_advertising(
        timeout_sec=0, auto_restart=True
    )
    assert ble_client_address is not None

    bt_dut_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_client_address,
                                                                    capability="DisplayOnly", pin_code=-8)
    assert bt_dut_address is not None

    time.sleep(1)

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if (
                ble_client_address in found_devices
                and found_devices[ble_client_address]
                == nrf_ble_client.interfaces.bluetooth.ble_advertising_data
        ):
            device_found = True
            break

    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found

    connected = False
    try:
        def connect():
            time.sleep(1)
            connected = ble_client.interfaces.bluetooth.pair_and_connect(ble_client_address)
            
        time.sleep(3)  # Give it time to connect

        # Create and start the connect thread
        connect_thread = threading.Thread(target=connect)
        connect_thread.start()
        time.sleep(10)

        nrf_ble_client.interfaces.bluetooth.set_passkey(ble_client.interfaces.bluetooth.get_passkey())
        time.sleep(20)
        assert nrf_ble_client.interfaces.bluetooth.get_connection_status(bt_dut_address)

        security_level = nrf_ble_client.interfaces.bluetooth.get_connection_security_status(bt_dut_address)
        assert security_level == 4
    finally:
        if connected:
            ble_client.interfaces.bluetooth.disconnect(ble_client_address)



@pytest.mark.test_src_map_id('TC6749978584')
def test_nrf_custom_service_and_characteristic_addition(
    ble_client, nrf_ble_client, logger
):
    custom_service = nrf_ble_client.interfaces.bluetooth.add_custom_service(uuid=0x1AA1)
    logger.info(custom_service)
    characteristic_properties = {
        "read": True,  # Set to True if you want this characteristic to be readable
        "write": False,  # Set to True if you want this characteristic to be writable
    }

    initial_value = b"initial_value"
    # Add the characteristic
    custom_characteristic = (
        nrf_ble_client.interfaces.bluetooth.add_custom_characteristic(
            uuid=0x1BB1,
            service=custom_service,
            properties=characteristic_properties,
            initial_value=initial_value,
        )
    )
    logger.info(custom_characteristic)
    descriptor_properties = {
        "read": True,  # Mark the descriptor as readable
        "write": False,  # Mark it as not writable (can be True if you need it)
    }

    # Initial value of the descriptor
    descriptor_initial_value = b"Characteristic Descriptor"

    # Add the custom descriptor
    desc = nrf_ble_client.interfaces.bluetooth.add_custom_descriptor(
        uuid=0x1BB1,  # UUID of the descriptor
        characteristic=custom_characteristic,  # The characteristic to add the descriptor to
        properties=descriptor_properties,  # The properties passed as a dictionary
        initial_value=descriptor_initial_value,  # Initial value of the descriptor
    )
    logger.info(desc)
    ble_client_address = nrf_ble_client.interfaces.bluetooth.get_ble_address()
    assert ble_client_address is not None

    bt_dut_address = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=ble_client_address
    )
    assert bt_dut_address is not None
    time.sleep(1)

    scan_timeout = 30
    nrf_ble_client.interfaces.bluetooth.set_default_scan_params(
        timeout_seconds=scan_timeout
    )

    # Begin Scanning for BLE devices
    nrf_ble_client.interfaces.bluetooth.start_scanning()  # this is not async
    found_devices = nrf_ble_client.interfaces.bluetooth.get_devices()
    assert (
        str(bt_dut_address) in found_devices
        and found_devices[str(bt_dut_address)]
        == ble_client.interfaces.bluetooth.get_ble_advertising_data()
    )

    nrf_ble_client.interfaces.bluetooth.stop_scanning()

    # Discovery complete, go to a longer connection interval
    nrf_ble_client.interfaces.bluetooth.set_connection_parameters(100, 120, 6000)
    connection_status = False
    try:
        nrf_ble_client.interfaces.bluetooth.connect(bt_dut_address)
        time.sleep(2)
        connection_status = (
            nrf_ble_client.interfaces.bluetooth.get_peer_connection_status(
                bt_dut_address
            )
        )
        assert connection_status
        (
            servs,
            chars,
        ) = (
            ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        )
        time.sleep(5)
        logger.info(f"{servs} {chars}")
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"
        service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
        (
            char_path,
            char_props,
        ) = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs, service_uid=service_uid, char_uid=char_uid
        )
        time.sleep(5)
        logger.info(f"{char_props}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
    finally:
        if connection_status:
            nrf_ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
