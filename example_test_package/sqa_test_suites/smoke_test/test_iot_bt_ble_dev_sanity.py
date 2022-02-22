import time
import pytest
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from interfaces.bluetooth import BTSocketRole
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from interfaces.bluetooth import BLEDeviceState
from utils.logger import get_logger
from interfaces.wifi import WlanError
from interfaces.bluetooth import BLEConnectError
from utils.time_measurer import TimeMeasurer


def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Initiates the DUT in master Spp mode for the capability
        3. Initiates the client in slave spp with capabilty enables
        4. Opnes Bt socket and connects to the remote client.
        5. Verifies ping after the connection.

    Author: RaviNemali
"""

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        }
    )
]


def test_BT_classic_slave_role_with_powersave(wifi_dut, wifi_access_point, bt_client):
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        logger().info("******* Join Wi-Fi Access Point *******")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None

        with bt_client.interfaces.bluetooth.bt_socket(
                mode=BTSocketRole.Server
        ) as bt_server_socket:
            # SPP Connection
            logger().info("******* SPP Connection *******")
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                assert connected
                if not connected:
                    logger().info('********** Connection Failed ***********')
            # Initiating power save
            logger().info("******* Initiating power save *******")
            if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
                wifi_dut.interfaces.wifi.set_sleep_gpio(True)
                wifi_dut.interfaces.wifi.power_save(
                    power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
                )
                wifi_dut.interfaces.wifi.bt_power_save(
                    power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
                )

            # Ping dut
            logger().info("******* Ping dut *******")
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                dest_addr=bt_dut_address
            )

            # Close connection
            logger().info("******* Close connection *******")
            bt_server_socket.close()


def test_BT_classic_master_role_with_powersave(wifi_dut, wifi_access_point, bt_client):
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        logger().info("******* Join Wi-Fi Access Point *******")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address is not None
        time.sleep(0.5)

        with bt_client.interfaces.bluetooth.bt_socket(
                mode=BTSocketRole.Client
        ) as bt_client_socket:
            # SPP Connection
            logger().info("******* SPP Connection *******")
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=12)
                assert addr == bt_dut_address

            # Initiating power save
            logger().info("******* Initiating power save *******")
            if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
                wifi_dut.interfaces.wifi.set_sleep_gpio(True)
                wifi_dut.interfaces.wifi.power_save(
                    power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
                )
                wifi_dut.interfaces.wifi.bt_power_save(
                    power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
                )
            # Ping dut
            logger().info("******* Ping dut *******")
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                dest_addr=bt_dut_address
            )

            # Close connection
            logger().info("******* Close connection *******")
            bt_client_socket.close()
            time.sleep(
                0.2
            )  # to overcome Unexpected response from 'at+rsibt_unbond=B8-27-EB-8E-A9-99': b'AT+RSIBT_SPPDISCONNECTED B8-27-EB-8E-A9-99\r\n\r\nOK'
            wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_gatt_BLE_connection_stability(wifi_dut, wifi_access_point, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )
        # Join Wi-Fi Access Point
        logger().info("******* Join Wi-Fi Access Point *******")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # Start DUT
        logger().info("******* Start DUT *******")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None

        # Start ble client
        logger().info("******* Start ble client *******")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None

        time.sleep(1)

        # Start scanning and connect to ble client
        logger().info("******* Start scanning and connect to ble client *******")
        wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
        # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
        logger().info(
            "Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?")
        timeout = 120
        logger().info(f"Initiating connection this can take upto {timeout} seconds....")
        wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

        # Get the state of the dut
        logger().info("******* Get the state of the dut *******")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected

        # Disconnect
        logger().info("******* Connection Disconnected *******")
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)


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
    logger().info("******* Join Wi-Fi Access Point *******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Start DUT
    logger().info("******* Start DUT *******")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None

    # Set up BLE Server on DUT
    logger().info("******* Set up BLE Server on DUT *******")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None
    wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
    wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
    wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)

    # Start ble client
    logger().info("******* Start ble client *******")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None

    time.sleep(1)

    # Start scanning and connect to ble client
    logger().info("******* Start scanning and connect to ble client *******")
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=20)
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    logger().info("******* Get the state of the dut *******")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # Start advertising
    logger().info("******* Start advertising *******")
    # characteristics are not visible until advertised
    logger().info("Characteristics are not visible until advertised")
    wifi_dut.interfaces.wifi.ble_start_advertising()
    time.sleep(0.5)

    # resolving characteristic
    logger().info("******* Resolving characteristic *******")
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
    logger().info("read value - Notifications not enabled")
    result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
    assert result == data1

    # subscribe to notifications
    logger().info("******* Subscribe to notifications *******")
    ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
    ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char, char_uid=char_uid)
    time.sleep(0.5)

    # notify only
    logger().info("******* notify only *******")
    wifi_dut.interfaces.wifi.ble_notify_value()

    # write/read new value - Notifications enabled
    logger().info("write/read new value - Notifications enabled")
    ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(characteristic=char, data=data2)
    time.sleep(0.1)
    result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
    assert result == data2

    # write value - Notifications enabled
    logger().info("write value - Notifications enabled")
    ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(characteristic=char, data=data3)

    # auto notify
    logger().info("******* auto notify *******")
    ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char, char_uid=char_uid)
    wifi_dut.interfaces.wifi.ble_start_notify_value(interval_ms=500, count=2)
    time.sleep(1)

    # subscribe to notifications
    logger().info("******* subscribe to notifications *******")
    ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(characteristic=char)
    ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
    time.sleep(0.5)

    # notify only - disabled notifications - should raise exception
    logger().info("notify only - disabled notifications - should raise exception")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.ble_notify_value()
    assert exc_info.value.error_code == 0x21

    # assert received notifications
    logger().info("******* assert received notifications *******")
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
    logger().info("******* Disconnect *******")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
