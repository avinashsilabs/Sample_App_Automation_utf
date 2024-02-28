import time

import pytest

from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_interface import BLEPermissions
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertService, \
    ImmediateAlertLevelCharacteristic
from utf.interfaces.bluetooth.bluez.gatt_application.link_loss_service import (
    LinkLossService,
    LinkLossAlertLevelCharacteristic,
)
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116CoexMode
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        },
    ),
    pytest.mark.end_state("wifi_dut", wifi=["disassociated", "ble_disconnect"]),
]


@pytest.mark.firmware_app("test_multi_gatt_conn")
@pytest.mark.test_src_map_id('SM11803')
def test_ble_immediate_alert_dut_scanning(
    firmware_loader, wifi_dut, wifi_access_point, ble_client, logger
):
    with ble_client.interfaces.bluetooth.ble_logs(
        start_collecting_logs=True,
        bt_log_path=f"reports/ble_logs{int(time.time())}.log",
    ):
        # # Join Wi-Fi Access Point
        # wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # Start DUT
        bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
        assert bt_dut_address is not None

        # bt_dut_address = "24:4B:FE:0E:E1:81"

        # Start ble client
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address, service_classes=["ImmediateAlertService"]
        )
        assert bt_client_address is not None

        # Start scanning and connect to ble client
        wifi_dut.interfaces.wifi.ble_start_scanning(
            ble_client_address=bt_client_address, timeout=60
        )
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
        timeout = 120
        logger.info(f"Initiating connection this can take upto {timeout} seconds....")
        wifi_dut.interfaces.wifi.ble_connect(
            ble_remote_dev_address=bt_client_address,
            timeout=timeout,
            expected="RSI_BLE_SECURITY_KEYS_EVENT",
        )

        # Get the state of the dut
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected

        # get all profiles
        uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(
            ble_remote_dev_address=bt_client_address
        )
        assert ImmediateAlertService.UUID in uuids

        # resolve profile
        start_handle, end_handle = wifi_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address, uuid=int(ImmediateAlertService.UUID, 16)
        )
        assert start_handle is not None
        assert end_handle is not None

        # resolve characteristics of profile
        (
            uuids,
            write_handles,
            char_properties,
        ) = wifi_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=bt_client_address,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
        )
        assert ImmediateAlertLevelCharacteristic.LLA_UUID in uuids
        index = uuids.index(ImmediateAlertLevelCharacteristic.LLA_UUID)

        logger.info(f"index : {index}")

        assert char_properties[index].isdigit()
        assert ImmediateAlertLevelCharacteristic.prop_int == int(char_properties[index])

        write_handle = int(write_handles[index], 16)
        assert write_handle > 0

        logger.info(f"write_handle : {write_handle}")

        # read value
        default_alert_level = wifi_dut.interfaces.wifi.ble_get_att_value_async(
            ble_remote_dev_address=bt_client_address, char_property=write_handle
        )
        assert int(default_alert_level) == ImmediateAlertLevelCharacteristic.DEFAULT_ALERT

        # Read rssi of remote device
        rssi = wifi_dut.interfaces.wifi.bt_get_rssi(bt_remote_dev_address=bt_client_address)
        assert -120 < rssi < 0

        # Since we can not impact the rssi value without using attenuator, in automation, we are changing the alert
        # level no matter what the rssi value is write value
        new_alert_level = 1
        wifi_dut.interfaces.wifi.ble_set_att_cmd(
            ble_remote_dev_address=bt_client_address,
            char_property=write_handle,
            value=new_alert_level,
            expected="RSI_BLE_MORE_DATA_REQ_EVT"
        )
        time.sleep(10)

        # read value
        current_alert_level = wifi_dut.interfaces.wifi.ble_get_att_value_async(
            ble_remote_dev_address=bt_client_address, char_property=write_handle
        )
        assert int(current_alert_level) == new_alert_level

        # Read rssi of remote device
        rssi = wifi_dut.interfaces.wifi.bt_get_rssi(bt_remote_dev_address=bt_client_address)
        assert -120 < rssi < 0

        # Since we can not impact the rssi value without using attenuator, in automation, we are changing the alert
        # level no matter what the rssi value is write value
        # write value
        new_alert_level = 2
        wifi_dut.interfaces.wifi.ble_set_att_cmd(
            ble_remote_dev_address=bt_client_address,
            char_property=write_handle,
            value=new_alert_level,
            expected="RSI_BLE_MORE_DATA_REQ_EVT"
        )
        time.sleep(10)

        # read value
        current_alert_level = wifi_dut.interfaces.wifi.ble_get_att_value_async(
            ble_remote_dev_address=bt_client_address, char_property=write_handle
        )
        assert int(current_alert_level) == new_alert_level

        # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)