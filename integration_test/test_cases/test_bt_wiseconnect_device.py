import time

import pytest

from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf_wiseconnect.devices.rs911x import RS9116CoexMode
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.ble_client("bt_wiseconnect")
def test_ble_phy_wiseconnect_dut(ble_client, wifi_dut, logger):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    # Join Wi-Fi Access Point
    # wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

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

    with BleLogs(start_collecting_logs=True, bt_log_path=f"./reports/test_ble_scanning_phy_{int(time.time())}.log") as ble_logs:
        rc, result = ble_client.interfaces.bluetooth.hci_tool_manager.read_phy(bt_dut_address)
        logger.info(result)
        ble_client.interfaces.bluetooth.hci_tool_manager.set_phy(bt_dut_address, "0x00 0x02 0x02 0x01")
        rc, result = ble_client.interfaces.bluetooth.hci_tool_manager.read_phy(bt_dut_address)
        logger.info(result)
        time.sleep(2)

    # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)





