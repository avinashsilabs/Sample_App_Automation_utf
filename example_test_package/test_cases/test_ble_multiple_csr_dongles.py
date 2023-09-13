import time
import pytest
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import (
    BatteryLevelCharacteristic,
)
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import (
    BatteryService,
)
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116AsyncEventType
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap
from utf_wiseconnect.devices.rs911x import (
    RS9116PowerSaveModes,
    RS9116PowerSaveProcedureTypes,
)
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands


def logger():
    return get_logger(__name__)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
#@pytest.mark.config("ble_clients[0]", bluetooth={"adapter_name": "hci1"})
#@pytest.mark.config("ble_clients[1]", bluetooth={"adapter_name": "hci2"})
def test_ble_advertisement_with_multiple_csr_dongle(wifi_dut, ble_clients):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    # Join Wi-Fi Access Point
    #wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None
    
    #wifi_dut.interfaces.wifi.ble_start_advertising()
    for i in range(0,2):
        logger().info(f"---------- Iteration No ----{i}")
        # Set up DUT for BLE advertising
        wifi_dut.interfaces.wifi.ble_start_advertising()
        
        # Begin Scanning for BLE devices
        if i==0:
            bt_client_address = ble_clients[i].interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address
        )
        else:
            bt_client_address = ble_clients[i].interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address, restart_bt_service = False, register_agent = False
        )
        assert bt_client_address is not None

        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            found_devices = ble_clients[i].interfaces.bluetooth.get_devices()
            if (
                bt_dut_address in found_devices
                and found_devices[bt_dut_address]
                == wifi_dut.interfaces.wifi.ble_advertising_data
            ):
                device_found = True
                break

        ble_clients[i].interfaces.bluetooth.stop_scanning()
        assert device_found

        #     # Not legal to start advertising if we're already advertising...
        #     with pytest.raises(WlanError) as exc_info:
        #         wifi_dut.interfaces.wifi.ble_start_advertising()
        #     assert exc_info.value.error_code == 0x4E0C  # "command disallowed"
    
        ble_clients[i].interfaces.bluetooth.connect(bt_dut_address)
        time.sleep(1)

        # Get the state of the dut
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected

        time.sleep(5)
        ble_clients[i].interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(5)
        
    # # Connecting will automatically stop advertising
    # with pytest.raises(WlanError) as exc_info:
    #     wifi_dut.interfaces.wifi.ble_stop_advertising()
    # assert exc_info.value.error_code == 0x4E0C  # "command disallowed"
    # for j in range(0,2):
    #     ble_clients[j].interfaces.bluetooth.disconnect(bt_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_scanning_with_multiple_csr_dongle(wifi_dut, wifi_access_point, ble_clients):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    # Join Wi-Fi Access Point
    #wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None

    for i in range(0,2):
        # Start ble client advertesing
        if i==0:
            bt_client_address = ble_clients[i].interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address, index = i
            )
            assert bt_client_address is not None
        else:
            bt_client_address = ble_clients[i].interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address, restart_bt_service = False, register_agent = False, index = i
            )
            assert bt_client_address is not None

        time.sleep(1)

        # Start scanning and connect to ble client
        wifi_dut.interfaces.wifi.ble_start_scanning(
            ble_client_address=bt_client_address, timeout=30
        )
        
        time.sleep(1)
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
        
        # Start ble client advertesing
        #ble_clients[i].interfaces.bluetooth.stop_advertising()