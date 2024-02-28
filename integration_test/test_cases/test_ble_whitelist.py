import time

import pytest

from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1
        | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
        | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE
        | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES
        | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.test_src_map_id("SM27706")
def test_sdk_ble_whitelist(wifi_dut, ble_client):
    with ble_client.interfaces.bluetooth.ble_logs(
        start_collecting_logs=True,
        bt_log_path=f"/tmp/test_sdk_ble_whitelist{int(time.time())}.log",
    ) as _:
        ble_white_list_address = None
        try:
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start(
                capability=0, set_smp=0
            )

            device_name = "AAA_DEVICE_NAME"
            wifi_dut.interfaces.wifi.bt_set_local_name(device_name)
            returned_name = wifi_dut.interfaces.wifi.bt_get_local_name()
            assert device_name == returned_name

            ble_white_list_address = ble_client.interfaces.bluetooth.get_ble_address()

            scan_response_data = "BBB_SCAN_RESPONSE"
            wifi_dut.interfaces.wifi.ble_set_scan_response_data(
                scan_response_data=scan_response_data
            )

            wifi_dut.interfaces.wifi.ble_add_white_list(ble_white_list_address)

            ble_advertising_data = "CCC_ADV_DATA"
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_filter_type=1, ble_advertising_data=ble_advertising_data)

            hci_scan_params = "0x01 0x10 0x00 0x10 0x00 0x00 0x00"
            ble_client.interfaces.bluetooth.set_scan_params(
                hci_scan_params=hci_scan_params
            )
            devices = ble_client.interfaces.bluetooth.start_scanning_with_hci(timeout=10)
            ble_client.interfaces.bluetooth.stop_scanning_with_hci()

            assert ble_dut_address in devices, "Device not found"
            target_device = devices[ble_dut_address]
            assert "Name" in target_device, "Name not resolved in advertising report"
            assert target_device["Name"] != ble_advertising_data, "Found Advertising data instead of Scan response data"
            assert target_device["Name"] == scan_response_data, "Scan response data is not found"

            ble_client.interfaces.bluetooth.hci_tool_manager.create_connection(ble_dut_address)

            time.sleep(5)

            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected

        finally:
            wifi_dut.interfaces.wifi.ble_disconnect(
                ble_remote_dev_address=ble_white_list_address
            )
            wifi_dut.interfaces.wifi.ble_clear_white_list()
            ble_client.interfaces.bluetooth.close()
        time.sleep(5)
