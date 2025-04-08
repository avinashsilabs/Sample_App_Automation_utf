import pytest
import time
import os
import re
from utf_wiseconnect_3.tests.devices.si91x import (Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap, \
    Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes)
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.logger import get_logger


ping_count = 10

def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(917-SDK)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Teledyne sniffer (to capture BLE OTA logs)

    Author: Vishakha
"""


def ble_anchorpoints(ble_sniffer=None, wifi_dut=None, ble_client=None, timesleep=None, capture_file=None,
                     set_local_name=None, Connection_Handle=None, Connection_Interval_Min=None,
                     Connection_Interval_Max=None, Max_Latency=None, Supervision_Timeout=None, Min_CE_Length=None,
                     Max_CE_Length=None):
    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture(capture_file)
    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status, "Set local name and get local name not matched "

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info("enabling the power save modes ")
    wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
    wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                  psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
    logger().info(f"Begin Scanning for BLE devices")
    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address, f"Unable to get BLE client address"
    time.sleep(1)
    logger().info(f"Stop Scanning for BLE devices")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(5)
    # Mapping Master and Slave Address for Adding devices for sniffer
    ble_dut_address_hex = re.split(":", ble_dut_address)
    ble_client_address_hex = re.split(":", ble_client_address)
    master_address = "0x"
    for hex_data_part in ble_dut_address_hex:
        master_address = master_address + hex_data_part
    slave_address = "0x"
    for hex_data_part in ble_client_address_hex:
        slave_address = slave_address + hex_data_part
    ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])

    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/{capture_file}.log_{int(time.time())}"):
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_conn(dev_addr=ble_dut_address,
                                                                         connection_handle=Connection_Handle,
                                                                         connection_interval_min=Connection_Interval_Min,
                                                                         connection_interval_max=Connection_Interval_Max,
                                                                         max_latency=Max_Latency,
                                                                         supervision_timeout=Supervision_Timeout,
                                                                         min_ce_length=Min_CE_Length,
                                                                         max_ce_length=Max_CE_Length
                                                                         )
    logger().info(f"Checking BLE connection stability for {timesleep}sec")
    time.sleep(timesleep)
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE disconnect successful")
    ble_sniffer.interfaces.sniffer.stop_capture()
    logger().info("Sniffer stop successful")
    captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')

    time.sleep(30)
    exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "LE DATA")
    for captured_file in captured_files:
        captured_file = captured_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(captured_file)
        assert file_size > 0

    exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
    file_size = os.path.getsize(exported_csv_file)
    assert file_size > 0
    sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
    assert sniffer_data_df is not None


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                        Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                                   Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                               Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        },
    )
]


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19889(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=1200,
                         capture_file='ble_anchorpoints_sdk_C19889', set_local_name="BLETEST19889",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x06 0x00",
                         Connection_Interval_Max="0x06 0x00",
                         Max_Latency="0x05 0x00",
                         Supervision_Timeout="0x90 0x01",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19890(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=1200,
                         capture_file='ble_anchorpoints_sdk_C19890', set_local_name="BLETEST19890",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x0C 0x00",
                         Connection_Interval_Max="0x0C 0x00",
                         Max_Latency="0x05 0x00",
                         Supervision_Timeout="0x90 0x01",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19891(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=1200,
                         capture_file='ble_anchorpoints_sdk_C19891', set_local_name="BLETEST19891",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x18 0x00",
                         Connection_Interval_Max="0x18 0x00",
                         Max_Latency="0x05 0x00",
                         Supervision_Timeout="0x90 0x01",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19892(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=1200,
                         capture_file='ble_anchorpoints_sdk_C19892', set_local_name="BLETEST19892",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x30 0x00",
                         Connection_Interval_Max="0x30 0x00",
                         Max_Latency="0x05 0x00",
                         Supervision_Timeout="0x90 0x01",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19893(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=1200,
                         capture_file='ble_anchorpoints_sdk_C19893', set_local_name="BLETEST19893",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x60 0x00",
                         Connection_Interval_Max="0x60 0x00",
                         Max_Latency="0x05 0x00",
                         Supervision_Timeout="0x90 0x01",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19894(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=1200,
                         capture_file='ble_anchorpoints_sdk_C19894', set_local_name="BLETEST19894",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0xC0 0x00",
                         Connection_Interval_Max="0xC0 0x00",
                         Max_Latency="0x05 0x00",
                         Supervision_Timeout="0x90 0x01",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19895(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=1200,
                         capture_file='ble_anchorpoints_sdk_C19895', set_local_name="BLETEST19895",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x80 0x01",
                         Connection_Interval_Max="0x80 0x01",
                         Max_Latency="0x05 0x00",
                         Supervision_Timeout="0x80 0x02",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip() # SI91X-17408
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19896(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=1200,
                         capture_file='ble_anchorpoints_sdk_C19896', set_local_name="BLETEST19896",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x00 0x03",
                         Connection_Interval_Max="0x00 0x03",
                         Max_Latency="0x05 0x00",
                         Supervision_Timeout="0x00 0x05",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip() # SI91X-17408
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19897(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=1200,
                         capture_file='ble_anchorpoints_sdk_C19897', set_local_name="BLETEST19897",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x00 0x06",
                         Connection_Interval_Max="0x00 0x06",
                         Max_Latency="0x05 0x00",
                         Supervision_Timeout="0x00 0x0A",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip() # SI91X-17408
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19898(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=1200,
                         capture_file='ble_anchorpoints_sdk_C19898', set_local_name="BLETEST19898",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x00 0x0C",
                         Connection_Interval_Max="0x00 0x0C",
                         Max_Latency="0x02 0x00",
                         Supervision_Timeout="0x80 0x0C",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip() # SI91X-17408
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19899(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=1200,
                         capture_file='ble_anchorpoints_sdk_C19899', set_local_name="BLETEST19899",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x80 0x0C",
                         Connection_Interval_Max="0x80 0x0C",
                         Max_Latency="0x02 0x00",
                         Supervision_Timeout="0x80 0x0C",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19900(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=300,
                         capture_file='ble_anchorpoints_sdk_C19900', set_local_name="BLETEST19900",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x06 0x00",
                         Connection_Interval_Max="0x06 0x00",
                         Max_Latency="0x00 0x00",
                         Supervision_Timeout="0x90 0x01",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19901(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=300,
                         capture_file='ble_anchorpoints_sdk_C19901', set_local_name="BLETEST19901",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x0C 0x00",
                         Connection_Interval_Max="0x0C 0x00",
                         Max_Latency="0x00 0x00",
                         Supervision_Timeout="0x90 0x01",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19902(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=300,
                         capture_file='ble_anchorpoints_sdk_C19902', set_local_name="BLETEST19902",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x18 0x00",
                         Connection_Interval_Max="0x18 0x00",
                         Max_Latency="0x00 0x00",
                         Supervision_Timeout="0x90 0x01",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19903(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=300,
                         capture_file='ble_anchorpoints_sdk_C19903', set_local_name="BLETEST19903",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x30 0x00",
                         Connection_Interval_Max="0x30 0x00",
                         Max_Latency="0x00 0x00",
                         Supervision_Timeout="0x90 0x01",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19904(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=300,
                         capture_file='ble_anchorpoints_sdk_C19904', set_local_name="BLETEST19904",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x60 0x00",
                         Connection_Interval_Max="0x60 0x00",
                         Max_Latency="0x00 0x00",
                         Supervision_Timeout="0x90 0x01",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19905(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=300,
                         capture_file='ble_anchorpoints_sdk_C19905', set_local_name="BLETEST19905",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0xC0 0x00",
                         Connection_Interval_Max="0xC0 0x00",
                         Max_Latency="0x00 0x00",
                         Supervision_Timeout="0x90 0x01",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19906(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=300,
                         capture_file='ble_anchorpoints_sdk_C19906', set_local_name="BLETEST19906",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x80 0x01",
                         Connection_Interval_Max="0x80 0x01",
                         Max_Latency="0x00 0x00",
                         Supervision_Timeout="0x80 0x02",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip() # SI91X-17408
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19907(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=300,
                         capture_file='ble_anchorpoints_sdk_C19907', set_local_name="BLETEST19907",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x00 0x03",
                         Connection_Interval_Max="0x00 0x03",
                         Max_Latency="0x00 0x00",
                         Supervision_Timeout="0x00 0x05",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip() # SI91X-17408
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19908(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=300,
                         capture_file='ble_anchorpoints_sdk_C19908', set_local_name="BLETEST19908",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x00 0x06",
                         Connection_Interval_Max="0x00 0x06",
                         Max_Latency="0x00 0x00",
                         Supervision_Timeout="0x00 0x0A",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip() # SI91X-17408
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19909(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=300,
                         capture_file='ble_anchorpoints_sdk_C19909', set_local_name="BLETEST19909",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x00 0x0C",
                         Connection_Interval_Max="0x00 0x0C",
                         Max_Latency="0x00 0x00",
                         Supervision_Timeout="0x80 0x0C",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip() # SI91X-17408
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C19910(wifi_dut, ble_client, ble_sniffer, sl_collections):
    try:
        ble_anchorpoints(ble_sniffer, wifi_dut, ble_client, timesleep=300,
                         capture_file='ble_anchorpoints_sdk_C19910', set_local_name="BLETEST19910",
                         Connection_Handle="0x61 0x00",
                         Connection_Interval_Min="0x80 0x0C",
                         Connection_Interval_Max="0x80 0x0C",
                         Max_Latency="0x00 0x00",
                         Supervision_Timeout="0x80 0x0C",
                         Min_CE_Length="0x00 0x00",
                         Max_CE_Length="0x00 0x00",
                         )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip()
@pytest.mark.config(
    "remote_wiseconnect3",
    sapi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.NWP120MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}, "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C537343(wifi_dut, remote_wiseconnect3, ble_sniffer, sl_collections):
    try:
        log_file_name = 'ble_anchorpoints_sdk_C537343'
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file=log_file_name)
        set_local_name = "BLETEST537343"
        logger().info(f"Setting BLE local name {set_local_name}")
        wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
        status = wifi_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f"getting the local name : {status}")
        assert set_local_name == status, "Set local name and get local name not matched "

        logger().info(f"Set up DUT for BLE advertising")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
        logger().info(f"Set up DUT for BLE advertising")
        ble_client_address = remote_wiseconnect3.interfaces.sapi.ble_start()
        assert ble_dut_address, f"Unable to find ble dut address"
        wifi_dut.interfaces.wifi.ble_start_advertising()

        logger().info("enabling the power save modes ")
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        logger().info(f"Begin Scanning for BLE devices")
        remote_wiseconnect3.interfaces.sapi.ble_start_scanning(ble_client_address=ble_dut_address)
        time.sleep(20)

        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex = re.split(":", ble_client_address)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address = "0x"
        for hex_data_part in ble_client_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])

        logger().info(f"Initiating ble connection with connection parameters")
        remote_wiseconnect3.interfaces.sapi.ble_connect(ble_remote_dev_address=ble_dut_address,
                                                        ble_conn_interval_min=6,
                                                        ble_conn_interval_max=6,
                                                        ble_supervision_timeout=400,
                                                        timeout=120)
        logger().info("Checking BLE connection stability for 300sec")
        time.sleep(300)
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
        logger().info("DUT is not disconnected from BLE")

        logger().info("Device Disconnection")
        wifi_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=ble_client_address)
        remote_wiseconnect3.interfaces.sapi.ble_disconnect(ble_remote_dev_address=ble_dut_address)
        logger().info("BLE disconnect successful")

        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "LE DATA")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        assert sniffer_data_df is not None

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip()
@pytest.mark.config(
    "remote_wiseconnect3",
    sapi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.NWP120MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}, "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_advertising", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_slave_latency_C537344(wifi_dut, remote_wiseconnect3, ble_sniffer, sl_collections):
    try:
        log_file_name = 'ble_anchorpoints_sdk_C537344'
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file=log_file_name)
        set_local_name = "BLETEST537344"
        logger().info(f"Setting BLE local name {set_local_name}")
        wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
        status = wifi_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f"getting the local name : {status}")
        assert set_local_name == status, "Set local name and get local name not matched "

        logger().info(f"Set up DUT for BLE advertising")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
        logger().info(f"Set up DUT for BLE advertising")
        ble_client_address = remote_wiseconnect3.interfaces.sapi.ble_start()
        assert ble_dut_address, f"Unable to find ble dut address"
        wifi_dut.interfaces.wifi.ble_start_advertising()

        logger().info("enabling the power save modes ")
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        logger().info(f"Begin Scanning for BLE devices")
        remote_wiseconnect3.interfaces.sapi.ble_start_scanning(ble_client_address=ble_dut_address)
        time.sleep(20)
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex = re.split(":", ble_client_address)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address = "0x"
        for hex_data_part in ble_client_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])

        logger().info(f"Initiating ble connection with connection parameters")
        remote_wiseconnect3.interfaces.sapi.ble_connect(ble_remote_dev_address=ble_dut_address,
                                                        ble_conn_interval_min=3200,
                                                        ble_conn_interval_max=3200,
                                                        ble_supervision_timeout=3200,
                                                        timeout=120)
        logger().info("Checking BLE connection stability for 300sec")
        time.sleep(300)
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
        logger().info("DUT is not disconnected from BLE")

        logger().info("Device Disconnection")
        wifi_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=ble_client_address)
        remote_wiseconnect3.interfaces.sapi.ble_disconnect(ble_remote_dev_address=ble_dut_address)
        logger().info("BLE disconnect successful")

        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "LE DATA")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        assert sniffer_data_df is not None

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)