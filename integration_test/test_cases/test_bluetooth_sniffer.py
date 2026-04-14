import pytest
from utf.utils.logger import get_logger
import os
import datetime
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap,\
    Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xBTFeatureBitMap,\
    Si91xCustomFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
import re
from utf.utils.stopwatch import Stopwatch
from utf.utils import print_dict
import time

def logger():
    return get_logger(__name__)

def __print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)


@pytest.mark.test_src_map_id('TC1021117529')
def test_ble_sniffer_using_nrf(ble_sniffer):
    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture()
    for _ in range(30):
        logger().info("Do Some Thing")
        time.sleep(1)
    ble_sniffer.interfaces.sniffer.stop_capture()
    file_size = os.path.getsize(ble_sniffer.interfaces.sniffer.capture_file)
    assert file_size > 0
    
@pytest.mark.test_src_map_id('TC6923505535')
def test_bt_sniffer_using_ellisys(bt_sniffer):
    bt_sniffer.interfaces.sniffer.init_sniffer()
    bt_sniffer.interfaces.sniffer.start_capture()
    for _ in range(30):
        logger().info("Do Some Thing")
        time.sleep(1)
    bt_sniffer.interfaces.sniffer.stop_capture()
    assert bt_sniffer.interfaces.sniffer.result is not None
    __print_throughput(bt_sniffer.interfaces.sniffer.result)
    assert bt_sniffer.interfaces.sniffer.capture_file is not None
    file_size = os.path.getsize(bt_sniffer.interfaces.sniffer.capture_file)
    assert file_size > 0


@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST ,
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('TC0689451540')
def test_ble_sniffer_using_frontline(ble_dut, ble_client, ble_sniffer):
    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture()
    logger().info("Initiate ble service in DUT")
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=3, set_smp=1)
    assert ble_dut_address, "failed to initiate ble in dut"

    logger().info("Set DUT in advertise mode")
    ble_dut.interfaces.bluetooth.ble_start_advertising()
    time.sleep(15)
    logger().info("Start smp scan from the remote device")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address, "failed to initiate ble in remote device"

    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Check the dut is listed...")
    ble_client.interfaces.bluetooth.get_devices()

    logger().info("Connect to the dut with mac address..")
    connect_time = datetime.datetime.now()
    ble_client.interfaces.bluetooth.pair_and_connect(ble_dut_address)
    logger().info(f"connect_time:  {connect_time}")
    # Mapping Master and Slave Address for Adding devices for sniffer
    ble_dut_address_hex = re.split(":", ble_dut_address)
    ble_client_address_hex = re.split(":", ble_client_address)
    master_address = "0x"
    for hex_data_part in ble_dut_address_hex:
        master_address = master_address + hex_data_part
    slave_address = "0x"
    for hex_data_part in ble_client_address_hex:
        slave_address = slave_address + hex_data_part
    tw = Stopwatch()
    # LinkKey Extraction from get_async_events may vary based on test agent/firmware output.
    # This logic is driven based on M61 wiseconnect_3, test agent and firmware
    link_key = ""
    link_key_data_hex = ""
    while tw.elapsed_sec < 30:
        events = ble_dut.interfaces.bluetooth.get_async_events()
        for event in events:
            logger().info(f"******{event.event_data}")
            if "link_key" in event.event_data:
                event_data = event.event_data
                link_key_data  = re.findall("link_key::.*", event_data)
                link_key_data_hex = re.split(":", link_key_data[0])
                link_key = "0x"
            for hex_data_part in link_key_data_hex:
                hex_data_part = hex_data_part.replace(" ", "")
                if len(hex_data_part) == 1:
                    hex_data_part = '0'+ hex_data_part
                link_key = link_key + hex_data_part
    link_key = link_key.replace(" ", "")
    link_key = link_key.replace("link_key", "")
    logger().info(f"**************Link Key Extracted: {link_key}***************")
    time.sleep(60)
    ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])
    time.sleep(30)
    if link_key != "":
        ble_sniffer.interfaces.sniffer.add_link_key(link_key.upper(), master_address, slave_address)
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    ble_sniffer.interfaces.sniffer.stop_capture()
    captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')

    time.sleep(30)
    exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "LE BB")
    for captured_file in captured_files:
        captured_file = captured_file.replace("/tmp/reports","/app/reports")
        file_size = os.path.getsize(captured_file)
        assert file_size > 0

    exported_csv_file = exported_csv_file.replace("/tmp/reports","/app/reports")
    file_size = os.path.getsize(exported_csv_file)
    assert file_size > 0
    sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
    assert sniffer_data_df is not None


@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST ,
        },
    )
@pytest.mark.ble_sniffer("mock_bluetooth_sniffer")
@pytest.mark.test_src_map_id('TC7518887545')
def test_ble_sniffer_using_frontline_with_mock_sniffer(ble_dut, ble_client, ble_sniffer):
    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture()
    logger().info("Initiate ble service in DUT")
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=3, set_smp=1)
    assert ble_dut_address, "failed to initiate ble in dut"

    logger().info("Set DUT in advertise mode")
    ble_dut.interfaces.bluetooth.ble_start_advertising()
    time.sleep(15)
    logger().info("Start smp scan from the remote device")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address, "failed to initiate ble in remote device"

    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Check the dut is listed...")
    ble_client.interfaces.bluetooth.get_devices()

    logger().info("Connect to the dut with mac address..")
    connect_time = datetime.datetime.now()
    ble_client.interfaces.bluetooth.pair_and_connect(ble_dut_address)
    logger().info(f"connect_time:  {connect_time}")
    # Mapping Master and Slave Address for Adding devices for sniffer
    ble_dut_address_hex = re.split(":", ble_dut_address)
    ble_client_address_hex = re.split(":", ble_client_address)
    master_address = "0x"
    for hex_data_part in ble_dut_address_hex:
        master_address = master_address + hex_data_part
    slave_address = "0x"
    for hex_data_part in ble_client_address_hex:
        slave_address = slave_address + hex_data_part
    tw = Stopwatch()
    # LinkKey Extraction from get_async_events may vary based on test agent/firmware output.
    # This logic is driven based on M61 wiseconnect_3, test agent and firmware
    link_key = ""
    link_key_data_hex = ""
    while tw.elapsed_sec < 30:
        events = ble_dut.interfaces.bluetooth.get_async_events()
        for event in events:
            logger().info(f"******{event.event_data}")
            if "link_key" in event.event_data:
                event_data = event.event_data
                link_key_data = re.findall("link_key::.*", event_data)
                link_key_data_hex = re.split(":", link_key_data[0])
                link_key = "0x"
            for hex_data_part in link_key_data_hex:
                hex_data_part = hex_data_part.replace(" ", "")
                if len(hex_data_part) == 1:
                    hex_data_part = '0'+ hex_data_part
                link_key = link_key + hex_data_part
    link_key = link_key.replace(" ", "")
    link_key = link_key.replace("link_key", "")
    logger().info(f"**************Link Key Extracted: {link_key}***************")
    time.sleep(60)
    ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])
    time.sleep(30)
    if link_key != "":
        ble_sniffer.interfaces.sniffer.add_link_key(link_key.upper(), master_address, slave_address)
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    ble_sniffer.interfaces.sniffer.stop_capture()
    captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')

    time.sleep(30)
    exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "LE BB")
    for captured_file in captured_files:
        captured_file = captured_file.replace("/tmp/reports","/app/reports")
        file_size = os.path.getsize(captured_file)
        assert file_size > 0

    exported_csv_file = exported_csv_file.replace("/tmp/reports","/app/reports")
    file_size = os.path.getsize(exported_csv_file)
    assert file_size > 0
    sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
    assert sniffer_data_df is not None
