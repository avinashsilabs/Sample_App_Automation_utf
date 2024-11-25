import re
import pytest
import time
import datetime
import os
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap,\
    Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xBTFeatureBitMap,\
    Si91xCustomFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.utils.stopwatch import Stopwatch
import pandas as pd


def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9117) SOC board
        2. EFR32
        3. Raspberry PI4
        4. Teledyne sniffer (to capture BLE OTA logs)

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Initiates the DUT in master Spp mode for the capability
        3. Initiates the client in slave spp with capability enables
        4. Opens Bt socket and connects to the remote client.
        5. Verifies ping after the connection.

    Author: Vishakha
"""

def ble_adv_and_scan(ble_dut=None, ble_client=None, ble_sniffer=None, capture_file=None, test_case=None,
                     ble_scan_type=1, ble_scan_interval=None, ble_scan_window=None, timeout=None):
    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture(capture_file=capture_file)
    logger().info(f"Start DUT")
    ble_dut_address = ble_dut.interfaces.wifi.ble_start()

    ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
    assert ble_client_address, "Unable to get ble_client_address"

    if (test_case==19819) or (test_case==537346) or (test_case==663404) or (test_case==663405):
        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode8,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
    logger().info(f"\n\n Start scanning and connect to ble client \n\n")
    ble_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, ble_scan_type=ble_scan_type,
                                               ble_scan_interval=ble_scan_interval, ble_scan_window=ble_scan_window,
                                               timeout=timeout)

    if ((test_case==19811) or (test_case==19812) or (test_case==19813) or (test_case==19814) or (test_case==19815) or
        (test_case==19816) or (test_case==19817) or (test_case==19818) or (test_case==537345) or (test_case==663401) or
        (test_case==663402) or (test_case==663403)):
        logger().info(f"\n\n ****Enabling Wlan and BLE power save**** \n\n")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
    time.sleep(120)
    if (test_case==663401) or (test_case==663402) or (test_case==663403) or (test_case==663404) or (test_case==663405):
        events = ble_dut.interfaces.bluetooth.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                    logger().info(f" event data : {event.event_data}")

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()

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

    logger().info("stop advertising")
    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(2)
    ble_client.interfaces.bluetooth.close()
    ble_sniffer.interfaces.sniffer.stop_capture()
    logger().info("Sniffer stop successful")
    captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
    time.sleep(30)
    exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "LE ADV")
    for captured_file in captured_files:
        captured_file = captured_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(captured_file)
        assert file_size > 0
    exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
    file_size = os.path.getsize(exported_csv_file)
    assert file_size > 0
    sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
    if ble_scan_type==1:
        filtered_df = sniffer_data_df[sniffer_data_df['Chan'].isin([37, 38, 39])]
        result = []
        for channel in filtered_df['Chan'].unique():
            channel_data = filtered_df[filtered_df['Chan'] == channel]
            if 'SCAN_REQ' in channel_data['Type'].values and 'SCAN_RSP' in channel_data['Type'].values:
                for request_type in ['SCAN_REQ', 'SCAN_RSP']:
                    result.append([channel, request_type])
        logger().info(f" channel response : {result}")
        assert len(result) > 1, f"Testcase failed with No scan response and scan request on same channel"
    else:
        logger().info(sniffer_data_df.head())
        assert sniffer_data_df is not None


pytestmark=[
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
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                                   Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
            "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS |
                            Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC |
                            Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID |
                            Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS |
                            Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE |
                            Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp |
                               Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        },
    )
]


#=========================== BLE GAP Scan Interval and Scan Window ==========================


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_interval_30_and_window_20_C19811(ble_dut, ble_client, sl_collections, ble_sniffer):
    """
    Verify BLE continuous Scanning by configuring scan window and scan interval different value
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_and_scan(ble_dut, ble_client, ble_sniffer, capture_file='ble_gap_sdk_C19811', test_case=19811,
                             ble_scan_interval=48, ble_scan_window=32, timeout=120)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_interval_40_and_window_30_C19812(ble_dut, ble_client, sl_collections, ble_sniffer):
    """
    Verify BLE continuous Scanning by configuring scan window and scan interval different value
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_and_scan(ble_dut, ble_client, ble_sniffer, capture_file='ble_gap_sdk_C19812', test_case=19812,
                             ble_scan_interval=64, ble_scan_window=48, timeout=120)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_interval_100_and_window_50_C19813(ble_dut, ble_client, sl_collections, ble_sniffer):
    """
    Verify BLE continuous Scanning by configuring scan window and scan interval different value
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_and_scan(ble_dut, ble_client, ble_sniffer, capture_file='ble_gap_sdk_C19813', test_case=19813,
                             ble_scan_interval=160, ble_scan_window=80, timeout=120)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_interval_200_and_window_100_C19814(ble_dut, ble_client, sl_collections, ble_sniffer):
    """
    Verify BLE continuous Scanning by configuring scan window and scan interval different value
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_and_scan(ble_dut, ble_client, ble_sniffer, capture_file='ble_gap_sdk_C19814', test_case=19814,
                             ble_scan_interval=320, ble_scan_window=160, timeout=120)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_interval_500_and_window_300_C19815(ble_dut, ble_client, sl_collections, ble_sniffer):
    """
    Verify BLE continuous Scanning by configuring scan window and scan interval different value
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_and_scan(ble_dut, ble_client, ble_sniffer, capture_file='ble_gap_sdk_C19815', test_case=19815,
                             ble_scan_interval=800, ble_scan_window=480, timeout=120)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_interval_600_and_window_400_C19816(ble_dut, ble_client, sl_collections, ble_sniffer):
    """
    Verify BLE continuous Scanning by configuring scan window and scan interval different value
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_and_scan(ble_dut, ble_client, ble_sniffer, capture_file='ble_gap_sdk_C19816', test_case=19816,
                             ble_scan_interval=960, ble_scan_window=640, timeout=120)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_interval_800_and_window_500_C19817(ble_dut, ble_client, sl_collections, ble_sniffer):
    """
    Verify BLE continuous Scanning by configuring scan window and scan interval different value
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_and_scan(ble_dut, ble_client, ble_sniffer, capture_file='ble_gap_sdk_C19817', test_case=19817,
                             ble_scan_interval=1280, ble_scan_window=800, timeout=120)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_interval_10sec_and_window_5sec_C19818(ble_dut, ble_client, sl_collections, ble_sniffer):
    """
    Verify BLE continuous Scanning by configuring scan window and scan interval different value
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_and_scan(ble_dut, ble_client, ble_sniffer, capture_file='ble_gap_sdk_C19818', test_case=19818,
                             ble_scan_interval=16384, ble_scan_window=8000, timeout=120)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_same_scan_interval_and_window_C19819(ble_dut, ble_client, sl_collections, ble_sniffer):
    """
    Verify BLE continuous Scanning by configuring scan window and scan interval same value
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_and_scan(ble_dut, ble_client, ble_sniffer, capture_file='ble_gap_sdk_C19819', test_case=19819,
                             ble_scan_interval=32, ble_scan_window=32, timeout=120)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


#Blocked: WIFI_BT_UTFHELP-4588, SI91X-17370
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_scan_interval_5ms_and_window_2ms_C537345(ble_dut, ble_client, sl_collections, ble_sniffer):
    """
    Verify BLE continuous Scanning by configuring scan window and scan interval different value
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_and_scan(ble_dut, ble_client, ble_sniffer, capture_file='ble_gap_sdk_C537345', test_case=537345,
                             ble_scan_interval=8, ble_scan_window=4, timeout=180)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_same_scan_interval_and_window_C537346(ble_dut, ble_client, sl_collections, ble_sniffer):
    """
    Verify BLE continuous Scanning by configuring scan window and scan interval same value
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_and_scan(ble_dut, ble_client, ble_sniffer, capture_file='ble_gap_sdk_C537346', test_case=537346,
                             ble_scan_interval=4, ble_scan_window=4, timeout=120)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "ble_stop_scan", "wifi_powersave_disable",
                                         "bt_powersave_disable"])
def test_ble_sdk_undirected_connectable_C91337(ble_dut, ble_client, sl_collections, ble_sniffer):
    """
    Configure DUT in Master and verify connectivity with Undirected connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_int_min = 1000
            ble_adv_int_max = 1000
            ble_scan_interval = 160
            ble_scan_window = 132
            log_file_name = 'ble_gap_sdk_C91337'
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(capture_file=log_file_name)

            logger().info("start ble...")
            ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            assert ble_dut_address, "unable to fetch bd address"
            logger().info(f"Configuring Remote LE device in Undirected connectable advertising mode")
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
                bt_dut_address=ble_dut_address,
                hci_adv_params="0xA0 0x05 "  # Advertising_Interval_Min
                               "0xA0 0x05 "  # Advertising_Interval_Max
                               "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                               "0x00 "  # Own_Address_Type
                               "0x00 "  # Peer_Address_Type
                               "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                               "0x07 "  # Advertising_Channel_Map
                               "0x00"  # Advertising_Filter_Policy
                , scan_resp_data="0x0f 0x0e 0x09 0x75 0x74 0x66 0x5f 0x77 0x69 "
                                        "0x66 0x69 0x5f 0x74 0x65 0x73 " 
                                        "0x74 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                        "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
            )
            assert ble_client_address, "failed to initiate ble in remote device"

            logger().info("Start scanning....")
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address,
                                                            ble_scan_interval=ble_scan_interval,
                                                            ble_scan_window=ble_scan_window, timeout=120)
            sw = Stopwatch()
            while sw.elapsed_sec < 60:
                events = ble_dut.interfaces.bluetooth.get_async_events()
                time_status = True
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                        if time_status:
                            start_time = time.time()
                            logger().info(f"Start time: {start_time}")
                            time_status = False
                        else:
                            if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                                logger().info(f" event data : {event.event_data}")
                                scan_result = event.event_data
                                logger().info(f"*************** scan result : {scan_result}")
                                end_time = time.time()
                                logger().info(f"End time: {end_time}")
                            assert (end_time-start_time)<4, f"scan responses of the remote device is " \
                                                            f"({end_time-start_time}) more than 4 sec, Hence testcase failed"
                        if not time_status:
                            break

            ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_int_min=ble_adv_int_min,
                                                               ble_adv_int_max=ble_adv_int_max)
            logger().info("enabling the power save modes ")
            ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                         psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            time.sleep(3)
            logger().info("stop scanning")
            ble_dut.interfaces.bluetooth.ble_stop_scanning()

            # Mapping Master and Slave Address for Adding devices for sniffer
            logger().info(f"dut address: {ble_dut_address}")
            logger().info(f"client address: {ble_client_address}")
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex = re.split(":", ble_client_address)
            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part
            slave_address = "0x"
            for hex_data_part in ble_client_address_hex:
                slave_address = slave_address + hex_data_part
            ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])

            logger().info("stop advertising")
            ble_client.interfaces.bluetooth.stop_advertising()
            time.sleep(2)
            ble_client.interfaces.bluetooth.close()
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "LE ADV")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            assert sniffer_data_df is not None
        logger().info(f"time taken for test {t.duration}")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_BLE_rejects_SMP_pair_request_C147312(ble_dut, ble_client, sl_collections, ble_sniffer):
    try:
        with TimeMeasurer() as t:
            log_file_name = 'ble_gap_sdk_C147312'
            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(capture_file=log_file_name)
            logger().info("start ble in dut")
            ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1, smp_pair=1)
            assert ble_dut_address, "ble initialization failed in dut"

            logger().info(f"Set up DUT for BLE advertising")
            ble_dut.interfaces.wifi.ble_start_advertising()

            logger().info("enabling the power save modes ")
            ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            logger().info(f"Begin Scanning for BLE devices")
            logger().info("Executing lescan in raspi")
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
            assert ble_client_address, f"Unable to get BLE client address"
            time.sleep(5)
            logger().info(f"Stop Scanning for BLE devices")
            ble_client.interfaces.bluetooth.stop_scanning()

            # connecting to dut
            logger().info("Connect start from remote to dut ")
            ble_client.interfaces.bluetooth.pair_and_connect(dev_addr=ble_dut_address, timeout=30)
            time.sleep(2)
            logger().info("Checking connection status of BLE")
            state = ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == 0, "DUT BLE device is in connected state"

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

            ble_client.interfaces.bluetooth.close()
            ble_sniffer.interfaces.sniffer.stop_capture()
            logger().info("Sniffer stop successful")
            captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "SMP")
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            assert len(sniffer_data_df.loc[sniffer_data_df['Code'].isin(['Pairing Request', 'Pairing Failed'])])>=2
        logger().info(f"time taken for test {t.duration}")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


#=========================== BLE GAP Passive Scan set by Interval and Scan Window ==========================


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_passive_scan_set_by_interval_and_window_C663401(ble_sniffer, ble_dut, ble_client, sl_collections):
    """
    Configure DUT_BLE for Passive scan and verify its functionality
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_and_scan(ble_dut, ble_client, ble_sniffer, capture_file='ble_gap_sdk_C663401', test_case=663401,
                             ble_scan_type=0, ble_scan_interval=48, ble_scan_window=32, timeout=120)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_passive_scan_set_by_interval_and_window_C663402(ble_sniffer, ble_dut, ble_client, sl_collections):
    """
    Configure DUT_BLE for Passive scan and verify its functionality
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_and_scan(ble_dut, ble_client, ble_sniffer, capture_file='ble_gap_sdk_C663402', test_case=663402,
                             ble_scan_type=0, ble_scan_interval=64, ble_scan_window=48, timeout=120)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_passive_scan_set_by_interval_and_window_C663403(ble_sniffer, ble_dut, ble_client, sl_collections):
    """
    Configure DUT_BLE for Passive scan and verify its functionality
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_and_scan(ble_dut, ble_client, ble_sniffer, capture_file='ble_gap_sdk_C663403', test_case=663403,
                             ble_scan_type=0, ble_scan_interval=160, ble_scan_window=80, timeout=120)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_passive_scan_set_by_same_interval_and_window_C663404(ble_sniffer, ble_dut, ble_client, sl_collections):
    """
    Configure DUT_BLE for Passive scan and verify its functionality
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_and_scan(ble_dut, ble_client, ble_sniffer, capture_file='ble_gap_sdk_C663404', test_case=663404,
                             ble_scan_type=0, ble_scan_interval=160, ble_scan_window=160, timeout=120)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_sdk_active_scan_set_by_same_interval_and_window_C663405(ble_sniffer, ble_dut, ble_client, sl_collections):
    """
    Configure DUT_BLE for Passive scan and verify its functionality
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with TimeMeasurer() as t:
            ble_adv_and_scan(ble_dut, ble_client, ble_sniffer, capture_file='ble_gap_sdk_C663405', test_case=663405,
                             ble_scan_type=1, ble_scan_interval=160, ble_scan_window=160, timeout=120)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)
