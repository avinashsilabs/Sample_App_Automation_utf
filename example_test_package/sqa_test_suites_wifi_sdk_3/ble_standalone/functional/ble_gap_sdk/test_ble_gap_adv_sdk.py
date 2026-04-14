import re
import pytest
import time
import os
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap,\
    Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xBTFeatureBitMap,\
    Si91xCustomFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.stopwatch import Stopwatch


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
        2. Initiates the advertising from DUT using different adv_type
        3. Verifying adv_type and channels on sniffer logs

    Author: Vishakha
"""


def ble_different_adv_type_random_private_addr(ble_dut=None, ble_sniffer=None, capture_file=None, test_case=None,
                                               ble_adv_type=128, ble_addr_type=0, own_addr_type=0, ble_adv_int_min=256,
                                               ble_adv_int_max=512):
    ble_sniffer.interfaces.sniffer.init_sniffer()
    ble_sniffer.interfaces.sniffer.start_capture(capture_file=capture_file)

    logger().info("Initiate ble service in DUT")
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert ble_dut_address, "failed to initiate ble in dut"

    if ble_addr_type==1:
        logger().info("Set ble random address")
        ble_dut.interfaces.wifi.set_ble_address(ble_address=ble_dut_address)

    logger().info("Set DUT in advertise mode")
    ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=ble_adv_type, ble_addr_type=ble_addr_type,
                                                       own_addr_type=own_addr_type, ble_adv_int_min=ble_adv_int_min,
                                                       ble_adv_int_max=ble_adv_int_max)
    time.sleep(120)
    # Mapping Master and Slave Address for Adding devices for sniffer
    logger().info(f"dut address: {ble_dut_address}")
    ble_dut_address_hex = re.split(":", ble_dut_address)
    slave_address = "0x"
    for hex_data_part in ble_dut_address_hex:
        slave_address = slave_address + hex_data_part
    ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])

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
    if ble_addr_type==0:
        if (test_case==663355):
            logger().info(f"Checking LE general discoverable mode enable or not")
            assert all(sniffer_data_df.loc[sniffer_data_df["LE General Discoverable Mode"].isin(["Yes"])])
        adv_type = {128: 'ADV_IND', 129: 'ADV_DIRECT_IND', 130: 'ADV_SCAN_IND', 131: 'ADV_NONCONN_IND'}
        filtered_df = sniffer_data_df.loc[sniffer_data_df['Type'] == adv_type[ble_adv_type]]
        logger().info(f" advertising type : {filtered_df}")
        assert len(filtered_df) > 1, f"Testcase failed with No advertising type"
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


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663355')
def test_ble_sdk_undirected_non_connectable_adv_C663355(ble_sniffer, ble_dut, sl_collections):
    """
    Configure DUT in Slave and verify connectivity with Undirected non-connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663355',
                                                       test_case=663355, ble_adv_type=131)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663377')
def test_ble_sdk_undirected_connectable_min_int_adv_C663377(ble_dut, sl_collections, ble_sniffer):
    """
    Configure DUT in Slave and verify connectivity with Undirected connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663377',
                                                       test_case=663377, ble_adv_type=128, ble_adv_int_min=32,
                                                       ble_adv_int_max=32)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663378')
def test_ble_sdk_directed_connectable_min_int_adv_C663378(ble_dut, sl_collections, ble_sniffer):
    """
    Configure DUT in Slave and verify connectivity with directed connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663378',
                                                       test_case=663378, ble_adv_type=129, ble_adv_int_min=32,
                                                       ble_adv_int_max=32)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663379')
def test_ble_sdk_undirected_scannable_min_int_adv_C663379(ble_dut, sl_collections, ble_sniffer):
    """
    Configure DUT in Slave and verify connectivity with Undirected scannable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663379',
                                                       test_case=663379, ble_adv_type=130, ble_adv_int_min=32,
                                                       ble_adv_int_max=32)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663380')
def test_ble_sdk_undirected_non_connectable_min_int_adv_C663380(ble_dut, sl_collections, ble_sniffer):
    """
    Configure DUT in Slave and verify connectivity with Undirected non-connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663380',
                                                       test_case=663380, ble_adv_type=131, ble_adv_int_min=32,
                                                       ble_adv_int_max=32)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663381')
def test_ble_sdk_undirected_connectable_max_int_adv_C663381(ble_dut, sl_collections, ble_sniffer):
    """
    Configure DUT in Slave and verify connectivity with Undirected connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663381',
                                                       test_case=663381, ble_adv_type=128, ble_adv_int_min=16384,
                                                       ble_adv_int_max=16384)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663382')
def test_ble_sdk_directed_connectable_max_int_adv_C663382(ble_dut, sl_collections, ble_sniffer):
    """
    Configure DUT in Slave and verify connectivity with directed connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663382',
                                                       test_case=663382, ble_adv_type=129, ble_adv_int_min=16384,
                                                       ble_adv_int_max=16384)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663383')
def test_ble_sdk_undirected_scannable_max_int_adv_C663383(ble_dut, sl_collections, ble_sniffer):
    """
    Configure DUT in Slave and verify connectivity with undirected scannable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663383',
                                                       test_case=663383, ble_adv_type=130, ble_adv_int_min=16384,
                                                       ble_adv_int_max=16384)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663384')
def test_ble_sdk_undirected_non_connectable_max_int_adv_C663384(ble_dut, sl_collections, ble_sniffer):
    """
    Configure DUT in Slave and verify connectivity with Undirected non connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663384',
                                                       test_case=663384, ble_adv_type=131, ble_adv_int_min=16384,
                                                       ble_adv_int_max=16384)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663385')
def test_ble_sdk_undirected_connectable_max_min_int_adv_C663385(ble_dut, sl_collections, ble_sniffer):
    """
    Configure DUT in Slave and verify connectivity with Undirected connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663385',
                                                       test_case=663385, ble_adv_type=128, ble_adv_int_min=32,
                                                       ble_adv_int_max=16384)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663386')
def test_ble_sdk_directed_connectable_max_min_int_adv_C663386(ble_dut, sl_collections, ble_sniffer):
    """
    Configure DUT in Slave and verify connectivity with directed connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663386',
                                                       test_case=663386, ble_adv_type=129, ble_adv_int_min=32,
                                                       ble_adv_int_max=16384)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663387')
def test_ble_sdk_undirected_scannable_max_min_int_adv_C663387(ble_dut, sl_collections, ble_sniffer):
    """
    Configure DUT in Slave and verify connectivity with undirected scannable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663387',
                                                       test_case=663387, ble_adv_type=130, ble_adv_int_min=32,
                                                       ble_adv_int_max=16384)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663388')
def test_ble_sdk_undirected_non_connectable_max_min_int_adv_C663388(ble_dut, sl_collections, ble_sniffer):
    """
    Configure DUT in Slave and verify connectivity with Undirected non-connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663388',
                                                       test_case=663388, ble_adv_type=131, ble_adv_int_min=32,
                                                       ble_adv_int_max=16384)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663389')
def test_ble_sdk_undirected_connectable_random_addr_C663389(ble_dut, sl_collections, ble_sniffer):
    """
    Configure DUT in Slave and verify connectivity with Undirected connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663389',
                                                       test_case=663389, ble_adv_type=128, ble_addr_type=1,
                                                       own_addr_type=1)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663390')
def test_ble_sdk_directed_connectable_random_addr_C663390(ble_dut, sl_collections, ble_sniffer):
    """
    Configure DUT in Slave and verify connectivity with directed connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663390',
                                                       test_case=663390, ble_adv_type=129, ble_addr_type=1,
                                                       own_addr_type=1)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663391')
def test_ble_sdk_undirected_scannable_random_addr_C663391(ble_dut, sl_collections, ble_sniffer):
    """
    Configure DUT in Slave and verify connectivity with undirected scannable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663391',
                                                       test_case=663391, ble_adv_type=130, ble_addr_type=1,
                                                       own_addr_type=1)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C663392')
def test_ble_sdk_undirected_non_connectable_random_addr_adv_C663392(ble_dut, sl_collections, ble_sniffer):
    """
    Configure DUT in Slave and verify connectivity with Undirected non-connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    """
    try:
        with TimeMeasurer() as t:
            ble_different_adv_type_random_private_addr(ble_dut, ble_sniffer, capture_file='ble_gap_sdk_C663392',
                                                       test_case=663392, ble_adv_type=131, ble_addr_type=1,
                                                       own_addr_type=1)
        logger().info(f"time taken for test {t.duration}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C219367')
def test_start_stop_adv_clear_resolve_list_C219367(ble_dut, sl_collections):
    """ Verify the BLE start advertising, stop advertising and clear resolve list api in loop for 1 minutes"""
    logger().info("Initiate ble service in DUT")
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert ble_dut_address, "failed to initiate ble in dut"
    sw = Stopwatch()
    while sw.elapsed_sec < 300:
        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(timeout=120)
        ble_dut.interfaces.bluetooth.ble_stop_advertising(timeout=30)
        ble_dut.interfaces.bluetooth.ble_resolvlist(process_type=3, addr_type=0, remote_dev_addr="00:00:00:00:00:00",
                                                    peer_irk=0, local_irk=0)