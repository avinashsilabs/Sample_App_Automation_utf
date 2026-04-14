import pytest
import pandas as pd
import re
from example_test_package.conftest import rs_helper_ble
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap
)
from utf.utf_config import UtfConfig
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.logger import get_logger
from utf.interfaces.wifi import WlanError
import time, os
import threading
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from datetime import timedelta, datetime

def logger():
    return get_logger(__name__)
"""
    * setup requirement:
        1. DUT(RS9117) SOC board
        2. REF(RS9117) SOC board
        3. Teledyne sniffer (to capture BLE OTA logs)
        4. NUC and nRF(To capture and validate OTA logs using Tshark) - optional
        5. Ellysis (to Capture OTA logs) - optional
    Author: 
        Ashwin.Rajendran@silabs.com
"""
def calculate_offset(df):
    # Extract numeric part of *Calculated Offset using regex and convert to numeric type, handling missing values
    try:
        df['*Calculated Offset'] = df['*Calculated Offset'].apply(
        lambda x: float(re.search(r'\d+', x).group(0)) if pd.notnull(x) else None)
    except:
        df['*Calculated Offset'] = df['*Calculated Offset'].apply(
            lambda x: float(re.search(r'\d+', str(x)).group(0)) if pd.notnull(x) else None
        )


    try:
        # Extract only the required part of the Timestamp using regex
        df['Timestamp'] = df['Timestamp'].apply(lambda x: re.search(r'\d+:\d+:\d+\.\d+ \w{2}', x).group(0))
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%I:%M:%S.%f %p')
    except:
        # Extract the time part from the original 'Timestamp' column
        df['Timestamp'] = df['Timestamp'].apply(lambda x: re.search(r"\d+:\d+:\d+\.\d+", x.strftime('%Y-%m-%d %H:%M:%S.%f')).group())
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%H:%M:%S.%f')

    # Function to find the pattern and calculate the required difference
    def find_pattern_and_calculate(df):
        for i in range(len(df) - 3):
            if df.loc[i, 'Chan'] == 37 and df.loc[i + 1, 'Chan'] == 38 and df.loc[i + 2, 'Chan'] == 39:
                if df.loc[i + 3, 'Chan'] not in [37, 38, 39]:
                    offset_39 = df.loc[i + 2, '*Calculated Offset']
                    timestamp_39 = df.loc[i + 2, 'Timestamp']
                    timestamp_random = df.loc[i + 3, 'Timestamp']
                    time_diff_microseconds = (timestamp_random - timestamp_39).total_seconds() * 1e6
                    if abs(offset_39 - time_diff_microseconds) <= 15:
                        return True
        return False

    return find_pattern_and_calculate(df)

def calculate_sync_offset(df):
    # Convert Timestamp column to datetime
    try:
        # Extract only the required part of the Timestamp using regex
        df['Timestamp'] = df['Timestamp'].apply(lambda x: re.search(r'\d+:\d+:\d+\.\d+ \w{2}', x).group(0))
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%I:%M:%S.%f %p')
    except:
        # Extract the time part from the original 'Timestamp' column
        df['Timestamp'] = df['Timestamp'].apply(
            lambda x: re.search(r"\d+:\d+:\d+\.\d+", x.strftime('%Y-%m-%d %H:%M:%S.%f')).group())
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%H:%M:%S.%f')

    aux_sync_ind_row = df[df['Type'] == 'AUX_SYNC_IND'].iloc[1]

    aux_sync_ind_timestamp = aux_sync_ind_row['Timestamp']

    aux_adv_ind_row = df[(df['Type'] == 'AUX_ADV_IND') & (df['Timestamp'] < aux_sync_ind_timestamp)].iloc[-1]

    offset_value = str(aux_adv_ind_row['*Calculated Offset [2]'])
    offset_value = int(re.findall(r'\d+', offset_value)[0])
    aux_adv_ind_timestamp = aux_adv_ind_row['Timestamp']

    # Calculate the time difference
    time_difference = aux_sync_ind_timestamp - aux_adv_ind_timestamp
    time_difference_in_microseconds = time_difference.total_seconds() * 1e6
    logger().info(f"\nTime difference between AUX_ADV_IND and AUX_SYNC_IND: {time_difference_in_microseconds}")
    logger().info(f"\nOffset value: {offset_value}")
    # Compare the time difference with offset value (+ or - 60 microseconds)
    return abs(time_difference_in_microseconds - offset_value) <= 60
"""
    Test case category : BLE Ext Connection with Legacy Adv on DUT - Slave connection
    Device roles       : DUT is performing Peripheral role
    Fixures used       : ble_sniffer - To caputre BLE OTA logs through Teledyne sniffer
"""
@pytest.mark.parametrize(
    "adv_type, test_case_id, adv_filter_policy",
    [
        (19, "C528553", 0),
        (19, "C528554", 2),
        (21, "C528555", 0),
    ],
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C528555')
def test_verify_Ext_legacy_connection_dut_as_slave_C528553_to_C528555(ble_dut, ble_sniffer, remote_wiseconnect3, sl_collections,
                                        adv_type, test_case_id, adv_filter_policy):
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                    data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy, test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, ble_sniffer=ble_sniffer, ble_client_address=ble_client_address, central=remote_wiseconnect3, powersave_p=True, connect=True, stop_scan=True)
    if adv_type in [19]:
        # Assert if there is no ADV_IND advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Type'] == "ADV_IND") & (df[
                                                           "Aux Pointer"] != "Present")]) >= 1, "\n\n **** Test case Failed with no ADV_IND advertising mode found or Aux Pointer is not present ****\n\n"
        logger().info("\n\n **** ADV_IND advertising mode found and Aux Pointer is not present ****\n\n")
    if adv_type in [21]:
        # Assert if there is no ADV_NONCONN_IND advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Type'] == "ADV_DIRECT_IND") & (df[
                                                                  "Aux Pointer"] != "Present")]) >= 1, "\n\n **** Test case Failed with no ADV_DIRECT_IND advertising mode found or Aux Pointer is not present ****\n\n"
        logger().info("\n\n **** ADV_DIRECT_IND advertising mode found and Aux Pointer is not present ****\n\n")
    # Assert if primary PHY is not 1M
    assert (df[df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '1M').any(), '\n\n **** Test case Failed with primary PHY is not 1M ****\n\n'
    logger().info("\n\n **** Primary PHY is 1M ****\n\n")
    # Assert if there is no SCAN_RSP packet found on 37, 38, 39 channels
    assert (df[df['Type'] == 'SCAN_RSP']['Chan'].isin(
        [37, 38,
         39]) == True).all(), "\n\n **** Test case Failed with SCAN_RSP packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** SCAN_RSP packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no CONNECT_IND packet found on 37, 38, 39 channels
    assert (df[df['Type'] == 'CONNECT_IND']['Chan'].isin(
        [37, 38,
         39]) == True).all(), "\n\n **** Test case Failed with CONNECT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

"""
    Test case category :BLE Ext Connection with Legacy Adv on Ref - Master connection
    Device roles       : DUT is performing Central role
    Fixures used       : ble_sniffer - To caputre BLE OTA logs through Teledyne sniffer
"""
@pytest.mark.parametrize(
    "adv_type, test_case_id, adv_filter_policy",
    [
        (19, "C528556", 0),
    ],
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C528556')
def test_verify_Ext_legacy_connection_dut_as_master_C528556(ble_dut, ble_sniffer, remote_wiseconnect3, sl_collections,
                                        adv_type, test_case_id, adv_filter_policy):
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                    data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy, test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, ble_sniffer=ble_sniffer, ble_client_address=ble_client_address, central=remote_wiseconnect3, powersave_p=True, connect=True, stop_scan=True)
    if adv_type in [19]:
        # Assert if there is no ADV_IND advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Type'] == "ADV_IND") & (df[
                                                           "Aux Pointer"] != "Present")]) >= 1, "\n\n **** Test case Failed with no ADV_IND advertising mode found or Aux Pointer is not present ****\n\n"
        logger().info("\n\n **** ADV_IND advertising mode found and Aux Pointer is not present ****\n\n")
    if adv_type in [21]:
        # Assert if there is no ADV_NONCONN_IND advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Type'] == "ADV_DIRECT_IND") & (df[
                                                                  "Aux Pointer"] != "Present")]) >= 1, "\n\n **** Test case Failed with no ADV_DIRECT_IND advertising mode found or Aux Pointer is not present ****\n\n"
        logger().info("\n\n **** ADV_DIRECT_IND advertising mode found and Aux Pointer is not present ****\n\n")
    # Assert if primary PHY is not 1M
    assert (df[df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '1M').any(), '\n\n **** Test case Failed with primary PHY is not 1M ****\n\n'
    logger().info("\n\n **** Primary PHY is 1M ****\n\n")
    # Assert if there is no SCAN_RSP packet found on 37, 38, 39 channels
    assert (df[df['Type'] == 'SCAN_RSP']['Chan'].isin(
        [37, 38,
         39]) == True).all(), "\n\n **** Test case Failed with SCAN_RSP packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** SCAN_RSP packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no CONNECT_IND packet found on 37, 38, 39 channels
    assert (df[df['Type'] == 'CONNECT_IND']['Chan'].isin(
        [37, 38,
         39]) == True).all(), "\n\n **** Test case Failed with CONNECT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

"""
    Test case category : BLE Ext peripheral connection with legacy advertising on DUT for random addr type - Slave Connection
    Device roles       : DUT is performing Peripheral role
    Fixures used       : ble_sniffer - To caputre BLE OTA logs through Teledyne sniffer
"""
@pytest.mark.parametrize(
    "adv_type, test_case_id, adv_filter_policy, pri_adv_phy, sec_adv_phy",
    [
        (19, "C528557", 0, 1, 1),
        (19, "C528558", 0, 1, 2),
        (19, "C528559", 0, 3, 3),
    ],
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C528559')
def test_verify_Ext_legacy_connection_with_random_addr_C528557_C528558_C528559(ble_dut, ble_sniffer, remote_wiseconnect3, sl_collections,
                                        adv_type, test_case_id, adv_filter_policy, pri_adv_phy, sec_adv_phy):
    random_address = "11:33:33:33:33:11"
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address, pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy,
                                    data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy, test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, ble_sniffer=ble_sniffer, ble_client_address=ble_client_address, central=remote_wiseconnect3, powersave_p=True, connect=True, stop_scan=True,
                                   random_address=random_address, remote_addr_type=1, dont_cleanup=True)
    if adv_type in [19]:
        # Assert if there is no ADV_IND advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Type'] == "ADV_IND") & (df[
                                                           "Aux Pointer"] != "Present") &
                        (df.apply(lambda row: row['AddrTypeA'] == "(rand)", axis=1))])>=1, "\n\n **** Test case Failed with no ADV_IND advertising mode found or Aux Pointer is not present ****\n\n"
        logger().info("\n\n **** ADV_IND advertising mode found and Aux Pointer is not present ****\n\n")
    if pri_adv_phy in [3]:
        # Assert if primary PHY is not LE Coded on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE Coded on ADV_EXT_IND packets ****\n\n")
    elif pri_adv_phy in [1]:
        # Assert if primary PHY is not LE 1M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE 1M on ADV_EXT_IND packets ****\n\n")
    # Assert if there is no SCAN_RSP packet found on 37, 38, 39 channels
    assert (df[df['Type'] == 'SCAN_RSP']['Chan'].isin(
        [37, 38,
         39]) == True).all(), "\n\n **** Test case Failed with SCAN_RSP packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** SCAN_RSP packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no CONNECT_IND packet found on 37, 38, 39 channels
    assert (df[df['Type'] == 'CONNECT_IND']['Chan'].isin(
        [37, 38,
         39]) == True).all(), "\n\n **** Test case Failed with CONNECT_IND packet found on 37, 38, 39 channels ****\n\n"
    # Assert if there is no CONNECT_IND packet found with 1M PHY
    assert len(df.loc[(df['Type'] == "CONNECT_IND") & (df[
                                                           "+PHY Type (LE BB)"] == "1M")])>=1, "\n\n **** Test case Failed with no CONNECT_IND packet found with 1M PHY ****\n\n"
    logger().info("\n\n **** CONNECT_IND packet found with 1M PHY ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

"""
    Test case category :BLE Ext Connection with Ext Adv on Ref - Master Connection
    Device roles       : DUT is performing Central role and Reference is performing Peripheral role
"""
@pytest.mark.parametrize(
    "adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, random_address",
    [
        (1, 32, 40, "C528560", 1, 1, "11:33:33:33:33:11"),
        (1, 32, 40, "C528561", 1, 1, None),
        (1, 32, 40, "C528562", 1, 2, "11:33:33:33:33:11"),
        (1, 32, 40, "C528563", 1, 2, None),
        (1, 32, 40, "C528564", 3, 3, "11:33:33:33:33:11"),
        (1, 32, 40, "C528565", 3, 3, None),
    ],
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C528565')
def test_verify_Ext_connection_dut_as_master_C528560_C528565(ble_dut, ble_sniffer, remote_wiseconnect3, sl_collections,
                                        adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, random_address):
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, adv_async_required=True,  min_interval=min_interval, max_interval=max_interval,
                                    data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id, adv_handle=0,
                                    random_address=random_address,
                                    ble_sniffer=ble_sniffer, ble_client_address=ble_client_address, central=remote_wiseconnect3, scanning_phys= 5, connect=True, stop_scan=True,
                                    remote_addr_type=1 if random_address!=None else 0, dont_cleanup=True)
    if adv_type in [1]:
        # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[
                       (df['Advertising Mode'] == "Connectable Non-Scannable") &
                       (df['Aux Pointer'] == "Present") &
                       (df.apply(
                           lambda row: row['Ext Adv Address Type'] == ("random" if random_address != None else "public"),
                           axis=1))
                       ]) >= 1, "\n\n **** Test case Failed with no connectable non-scannable advertising mode found..! ****\n\n"
        logger().info(
            f"\n\n **** Connectable non-Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if random_address != None  else 'public'} ****\n\n")
    assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
        [37, 38, 39]) == False).all(), "\n\n **** Test case Failed with no AUX_SCAN_RSP packets found..! ****\n\n"
    logger().info("\n\n **** AUX_SCAN_RSP packets are not found ****\n\n")
    if pri_adv_phy in [3] and sec_adv_phy in [3]:
        # Assert if primary PHY is not LE Coded on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE Coded on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE Coded on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE Coded on AUX_ADV_IND packets ****\n\n")
    elif pri_adv_phy in [1] and sec_adv_phy in [1]:
        # Assert if primary PHY is not LE 1M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE 1M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE 1M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE 1M on AUX_ADV_IND packets ****\n\n")
    elif pri_adv_phy in [2] and sec_adv_phy in [2]:
        # Assert if primary PHY is not LE 2M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE 2M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE 2M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE 2M on AUX_ADV_IND packets ****\n\n")
    elif pri_adv_phy in [1] and sec_adv_phy in [2]:
        # Assert if primary PHY is not LE 1M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE 1M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE 2M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE 2M on AUX_ADV_IND packets ****\n\n")
    # Assert if there is no AUX_CONNECT_REQ packet found with 1M PHY
    assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39]))]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel ****\n\n"
    logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel ****\n\n")
    # Assert if there is no AUX_CONNECT_RSP packet found with 1M PHY
    assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                             39]))]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel ****\n\n"
    logger().info("\n\n **** AUX_CONNECT_RSP packet found on secondary channel ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

"""
    Test case category :BLE Ext Connection with Ext Adv on DUT - Slave Connection
    Device roles       : DUT is performing Peripheral role and Reference is performing Central role
"""
@pytest.mark.parametrize(
    "adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, random_address",
    [
        (1, 32, 40, "C528652", 1, 1, "11:33:33:33:33:11"),
        (1, 32, 40, "C528653", 1, 1, None),
        (1, 32, 40, "C528654", 1, 2, "11:33:33:33:33:11"),
        (1, 32, 40, "C528655", 1, 2, None),
        (1, 32, 40, "C528656", 3, 3, "11:33:33:33:33:11"),
        (1, 32, 40, "C528657", 3, 3, None),
    ],
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C528657')
def test_verify_Ext_connection_dut_as_Slave_C528652_C528657(ble_dut, ble_sniffer, remote_wiseconnect3, sl_collections,
                                        adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, random_address):
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, adv_async_required=True,  min_interval=min_interval, max_interval=max_interval,
                                    data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id, adv_handle=0,
                                    random_address=random_address,
                                    ble_sniffer=ble_sniffer, ble_client_address=ble_client_address, central=remote_wiseconnect3, scanning_phys= 5, connect=True, stop_scan=True,
                                    remote_addr_type=1 if random_address!=None else 0, dont_cleanup=True)
    if adv_type in [1]:
        # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[
                       (df['Advertising Mode'] == "Connectable Non-Scannable") &
                       (df['Aux Pointer'] == "Present") &
                       (df.apply(
                           lambda row: row['Ext Adv Address Type'] == ("random" if random_address != None else "public"),
                           axis=1))
                       ]) >= 1, "\n\n **** Test case Failed with no connectable non-scannable advertising mode found..! ****\n\n"
        logger().info(
            f"\n\n **** Connectable non-Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if random_address != None  else 'public'} ****\n\n")
    assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
        [37, 38, 39]) == False).all(), "\n\n **** Test case Failed with no AUX_SCAN_RSP packets found..! ****\n\n"
    logger().info("\n\n **** AUX_SCAN_RSP packets are not found ****\n\n")
    if pri_adv_phy in [3] and sec_adv_phy in [3]:
        # Assert if primary PHY is not LE Coded on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE Coded on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE Coded on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE Coded on AUX_ADV_IND packets ****\n\n")
        # Assert if there is no AUX_CONNECT_REQ packet found with 125k PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39])) & (df[
                                                                                                      '+PHY Type (LE BB)'] == "125k")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel and with phy rate 125k ****\n\n"
        logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel and with phy rate 125k ****\n\n")
        # Assert if there is no AUX_CONNECT_RSP packet found with 125k PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                                 39])) & (df[
                                                                                              '+PHY Type (LE BB)'] == "125k")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel and with phy rate 125k****\n\n"
    elif pri_adv_phy in [1] and sec_adv_phy in [1]:
        # Assert if primary PHY is not LE 1M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE 1M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE 1M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE 1M on AUX_ADV_IND packets ****\n\n")
        # Assert if there is no AUX_CONNECT_REQ packet found with 1M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39])) & (df[
                                                                                                      '+PHY Type (LE BB)'] == "1M")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel and with phy rate 1m ****\n\n"
        logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel and with phy rate 1m ****\n\n")
        # Assert if there is no AUX_CONNECT_RSP packet found with 1M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                                 39])) & (df[
                                                                                              '+PHY Type (LE BB)'] == "1M")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel and with phy rate 1m****\n\n"
    elif pri_adv_phy in [2] and sec_adv_phy in [2]:
        # Assert if primary PHY is not LE 2M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE 2M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE 2M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE 2M on AUX_ADV_IND packets ****\n\n")
        # Assert if there is no AUX_CONNECT_REQ packet found with 2M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39])) & (df[
                                                                                                      '+PHY Type (LE BB)'] == "2M")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel and with phy rate 2m ****\n\n"
        logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel and with phy rate 2m ****\n\n")
        # Assert if there is no AUX_CONNECT_RSP packet found with 2M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                                 39])) & (df[
                                                                                              '+PHY Type (LE BB)'] == "2M")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel and with phy rate 2m****\n\n"
    elif pri_adv_phy in [1] and sec_adv_phy in [2]:
        # Assert if primary PHY is not LE 1M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE 1M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE 2M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE 2M on AUX_ADV_IND packets ****\n\n")
        # Assert if there is no AUX_CONNECT_REQ packet found with 2M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39])) & (df['+PHY Type (LE BB)'] == "2M") ]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel and with phy rate 2m ****\n\n"
        logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel and with phy rate 2m ****\n\n")
        # Assert if there is no AUX_CONNECT_RSP packet found with 2M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                                 39])) & (df['+PHY Type (LE BB)'] == "2M") ]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel and with phy rate 2m****\n\n"
    logger().info("\n\n **** AUX_CONNECT_RSP packet found on secondary channel and with phy rate 2m ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

"""
    Test case category :BLE Ext connection with DUT for directed ext adv on DUT - Slave connection
    Device roles       : DUT is performing Peripheral role and Reference is performing Central role
"""
@pytest.mark.parametrize(
    "adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, random_address",
    [
        (5, 32, 40, "C528566", 1, 1, None),
        (5, 32, 40, "C528567", 1, 2, None),
        (5, 32, 40, "C528568", 3, 3, None),
    ],
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C528568')
def test_verify_Ext_connection_dut_as_Slave__directed_C528566_to_C528568(ble_dut, ble_sniffer, remote_wiseconnect3, sl_collections,
                                        adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, random_address):
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, adv_async_required=True,  min_interval=min_interval, max_interval=max_interval,
                                    data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id, adv_handle=0,
                                    random_address=random_address,
                                    ble_sniffer=ble_sniffer, ble_client_address=ble_client_address, central=remote_wiseconnect3, scanning_phys= 5, connect=True, stop_scan=True,
                                    remote_addr_type=1 if random_address!=None else 0, dont_cleanup=True)
    if adv_type in [5]:
        # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[
                       (df['Advertising Mode'] == "Connectable Non-Scannable") &
                       (df['Aux Pointer'] == "Present") &
                       (df.apply(
                           lambda row: row['Ext Adv Address Type'] == ("random" if random_address != None else "public"),
                           axis=1))
                       ]) >= 1, "\n\n **** Test case Failed with no connectable non-scannable advertising mode found..! ****\n\n"
        logger().info(
            f"\n\n **** Connectable non-Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if random_address != None  else 'public'} ****\n\n")
    assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
        [37, 38, 39]) == False).all(), "\n\n **** Test case Failed with no AUX_SCAN_RSP packets found..! ****\n\n"
    logger().info("\n\n **** AUX_SCAN_RSP packets are not found ****\n\n")
    if pri_adv_phy in [3] and sec_adv_phy in [3]:
        # Assert if primary PHY is not LE Coded on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE Coded on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE Coded on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE Coded on AUX_ADV_IND packets ****\n\n")
        # Assert if there is no AUX_CONNECT_REQ packet found with 125k PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39])) & (df[
                                                                                                      '+PHY Type (LE BB)'] == "125k")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel and with phy rate 125k ****\n\n"
        logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel and with phy rate 125k ****\n\n")
        # Assert if there is no AUX_CONNECT_RSP packet found with 125k PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                                 39])) & (df[
                                                                                              '+PHY Type (LE BB)'] == "125k")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel and with phy rate 125k****\n\n"
    elif pri_adv_phy in [1] and sec_adv_phy in [1]:
        # Assert if primary PHY is not LE 1M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE 1M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE 1M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE 1M on AUX_ADV_IND packets ****\n\n")
        # Assert if there is no AUX_CONNECT_REQ packet found with 1M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39])) & (df[
                                                                                                      '+PHY Type (LE BB)'] == "1M")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel and with phy rate 1m ****\n\n"
        logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel and with phy rate 1m ****\n\n")
        # Assert if there is no AUX_CONNECT_RSP packet found with 1M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                                 39])) & (df[
                                                                                              '+PHY Type (LE BB)'] == "1M")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel and with phy rate 1m****\n\n"
    elif pri_adv_phy in [2] and sec_adv_phy in [2]:
        # Assert if primary PHY is not LE 2M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE 2M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE 2M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE 2M on AUX_ADV_IND packets ****\n\n")
        # Assert if there is no AUX_CONNECT_REQ packet found with 2M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39])) & (df[
                                                                                                      '+PHY Type (LE BB)'] == "2M")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel and with phy rate 2m ****\n\n"
        logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel and with phy rate 2m ****\n\n")
        # Assert if there is no AUX_CONNECT_RSP packet found with 2M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                                 39])) & (df[
                                                                                              '+PHY Type (LE BB)'] == "2M")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel and with phy rate 2m****\n\n"
    elif pri_adv_phy in [1] and sec_adv_phy in [2]:
        # Assert if primary PHY is not LE 1M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE 1M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE 2M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE 2M on AUX_ADV_IND packets ****\n\n")
        # Assert if there is no AUX_CONNECT_REQ packet found with 2M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39])) & (df['+PHY Type (LE BB)'] == "2M") ]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel and with phy rate 2m ****\n\n"
        logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel and with phy rate 2m ****\n\n")
        # Assert if there is no AUX_CONNECT_RSP packet found with 2M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                                 39])) & (df['+PHY Type (LE BB)'] == "2M") ]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel and with phy rate 2m****\n\n"
    logger().info("\n\n **** AUX_CONNECT_RSP packet found on secondary channel and with phy rate 2m ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

@pytest.mark.parametrize(
    "adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, random_address, adv_filter_policy, scanning_filter_policy, initiator_filter_policy, init_phys",
    [
        (1, 32, 40, "C528569", 1, 1, None, 0, 1, 3, 1),
        (1, 32, 40, "C528570", 1, 2, None, 0, 1, 3, 3),
        (1, 32, 40, "C528571", 3, 3, None, 0, 1, 3, 4),
        (1, 32, 40, "C528572", 1, 1, "11:33:33:33:33:11", 0, 1, 3, 1),
        (1, 32, 40, "C528573", 1, 2, "11:33:33:33:33:11", 0, 1, 3, 3),
        (1, 32, 40, "C528574", 3, 3, "11:33:33:33:33:11", 0, 1, 3, 4),
    ],
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C528574')
def test_verify_Ext_connection_with_initiating_filter_policy_C528569_to_C528574(ble_dut, ble_sniffer, remote_wiseconnect3, sl_collections,
                                        adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, random_address, adv_filter_policy, scanning_filter_policy, initiator_filter_policy, init_phys):
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, adv_async_required=True,  min_interval=min_interval, max_interval=max_interval,
                                    data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id, adv_handle=0,
                                    random_address=random_address, init_phys=init_phys, adv_filter_policy=adv_filter_policy, scanning_filter_policy=scanning_filter_policy, initiator_filter_policy=initiator_filter_policy,
                                    ble_sniffer=ble_sniffer, ble_client_address=ble_client_address, central=remote_wiseconnect3, scanning_phys= 5, connect=True, stop_scan=True,
                                    remote_addr_type=1 if random_address!=None else 0, dont_cleanup=True)
    if adv_type in [1]:
        # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[
                       (df['Advertising Mode'] == "Connectable Non-Scannable") &
                       (df['Aux Pointer'] == "Present") &
                       (df.apply(
                           lambda row: row['Ext Adv Address Type'] == ("random" if random_address != None else "public"),
                           axis=1))
                       ]) >= 1, "\n\n **** Test case Failed with no connectable non-scannable advertising mode found..! ****\n\n"
        logger().info(
            f"\n\n **** Connectable non-Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if random_address != None  else 'public'} ****\n\n")
    assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
        [37, 38, 39]) == False).all(), "\n\n **** Test case Failed with no AUX_SCAN_RSP packets found..! ****\n\n"
    logger().info("\n\n **** AUX_SCAN_RSP packets are not found ****\n\n")
    if pri_adv_phy in [3] and sec_adv_phy in [3]:
        # Assert if primary PHY is not LE Coded on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE Coded on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE Coded on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE Coded on AUX_ADV_IND packets ****\n\n")
        # Assert if there is no AUX_CONNECT_REQ packet found with 125k PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39])) & (df[
                                                                                                      '+PHY Type (LE BB)'] == "125k")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel and with phy rate 125k ****\n\n"
        logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel and with phy rate 125k ****\n\n")
        # Assert if there is no AUX_CONNECT_RSP packet found with 125k PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                                 39])) & (df[
                                                                                              '+PHY Type (LE BB)'] == "125k")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel and with phy rate 125k****\n\n"
    elif pri_adv_phy in [1] and sec_adv_phy in [1]:
        # Assert if primary PHY is not LE 1M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE 1M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE 1M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE 1M on AUX_ADV_IND packets ****\n\n")
        # Assert if there is no AUX_CONNECT_REQ packet found with 1M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39])) & (df[
                                                                                                      '+PHY Type (LE BB)'] == "1M")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel and with phy rate 1m ****\n\n"
        logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel and with phy rate 1m ****\n\n")
        # Assert if there is no AUX_CONNECT_RSP packet found with 1M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                                 39])) & (df[
                                                                                              '+PHY Type (LE BB)'] == "1M")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel and with phy rate 1m****\n\n"
    elif pri_adv_phy in [2] and sec_adv_phy in [2]:
        # Assert if primary PHY is not LE 2M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE 2M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE 2M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE 2M on AUX_ADV_IND packets ****\n\n")
        # Assert if there is no AUX_CONNECT_REQ packet found with 2M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39])) & (df[
                                                                                                      '+PHY Type (LE BB)'] == "2M")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel and with phy rate 2m ****\n\n"
        logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel and with phy rate 2m ****\n\n")
        # Assert if there is no AUX_CONNECT_RSP packet found with 2M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                                 39])) & (df[
                                                                                              '+PHY Type (LE BB)'] == "2M")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel and with phy rate 2m****\n\n"
    elif pri_adv_phy in [1] and sec_adv_phy in [2]:
        # Assert if primary PHY is not LE 1M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE 1M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE 2M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE 2M on AUX_ADV_IND packets ****\n\n")
        # Assert if there is no AUX_CONNECT_REQ packet found with 2M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39])) & (df['+PHY Type (LE BB)'] == "2M") ]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel and with phy rate 2m ****\n\n"
        logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel and with phy rate 2m ****\n\n")
        # Assert if there is no AUX_CONNECT_RSP packet found with 2M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                                 39])) & (df['+PHY Type (LE BB)'] == "2M") ]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel and with phy rate 2m****\n\n"
    logger().info("\n\n **** AUX_CONNECT_RSP packet found on secondary channel and with phy rate 2m ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

"""
    Test case category :BLE Ext Central connection with different min and max connection intervals. 
    Device roles       : DUT is performing Peripheral role and Reference is performing Central role
"""
@pytest.mark.parametrize(
    "adv_type, ConnIntervalMin, ConnIntervalMax, test_case_id, pri_adv_phy, sec_adv_phy, random_address, init_phys, connection_time",
    [
        (1, 80, 160, "C528646", 1, 1, None, 1, 900),
        (1, 80, 160, "C528647", 1, 2, None, 3, 900),
        (1, 80, 160, "C528648", 3, 3, None, 4, 900),
        (1, 6, 6, "C538061", 3, 3, None, 4, 300),
        (1, 3200, 3200, "C538062", 3, 3, None, 4, 300),
    ],
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C538062')
def test_verify_Ext_connection_with_diff_min_max_interval_C528646_to_C528648_C538061_C538062(ble_dut, ble_sniffer, remote_wiseconnect3, sl_collections, ConnIntervalMin, ConnIntervalMax,
                                        adv_type, test_case_id, pri_adv_phy, sec_adv_phy, random_address, init_phys, connection_time):
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=0)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=0)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, adv_async_required=True,  min_interval=32, max_interval=40,
                                    data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id, adv_handle=0,
                                    random_address=random_address, init_phys=init_phys, connection_time=connection_time, ConnIntervalMin=ConnIntervalMin, ConnIntervalMax=ConnIntervalMax,
                                    ble_sniffer=ble_sniffer, ble_client_address=ble_client_address, central=remote_wiseconnect3, scanning_phys= 5, connect=True, stop_scan=True,
                                    remote_addr_type=1 if random_address!=None else 0, dont_cleanup=True)
    if adv_type in [1]:
        # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[
                       (df['Advertising Mode'] == "Connectable Non-Scannable") &
                       (df['Aux Pointer'] == "Present") &
                       (df.apply(
                           lambda row: row['Ext Adv Address Type'] == ("random" if random_address != None else "public"),
                           axis=1))
                       ]) >= 1, "\n\n **** Test case Failed with no connectable non-scannable advertising mode found..! ****\n\n"
        logger().info(
            f"\n\n **** Connectable non-Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if random_address != None  else 'public'} ****\n\n")
    assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
        [37, 38, 39]) == False).all(), "\n\n **** Test case Failed with no AUX_SCAN_RSP packets found..! ****\n\n"
    logger().info("\n\n **** AUX_SCAN_RSP packets are not found ****\n\n")
    if pri_adv_phy in [3] and sec_adv_phy in [3]:
        # Assert if primary PHY is not LE Coded on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE Coded on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE Coded on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '125k').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE Coded on AUX_ADV_IND packets ****\n\n")
        # Assert if there is no AUX_CONNECT_REQ packet found with 125k PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39])) & (df[
                                                                                                      '+PHY Type (LE BB)'] == "125k")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel and with phy rate 125k ****\n\n"
        logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel and with phy rate 125k ****\n\n")
        # Assert if there is no AUX_CONNECT_RSP packet found with 125k PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                                 39])) & (df[
                                                                                              '+PHY Type (LE BB)'] == "125k")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel and with phy rate 125k****\n\n"
    elif pri_adv_phy in [1] and sec_adv_phy in [1]:
        # Assert if primary PHY is not LE 1M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE 1M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE 1M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE 1M on AUX_ADV_IND packets ****\n\n")
        # Assert if there is no AUX_CONNECT_REQ packet found with 1M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39])) & (df[
                                                                                                      '+PHY Type (LE BB)'] == "1M")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel and with phy rate 1m ****\n\n"
        logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel and with phy rate 1m ****\n\n")
        # Assert if there is no AUX_CONNECT_RSP packet found with 1M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                                 39])) & (df[
                                                                                              '+PHY Type (LE BB)'] == "1M")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel and with phy rate 1m****\n\n"
    elif pri_adv_phy in [2] and sec_adv_phy in [2]:
        # Assert if primary PHY is not LE 2M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE 2M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE 2M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE 2M on AUX_ADV_IND packets ****\n\n")
        # Assert if there is no AUX_CONNECT_REQ packet found with 2M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39])) & (df[
                                                                                                      '+PHY Type (LE BB)'] == "2M")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel and with phy rate 2m ****\n\n"
        logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel and with phy rate 2m ****\n\n")
        # Assert if there is no AUX_CONNECT_RSP packet found with 2M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                                 39])) & (df[
                                                                                              '+PHY Type (LE BB)'] == "2M")]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel and with phy rate 2m****\n\n"
    elif pri_adv_phy in [1] and sec_adv_phy in [2]:
        # Assert if primary PHY is not LE 1M on ADV_EXT_IND packets
        assert (df[df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with no ADV_EXT_IND packets found..! ****\n\n"
        logger().info("\n\n **** Primary PHY is LE 1M on ADV_EXT_IND packets ****\n\n")
        # Assert if secondary PHY is not LE 2M on AUX_ADV_IND packets
        assert (df[~df['Chan'].isin([37, 38, 39])][
                    '+PHY Type (LE BB)'] == '2M').any(), "\n\n **** Test case Failed with no AUX_ADV_IND packets found..! ****\n\n"
        logger().info("\n\n **** Secondary PHY is LE 2M on AUX_ADV_IND packets ****\n\n")
        # Assert if there is no AUX_CONNECT_REQ packet found with 2M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_REQ") & (~df['Chan'].isin([37, 38, 39])) & (df['+PHY Type (LE BB)'] == "2M") ]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_REQ packet found on secondary channel and with phy rate 2m ****\n\n"
        logger().info("\n\n **** AUX_CONNECT_REQ packet found on secondary channel and with phy rate 2m ****\n\n")
        # Assert if there is no AUX_CONNECT_RSP packet found with 2M PHY and on secondary channel
        assert len(df.loc[(df['Type'] == "AUX_CONNECT_RSP") & (~df['Chan'].isin([37, 38,
                                                                                 39])) & (df['+PHY Type (LE BB)'] == "2M") ]) >= 1, "\n\n **** Test case Failed with no AUX_CONNECT_RSP packet found on secondary channel and with phy rate 2m****\n\n"
    logger().info("\n\n **** AUX_CONNECT_RSP packet found on secondary channel and with phy rate 2m ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")