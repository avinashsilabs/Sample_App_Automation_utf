import pytest
import pandas as pd
import re
import pdb
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

from utf.interfaces.bluetooth import BLEDeviceState
from utf.utf_config import UtfConfig
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.logger import get_logger
from utf.interfaces.wifi import WlanError
import time, os
import threading
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from datetime import timedelta, datetime
from utf.utils.stopwatch import Stopwatch
import random
import string



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
        Kagitha Srinivasarao
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
        df['Timestamp'] = df['Timestamp'].apply(
            lambda x: re.search(r"\d+:\d+:\d+\.\d+", x.strftime('%Y-%m-%d %H:%M:%S.%f')).group())
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
@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C535821", 1, 1),
    ],
)
@pytest.mark.check()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.parametrize("periodic_data_len, adv_handle", [(30, 0)])
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C535821')
def test_verify_periodic_scanning_by_adding_ref_device_in_periodic_list_C535821(ble_dut, ble_sniffer, sl_collections,  remote_wiseconnect3, adv_type, periodic_data_len, adv_handle,test_case_id, pri_adv_phy,
                                                                               sec_adv_phy):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        random_address = "11:44:33:AA:BB:CC"
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        df = sl_collections.start_periodic_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                               pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=200,
                                               scan_resp_len=1,
                                               test_case_id=test_case_id, random_address_s2=True,
                                               random_address=random_address,
                                               adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                               ble_sniffer=ble_sniffer, powersave_p=True, adv_type_s2=127, adv_data_type=2,
                                               periodic_data_len=200)
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0,
            scanning_filter_policy=0,
            scanning_phys=1,  # 4 for 2M ph
            scan_type_sec=1,
            ScanInterval=48,
            ScanWindow=48,
            scan_type=1,
            remote_addr_type=0,
            scan_interval_sec=48,
            scan_window_sec=30
        )
        logger().info("*** Initiating ae_set_scan_enable ***")
        ble_dut_address = random_address
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_dut_address  # Use public address
        )
        logger().info(f"\n\n *** periodic list ***\n\n")
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_dev_to_periodic_list(
            remote_dev_addr=ble_dut_address,
            adv_addr_type=1,  # 0 for pabulic
            adv_sid=0,
            type=1
        )
        logger().info(f"\n\n *** Scanning status: {status} ***\n\n")
        if status is None:
            logger().info('successfully added to periodic list')
        else:
            logger().info('device not added to periodic list')
            assert False
        logger().info("***********stoping scan")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_client_address
        )
        logger().info("***********stoping advertise")
        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_enable=0
        )
    except Exception as e:
        logger().info(f'e--{e}')
        assert False
@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C539208", 1, 1),
    ],
)
@pytest.mark.check()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.parametrize("periodic_data_len, adv_handle", [(30, 0)])
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C539208')
def test_verify_periodic_scanning_by_enabling_Duplicate_filtering_bit_C539208(ble_dut, ble_sniffer, sl_collections,  remote_wiseconnect3, adv_type, periodic_data_len, adv_handle,test_case_id, pri_adv_phy,
                                                                               sec_adv_phy):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        random_address = "11:44:33:AA:BB:CC"
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        
        df = sl_collections.start_periodic_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                               pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=200,
                                               scan_resp_len=1,
                                               test_case_id=test_case_id, random_address_s2=True,
                                               random_address=random_address,
                                               adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                               ble_sniffer=ble_sniffer, powersave_p=True, adv_type_s2=127,
                                               adv_data_type=2, periodic_data_len=200)
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0,
            scanning_filter_policy=0,
            scanning_phys=1,  # 4 for 2M ph
            scan_type_sec=1,
            ScanInterval=48,
            ScanWindow=48,
            scan_type=1,
            remote_addr_type=0,
            scan_interval_sec=48,
            scan_window_sec=30
        )
        logger().info("*** Initiating ae_set_scan_enable ***")
        ble_dut_address = random_address
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_dut_address  # Use public address
        )
        logger().info(f"\n\n *** periodic list ***\n\n")
        remote_wiseconnect3.interfaces.wifi.ble_ae_dev_to_periodic_list(
            remote_dev_addr=ble_dut_address,
            adv_addr_type=1,  # 0 for pabulic
            adv_sid=0,
            type=1
        )
        BLE_AE_PERIODIC_LIST_USED = 1
        BLE_AE_REPORTING_ENABLED = 0
        BLE_AE_PERODIC_DUPLICATE_FILTERING_ENABLED = 1
        logger().info(
            f'(ble_param1 | ble_param2 << 1 | ble_param3 << 2), {(BLE_AE_PERIODIC_LIST_USED | BLE_AE_REPORTING_ENABLED << 1 | BLE_AE_PERODIC_DUPLICATE_FILTERING_ENABLED << 2)}')

        BLE_AE_PERIODIC_LIST_USED = 1
        BLE_AE_REPORTING_ENABLED = 1
        BLE_AE_PERODIC_DUPLICATE_FILTERING_ENABLED = 0
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=(
                        BLE_AE_PERIODIC_LIST_USED | BLE_AE_REPORTING_ENABLED << 1 | BLE_AE_PERODIC_DUPLICATE_FILTERING_ENABLED << 2),
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=0
        )
        time.sleep(180)
        count = 0
        events = remote_wiseconnect3.interfaces.wifi.get_async_events()
        for event in events:
            count = count + 1
            logger().info(f'{event.event_data}{count}')
            z = re.findall(r'AE Periodic Adv Report Event', event.event_data)
            logger().info(f'z is {z}')
            if 'AE Periodic Adv Report Event' in event.event_data:
                logger().info(' successfully got AE Periodic Adv Report Event in event.event_data')
            assert 'AE Periodic Adv Report Event' in event.event_data

        logger().info(f" count= {count}")
        for event in events:
            z = re.findall(r'AE Periodic Adv Report Event', event.event_data)
            logger().info(f'z is {z}')
        events = remote_wiseconnect3.interfaces.wifi.get_async_events()
        adv_reports = [e for e in events if 'AE Periodic Adv Report Event' in e.events.data]
        logger().info("***********stoping scan")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_client_address
        )
        logger().info("***********stoping advertise")
        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_enable=0
        )

    except Exception as e:
        logger().info(f'e is --->{e}')
        assert False
@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C539209", 1, 1),
    ],
)

@pytest.mark.check()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.parametrize("periodic_data_len, adv_handle", [(30, 0)])
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C539209')
def test_Verify_periodic_scanning_by_disabling_reporting_bit_C539209(ble_dut, ble_sniffer, sl_collections,  remote_wiseconnect3, adv_type, periodic_data_len, adv_handle,test_case_id, pri_adv_phy,
                                                                               sec_adv_phy):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        random_address = "11:44:33:AA:BB:CC"
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        df = sl_collections.start_periodic_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                               pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=200,
                                               scan_resp_len=1,
                                               test_case_id=test_case_id, random_address_s2=True,
                                               random_address=random_address,
                                               adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                               ble_sniffer=ble_sniffer, powersave_p=True, adv_type_s2=127,
                                               adv_data_type=2, periodic_data_len=200)
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0,
            scanning_filter_policy=0,
            scanning_phys=1,  # 4 for 2M ph
            scan_type_sec=1,
            ScanInterval=48,
            ScanWindow=48,
            scan_type=1,
            remote_addr_type=0,
            scan_interval_sec=48,
            scan_window_sec=30
        )
        logger().info("*** Initiating ae_set_scan_enable ***")
        ble_dut_address = random_address
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_dut_address  # Use public address
        )
        logger().info(f"\n\n *** periodic list ***\n\n")
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_dev_to_periodic_list(
            remote_dev_addr=ble_dut_address,
            adv_addr_type=1,  # 0 for pabulic
            adv_sid=0,
            type=1
        )
        BLE_AE_PERIODIC_LIST_USED = 0
        BLE_AE_REPORTING_ENABLED = 1
        BLE_AE_PERODIC_DUPLICATE_FILTERING_ENABLED = 0
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=1,  # 1 i need check #0 before
            fil_policy=(BLE_AE_PERIODIC_LIST_USED | BLE_AE_REPORTING_ENABLED << 1 | BLE_AE_PERODIC_DUPLICATE_FILTERING_ENABLED << 2),
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=0
        )
        
        logger().info(f"Periodic sync created successfully 134 sec{ble_dut_address} {ble_client_address}")
        time.sleep(180)
        events = remote_wiseconnect3.interfaces.wifi.get_async_events()
        for event in events:
            z = re.findall(r'AE Periodic Adv Report Event', event.event_data)
            logger().info(f'z is {z}')
            if 'AE Periodic Adv Report Event' in event.event_data:
                logger().info(' successfully got AE Periodic Adv Report Event in event.event_data')
            assert 'AE Periodic Adv Report Event' not in event.event_data
        logger().info(f"Async events: {events}")
        logger().info("***********stoping scan")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_client_address
        )
        logger().info("***********stoping advertise")
        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_enable=0
        )
        time.sleep(2)
        events = remote_wiseconnect3.interfaces.wifi.get_async_events()
    except Exception as e:
        logger().info(f'{e}')
        assert False
@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C539207", 1, 1),
    ],
)

@pytest.mark.check()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.parametrize("periodic_data_len, adv_handle", [(30, 0)])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C539207')
def test_verify_periodic_scanning_by_disabling_Duplicate_filtering_bit_C539207(ble_dut, ble_sniffer, sl_collections,  remote_wiseconnect3, adv_type, periodic_data_len, adv_handle,test_case_id, pri_adv_phy,
                                                                               sec_adv_phy ):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        random_address = "11:44:33:AA:BB:CC"
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        df = sl_collections.start_periodic_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                               pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=200,
                                               scan_resp_len=1,
                                               test_case_id=test_case_id, random_address_s2=True,
                                               random_address=random_address,
                                               adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                               ble_sniffer=ble_sniffer, powersave_p=True, adv_type_s2=127,
                                               adv_data_type=2, periodic_data_len=200)
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0,
            scanning_filter_policy=0,
            scanning_phys=1,  # 4 for 2M ph
            scan_type_sec=1,
            ScanInterval=48,
            ScanWindow=48,
            scan_type=1,
            remote_addr_type=0,
            scan_interval_sec=48,
            scan_window_sec=30
        )
        logger().info("*** Initiating ae_set_scan_enable ***")
        ble_dut_address = random_address
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=5,
            duration=0,
            period=0,
            remote_address=ble_dut_address  # Use public address
        )
        logger().info(f"\n\n *** periodic list ***\n\n")
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_dev_to_periodic_list(
            remote_dev_addr=ble_dut_address,
            adv_addr_type=1,  # 0 for pabulic
            adv_sid=0,
            type=1
        )
        logger().info(f"\n\n *** Scanning status: {status} ***\n\n")

        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=5,
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=0
        )
        logger().info(f"Periodic sync created successfully 180 sec{ble_dut_address} {ble_client_address}")
        time.sleep(180)
        events = remote_wiseconnect3.interfaces.wifi.get_async_events()
        for event in events:
            if 'AE Periodic Adv Report Event' in event.event_data:
                logger().info(' successfully got AE Periodic Adv Report Event in event.event_data')
            assert 'AE Periodic Adv Report Event' in event.event_data

        logger().info(f"\n\n terminating sync")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=0,
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=2
        )
        logger().info("***********stoping scan")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_client_address
        )
        logger().info("***********stoping advertise")
        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_enable=0
        )
    except Exception as e:
        logger().info(f'{e}')
        assert False
@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C539211", 1, 1),
    ],
)

@pytest.mark.check()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.parametrize("periodic_data_len, adv_handle", [(30, 0)])
@pytest.mark.ble_sniffer("frontline_sniffer")
def skip_test_Verify_BLE_AE_Periodic_scanning_by_configuring_the_min_Sync_Timeout_values_C539211(ble_dut, ble_sniffer, sl_collections,  remote_wiseconnect3, adv_type, periodic_data_len, adv_handle,test_case_id, pri_adv_phy,
                                                                               sec_adv_phy):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        random_address = "11:44:33:AA:BB:CC"
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        df = sl_collections.start_periodic_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                               pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=200,
                                               scan_resp_len=1,
                                               test_case_id=test_case_id, random_address_s2=True,
                                               random_address=random_address,
                                               adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                               ble_sniffer=ble_sniffer, powersave_p=True, adv_type_s2=127,
                                               adv_data_type=2,
                                               periodic_data_len=200)
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0,
            scanning_filter_policy=0,
            scanning_phys=1,  # 4 for 2M ph
            scan_type_sec=1,
            ScanInterval=48,
            ScanWindow=48,
            scan_type=1,
            remote_addr_type=0,
            scan_interval_sec=48,
            scan_window_sec=30
        )
        logger().info("*** Initiating ae_set_scan_enable ***")
        ble_dut_address = random_address
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_dut_address  # Use public address
        )
        logger().info(f"\n\n *** periodic list ***\n\n")
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_dev_to_periodic_list(
            remote_dev_addr=ble_dut_address,
            adv_addr_type=1,  # 0 for pabulic
            adv_sid=0,
            type=1
        )
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=5,
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=0
        )
        logger().info(f"Periodic sync created successfully 180 sec{ble_dut_address} {ble_client_address}")
        logger().info("***********stoping advertise")
        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_enable=0
        )
        time.sleep(180)
        events = remote_wiseconnect3.interfaces.wifi.get_async_events()
        for event in events:
            if 'AE Periodic Adv Report Event' in event.event_data:
                logger().info(' successfully got AE Periodic Adv Report Event in event.event_data')
            assert 'AE Periodic Adv Report Event' in event.event_data
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=5,
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=2
        )
        logger().info("***********stoping scan")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_client_address
        )
    except Exception as e:
        logger().info(f'{e}')
        assert False
@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C539211_1", 1, 1),
    ],
)
@pytest.mark.check()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.parametrize("periodic_data_len, adv_handle", [(30, 0)])
@pytest.mark.ble_sniffer("frontline_sniffer")
def skip_test_Verify_BLE_AE_Periodic_scanning_by_configuring_the_max_Sync_Timeout_values_C539211_1(ble_dut, ble_sniffer,
                                                                                                sl_collections,
                                                                                                remote_wiseconnect3,
                                                                                                adv_type,
                                                                                                periodic_data_len,
                                                                                                adv_handle,
                                                                                                test_case_id,
                                                                                                pri_adv_phy,
                                                                                                sec_adv_phy):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        random_address = "11:44:33:AA:BB:CC"
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        df = sl_collections.start_periodic_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                               pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=200,
                                               scan_resp_len=1,
                                               test_case_id=test_case_id, random_address_s2=True,
                                               random_address=random_address,
                                               adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                               ble_sniffer=ble_sniffer, powersave_p=True, adv_type_s2=127,
                                               adv_data_type=2,
                                               periodic_data_len=200)
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0,
            scanning_filter_policy=0,
            scanning_phys=1,  # 4 for 2M ph
            scan_type_sec=1,
            ScanInterval=48,
            ScanWindow=48,
            scan_type=1,
            remote_addr_type=0,
            scan_interval_sec=48,
            scan_window_sec=30
        )
        logger().info("*** Initiating ae_set_scan_enable ***")
        ble_dut_address = random_address
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_dut_address  # Use public address
        )
        logger().info(f"\n\n *** periodic list ***\n\n")
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_dev_to_periodic_list(
            remote_dev_addr=ble_dut_address,
            adv_addr_type=1,  # 0 for pabulic
            adv_sid=0,
            type=1
        )
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=4,
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=0
        )
        logger().info(f"Periodic sync created successfully 180 sec{ble_dut_address} {ble_client_address}")
        logger().info("***********stoping advertise")
        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_enable=0
        )
        time.sleep(180)
        events = remote_wiseconnect3.interfaces.wifi.get_async_events()
        for event in events:
            if 'AE Periodic Adv Report Event' in event.event_data:
                logger().info(' successfully got AE Periodic Adv Report Event in event.event_data')
            assert 'AE Periodic Adv Report Event' in event.event_data

        remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=5,
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=2
        )
        logger().info("***********stoping scan")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_client_address
        )
    except Exception as e:
        logger().info(f'{e}')
        assert False

@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C539212", 1, 1),
    ],
)
@pytest.mark.check()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.parametrize("periodic_data_len, adv_handle", [(30, 0)])
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C539212')
def test_Verify_the_functionality_of_LE_Periodic_Advertising_Create_cancel_Sync_when_advertising_is_disabled_C539212(ble_dut, ble_sniffer, sl_collections,  remote_wiseconnect3, adv_type, periodic_data_len, adv_handle,test_case_id, pri_adv_phy,
                                                                               sec_adv_phy):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        random_address = "11:44:33:AA:BB:CC"
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        df = sl_collections.start_periodic_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                               pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=200,
                                               scan_resp_len=1,
                                               test_case_id=test_case_id, random_address_s2=True,
                                               random_address=random_address,
                                               adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                               ble_sniffer=ble_sniffer, powersave_p=True, adv_type_s2=127,
                                               adv_data_type=2, periodic_data_len=200)
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0,
            scanning_filter_policy=0,
            scanning_phys=1,  # 4 for 2M ph
            scan_type_sec=1,
            ScanInterval=48,
            ScanWindow=48,
            scan_type=1,
            remote_addr_type=0,
            scan_interval_sec=48,
            scan_window_sec=30
        )
        logger().info("*** Initiating ae_set_scan_enable ***")
        ble_dut_address = random_address
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_dut_address  # Use public address
        )
        logger().info(f"\n\n *** periodic list ***\n\n")
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_dev_to_periodic_list(
            remote_dev_addr=ble_dut_address,
            adv_addr_type=1,  # 0 for pabulic
            adv_sid=0,
            type=1
        )
        logger().info("***********stoping advertise")
        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_enable=0
        )
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=5,
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=0
        )
        success = remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=5,
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=1
        )
        assert success is None, "sunc cancel is failed"
        logger().info(f"sync cancel status success")
        logger().info("***********stoping scan")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_client_address
        )
    except Exception as e:
        logger().info(f'{e}')
        assert False
@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C539213", 1, 1),
    ],
)
@pytest.mark.check()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.parametrize("periodic_data_len, adv_handle", [(30, 0)])
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C539213')
def test_Verify_the_functionality_of_LE_Periodic_Advertising_Create_terminate_Sync_when_advertising_is_disabled_C539213(ble_dut, ble_sniffer, sl_collections,  remote_wiseconnect3, adv_type, periodic_data_len, adv_handle,test_case_id, pri_adv_phy,
                                                                               sec_adv_phy):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        random_address = "11:44:33:AA:BB:CC"
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        df = sl_collections.start_periodic_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                               pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=200,
                                               scan_resp_len=1,
                                               test_case_id=test_case_id, random_address_s2=True,
                                               random_address=random_address,
                                               adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                               ble_sniffer=ble_sniffer, powersave_p=True, adv_type_s2=127,
                                               adv_data_type=2, periodic_data_len=200)
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0,
            scanning_filter_policy=0,
            scanning_phys=1,  # 4 for 2M ph
            scan_type_sec=1,
            ScanInterval=48,
            ScanWindow=48,
            scan_type=1,
            remote_addr_type=0,
            scan_interval_sec=48,
            scan_window_sec=30
        )
        logger().info("*** Initiating ae_set_scan_enable ***")
        ble_dut_address = random_address
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_dut_address  # Use public address
        )
        logger().info(f"\n\n *** periodic list ***\n\n")
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_dev_to_periodic_list(
            remote_dev_addr=ble_dut_address,
            adv_addr_type=1,  # 0 for pabulic
            adv_sid=0,
            type=1
        )
        logger().info("***********stoping advertise")
        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_enable=0
        )
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=5,
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=0
        )
        logger().info(f"Periodic sync created successfully 40 sec{ble_dut_address} {ble_client_address}")
        time.sleep(40)
        logger().info(f"\n\n terminating sync")
        try:
            status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
                remote_dev_addr=ble_dut_address,  # Use public address
                adv_addr_type=1,  # 0 = public address
                adv_sid=0,  # 1 i need check #0 before
                fil_policy=5,
                skip=0,
                sync_timeout=48,
                BLE_AE_PER_SYNC=2
            )
            if '0x4e42' in status:
                logger.info(' successfully got 0x4e42 error')
            assert '0x4e42' not in status
        except Exception as e:
            logger().info(f'{e}')
        logger().info("***********stoping scan")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_client_address
        )
    except Exception as e:
        logger().info(f'{e}')
        assert False
@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C656067", 1, 1),
    ],
)
@pytest.mark.check()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.parametrize("periodic_data_len, adv_handle", [(30, 0)])
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C656067')
def test_Verify_the_functionality_of_LE_Periodic_Advertising_Create_Cancel_Sync_when_advertising_is_enabled_C656067(ble_dut, ble_sniffer, sl_collections,  remote_wiseconnect3, adv_type, periodic_data_len, adv_handle,test_case_id, pri_adv_phy,
                                                                               sec_adv_phy):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        random_address = "11:44:33:AA:BB:CC"
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        df = sl_collections.start_periodic_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                               pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=200,
                                               scan_resp_len=1,
                                               test_case_id=test_case_id, random_address_s2=True,
                                               random_address=random_address,
                                               adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                               ble_sniffer=ble_sniffer, powersave_p=True, adv_type_s2=127, adv_data_type=2,
                                               periodic_data_len=200)
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0,
            scanning_filter_policy=0,
            scanning_phys=1,  # 4 for 2M ph
            scan_type_sec=1,
            ScanInterval=48,
            ScanWindow=48,
            scan_type=1,
            remote_addr_type=0,
            scan_interval_sec=48,
            scan_window_sec=30
        )
        logger().info("*** Initiating ae_set_scan_enable ***")
        ble_dut_address = random_address
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_dut_address  # Use public address
        )
        logger().info(f"\n\n *** periodic list ***\n\n")
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_dev_to_periodic_list(
            remote_dev_addr=ble_dut_address,
            adv_addr_type=1,  # 0 for pabulic
            adv_sid=0,
            type=1
        )
        logger().info(f"\n\n *** Scanning status: {status} ***\n\n")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=5,
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=0
        )
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=5,
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=1
        )
        logger().info("***********stoping scan")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_client_address
        )
        logger().info("***********stoping advertise")
        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_enable=0
        )
        events = ble_dut.interfaces.bluetooth.get_async_events()
    except Exception as e:
        logger().info(f'e--->{e}')
        assert False
@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C656068", 1, 1),
    ],
)
@pytest.mark.check()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.parametrize("periodic_data_len, adv_handle", [(30, 0)])
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C656068')
def test_Verify_the_functionality_of_LE_Periodic_Advertising_Create_terminate_Sync_when_advertising_is_enabled_C656068(ble_dut, ble_sniffer, sl_collections,  remote_wiseconnect3, adv_type, periodic_data_len, adv_handle,test_case_id, pri_adv_phy,
                                                                               sec_adv_phy):

    try:
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=periodic_data_len))
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        random_address = "11:44:33:AA:BB:CC"
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        df = sl_collections.start_periodic_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                       pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=200, scan_resp_len=1,
                                       test_case_id=test_case_id,random_address_s2=True,random_address=random_address,
                                       adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                       ble_sniffer=ble_sniffer, powersave_p=True, adv_type_s2 = 127, adv_data_type=2, periodic_data_len=200)
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
              ble_addr_type=0,
              scanning_filter_policy=0,
              scanning_phys=1,#4 for 2M ph
              scan_type_sec=1,
              ScanInterval=48,
              ScanWindow=48,
              scan_type=1,
              remote_addr_type=0,
              scan_interval_sec=48,
              scan_window_sec=30
          )
        logger().info("*** Initiating ae_set_scan_enable ***")
        ble_dut_address=random_address
        status=remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
              enable=1,
              filter_duplicates=0,
              duration=0,
              period=0,
              remote_address=ble_dut_address  # Use public address
          )
        logger().info(f"\n\n *** periodic list ***\n\n")
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_dev_to_periodic_list(
            remote_dev_addr=ble_dut_address,
            adv_addr_type=1,      # 0 for pabulic
            adv_sid=0,
            type=1
        )
        logger().info(f"\n\n *** Scanning status: {status} ***\n\n")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
              remote_dev_addr=ble_dut_address,  # Use public address
              adv_addr_type=1,  # 0 = public address
              adv_sid=0, #1 i need check #0 before
              fil_policy=5,
              skip=0,
              sync_timeout=48,
              BLE_AE_PER_SYNC=0
          )
        logger().info(f"Periodic sync created successfully 180 sec{ble_dut_address} {ble_client_address}")
        time.sleep(180)
        events = ble_dut.interfaces.bluetooth.get_async_events()
        for event in events:
            # logger().info(f'{event.event_data}')
            if 'AE Periodic Adv Report Event' in event.event_data:
                logger().info(' successfully got AE Periodic Adv Report Event in event.event_data')
            assert 'AE Periodic Adv Report Event' in event.event_data
        logger().info(f"\n\n terminating sync")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=0,
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=2
        )
        logger().info("***********stoping scan")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_client_address
        )
        logger().info("***********stoping advertise")
        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address= ble_dut_address,
            adv_enable=0
        )
    except Exception as e:
        logger().info(f"{e}")
        assert False
@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C539210", 1, 1),
        #(0, "C528650", 1, 2),
        #(0, "C528651", 3, 3),
    ],
)
@pytest.mark.check()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.parametrize("periodic_data_len, adv_handle", [(30, 0)])
@pytest.mark.ble_sniffer("frontline_sniffer")
def skip_test_Verify_BLE_AE_Periodic_scanning_by_configuring_the_min_Skip_values_C539210(ble_dut, ble_sniffer, sl_collections,  remote_wiseconnect3, adv_type, periodic_data_len, adv_handle,test_case_id, pri_adv_phy,
                                                                               sec_adv_phy):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        random_address = "11:44:33:AA:BB:CC"
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        df = sl_collections.start_periodic_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                               pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=200,
                                               scan_resp_len=1,
                                               test_case_id=test_case_id, random_address_s2=True,
                                               random_address=random_address,
                                               adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                               ble_sniffer=ble_sniffer, powersave_p=True, adv_type_s2=127,
                                               adv_data_type=2,
                                               periodic_data_len=200)
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0,
            scanning_filter_policy=0,
            scanning_phys=1,  # 4 for 2M ph
            scan_type_sec=1,
            ScanInterval=48,
            ScanWindow=48,
            scan_type=1,
            remote_addr_type=0,
            scan_interval_sec=48,
            scan_window_sec=30
        )
        logger().info("*** Initiating ae_set_scan_enable ***")
        ble_dut_address = random_address
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_dut_address  # Use public address
        )
        logger().info(f"\n\n *** periodic list ***\n\n")
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_dev_to_periodic_list(
            remote_dev_addr=ble_dut_address,
            adv_addr_type=1,  # 0 for pabulic
            adv_sid=0,
            type=1
        )
        # logger().info(f"\n\n *** Scanning status: {status} ***\n\n")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=4,
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=0
        )
        logger().info(f"Periodic sync created successfully 180 sec{ble_dut_address} {ble_client_address}")
        time.sleep(180)
        events = remote_wiseconnect3.interfaces.wifi.get_async_events()
        for event in events:
            if 'AE Periodic Adv Report Event' in event.event_data:
                logger().info(' successfully got AE Periodic Adv Report Event in event.event_data')
            assert 'AE Periodic Adv Report Event' in event.event_data
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=5,
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=2
        )
        logger().info("***********stoping scan")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_client_address
        )
        logger().info("***********stoping advertise")
        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_enable=0
        )
    except Exception as e:
        logger().info(f'{e}')
        assert False
@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C539210_1", 1, 1),
    ],
)

@pytest.mark.check()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.parametrize("periodic_data_len, adv_handle", [(30, 0)])
@pytest.mark.ble_sniffer("frontline_sniffer")
def skip_test_Verify_BLE_AE_Periodic_scanning_by_configuring_the_max_Skip_values_C539210_1(ble_dut, ble_sniffer, sl_collections,  remote_wiseconnect3, adv_type, periodic_data_len, adv_handle,test_case_id, pri_adv_phy,
                                                                               sec_adv_phy):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        random_address = "11:44:33:AA:BB:CC"
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        df = sl_collections.start_periodic_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                               pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=200,
                                               scan_resp_len=1,
                                               test_case_id=test_case_id, random_address_s2=True,
                                               random_address=random_address,
                                               adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                               ble_sniffer=ble_sniffer, powersave_p=True, adv_type_s2=127,
                                               adv_data_type=2,
                                               periodic_data_len=200)
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0,
            scanning_filter_policy=0,
            scanning_phys=1,  # 4 for 2M ph
            scan_type_sec=1,
            ScanInterval=48,
            ScanWindow=48,
            scan_type=1,
            remote_addr_type=0,
            scan_interval_sec=48,
            scan_window_sec=30
        )
        logger().info("*** Initiating ae_set_scan_enable ***")
        ble_dut_address = random_address
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_dut_address  # Use public address
        )
        logger().info(f"\n\n *** periodic list ***\n\n")
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_dev_to_periodic_list(
            remote_dev_addr=ble_dut_address,
            adv_addr_type=1,  # 0 for pabulic
            adv_sid=0,
            type=1
        )
        logger().info(f"\n\n *** Scanning status: {status} ***\n\n")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=4,
            skip=499,
            sync_timeout=48,
            BLE_AE_PER_SYNC=0
        )
        logger().info(f"Periodic sync created successfully waiting 180 sec{ble_dut_address} {ble_client_address}")
        time.sleep(180)
        events = remote_wiseconnect3.interfaces.wifi.get_async_events()
        for event in events:
            if 'AE Periodic Adv Report Event' in event.event_data:
                logger().info(' successfully got AE Periodic Adv Report Event in event.event_data')
            assert 'AE Periodic Adv Report Event' in event.event_data
        logger().info(f"\n\n terminating sync")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=5,
            skip=499,
            sync_timeout=48,
            BLE_AE_PER_SYNC=2
        )
        logger().info("***********stoping scan")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_client_address
        )
        logger().info("***********stoping advertise")
        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_enable=0
        )
    except Exception as e:
        logger().info(f'{e}')
        assert False
@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C528528", 1, 1),
    ],
)
@pytest.mark.check()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.parametrize("periodic_data_len, adv_handle", [(30, 0)])
@pytest.mark.ble_sniffer("frontline_sniffer")
def skip_test_filter_duplicates_with_nonzero_duration_period_C528528(ble_dut, ble_sniffer, sl_collections,
                                                                                remote_wiseconnect3, adv_type,
                                                                                periodic_data_len, adv_handle,
                                                                                test_case_id, pri_adv_phy,
                                                                                sec_adv_phy):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        df = sl_collections.start_periodic_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,adv_filter_policy=2,
                                               pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_len=200,
                                               scan_resp_len=1,
                                               test_case_id=test_case_id, #random_address_s2=True,
                                               #random_address=random_address,
                                               adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", adv_handle=0,
                                               ble_sniffer=ble_sniffer, powersave_p=True, adv_type_s2=127,
                                               adv_data_type=2, periodic_data_len=200)
        '''define PRI_PHY_LE_SCAN_INTERVAL 0x100
define PRI_PHY_LE_SCAN_WINDOW   0x50
define SEC_PHY_LE_SCAN_INTERVAL 0x100
define SEC_PHY_LE_SCAN_WINDOW   0x50'''

        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0,
            scanning_filter_policy=0,
            scanning_phys=1,  # 4 for 2M ph
            scan_type_sec=1,
            ScanInterval=100,
            ScanWindow=100,
            scan_type=1,
            remote_addr_type=0,
            scan_interval_sec=100,
            scan_window_sec=100
        )
        logger().info("*** Initiating ae_set_scan_enable ***")
        #ble_dut_address = random_address
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,  # 0x01: Scanning enabled
            filter_duplicates=2,  # 0x02: Duplicate filtering enabled, reset for each scan period
            duration=10,  # Non-zero: Scan duration (10 * 10ms = 100ms)
            period=20,  # Non-zero: Scan period (2 * 1.28s = 2.56s)
            remote_address=ble_dut_address  # Example address, must be valid for your setup
        )
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,  # 0x01: Scanning enabled
            filter_duplicates=2,  # 0x02: Duplicate filtering enabled, reset for each scan period
            duration=20,  # Non-zero: Scan duration (10 * 10ms = 100ms)
            period=10,  # Non-zero: Scan period (2 * 1.28s = 2.56s)
            remote_address=ble_dut_address  # Example address, must be valid for your setup
        )
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=2,
            duration=10,
            period=0,
            remote_address=ble_dut_address
        )
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=2,
            duration=0,
            period=10,
            remote_address=ble_dut_address
        )
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=2,
            duration=10,
            period=10,
            remote_address=ble_dut_address
        )
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=2,
            duration=0,
            period=0,
            remote_address=ble_dut_address
        )
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=0x02,
            duration=10,
            period=0,
            remote_address=ble_dut_address
        )
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=0x02,
            duration=0,
            period=10,
            remote_address=ble_dut_address
        )
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=0x02,
            duration=10,
            period=10,
            remote_address=ble_dut_address
        )
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=5,
            duration=0,
            period=0,
            remote_address=ble_dut_address
        )
        logger().info(f"\n\n *** periodic list ***\n\n")
        status = remote_wiseconnect3.interfaces.wifi.ble_ae_dev_to_periodic_list(
            remote_dev_addr=ble_dut_address,
            adv_addr_type=1,  # 0 for pabulic
            adv_sid=0,
            type=1
        )
        logger().info(f"\n\n *** Scanning status: {status} ***\n\n")
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_periodic_sync(
            remote_dev_addr=ble_dut_address,  # Use public address
            adv_addr_type=1,  # 0 = public address
            adv_sid=0,  # 1 i need check #0 before
            fil_policy=2,
            skip=0,
            sync_timeout=48,
            BLE_AE_PER_SYNC=0
        )
        logger().info(f"Periodic sync created successfully 134 sec{ble_dut_address} {ble_client_address}")
        time.sleep(180)
        count=0
        events = remote_wiseconnect3.interfaces.wifi.get_async_events()
        for event in events:
            count=count+1
            logger().info(f'{event.event_data}{count}')
            if 'AE Periodic Adv Report Event' in event.event_data:
                logger().info(' successfully got AE Periodic Adv Report Event in event.event_data')
            assert 'AE Periodic Adv Report Event' in event.event_data
        logger().info(f" count= {count}")

        events = remote_wiseconnect3.interfaces.wifi.get_async_events()
        adv_reports = [e for e in events if 'AE Periodic Adv Report Event' in e.events.data]
        logger().info(f'--->adv reports {adv_reports}')
        remote_wiseconnect3.interfaces.wifi.close()
    except Exception as e:
        logger().info(f'--e is --->{e}')
        assert False
    finally:
        remote_wiseconnect3.interfaces.wifi.remove_device(bt_dut_address=ble_dut_address)
        ble_dut.interfaces.bluetooth.close()
        remote_wiseconnect3.interfaces.wifi.close()
@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C528647", 1, 1),
        #(0, "C528650", 1, 2),
        #(0, "C528651", 3, 3),
    ],
)
@pytest.mark.check()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE |
                        Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.parametrize("periodic_data_len, adv_handle", [(30, 0)])
@pytest.mark.ble_sniffer("frontline_sniffer")
def skip_test_ble_ext_master_connection_disconnection_loop_528645(ble_dut, ble_sniffer, sl_collections,
                                                            remote_wiseconnect3, adv_type,
                                                            periodic_data_len, adv_handle,
                                                            test_case_id, pri_adv_phy,
                                                            sec_adv_phy):


    # Reference device details
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
    REF_DEVICE_NAME = "SILABS_DEVTEJ"
    DUT_RANDOM_ADDR = "11:44:33:AA:BB:CC"

    PRI_PHY_LE_SCAN_INTERVAL = 0x100
    PRI_PHY_LE_SCAN_WINDOW = 0x50
    SEC_PHY_LE_SCAN_INTERVAL = 0x100
    SEC_PHY_LE_SCAN_WINDOW = 0x50
    PRI_PHY_BLE_SCAN_TYPE = 1  # SCAN_TYPE_ACTIVE
    SEC_PHY_BLE_SCAN_TYPE = 1  # SCAN_TYPE_ACTIVE
    remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
        ble_addr_type=0,
        scanning_filter_policy=0,
        scanning_phys=1,
        scan_type_sec=SEC_PHY_BLE_SCAN_TYPE,
        ScanInterval=PRI_PHY_LE_SCAN_INTERVAL,
        ScanWindow=PRI_PHY_LE_SCAN_WINDOW,
        scan_type=PRI_PHY_BLE_SCAN_TYPE,
        remote_addr_type=0,
        scan_interval_sec=SEC_PHY_LE_SCAN_INTERVAL,
        scan_window_sec=SEC_PHY_LE_SCAN_WINDOW
    )
    ble_dut.interfaces.bluetooth.ble_get_max_no_of_supp_adv_sets(no_adv_sets=1)
    adv_type = 1
    sl_collections.ble_ae_set_params(
        pheripheral_dev=ble_dut, adv_event_prop=adv_type, own_address_type=0, peer_addr_type=0, adv_handle=0,
        pri_adv_phy=1, sec_adv_phy=1,
        scan_req_notify_enable=1,
        adv_filter_policy=0, sec_adv_max_skip=1, adv_min_interval=48, adv_max_interval=48
    )

    adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
    sl_collections.ble_set_ae_data(ble_dut=ble_dut, dut_address=ble_dut_address, adv_data_type=1,
                                   data_len=len(adv_data), adv_data=adv_data, adv_handle=0)
    sl_collections.ble_set_ae_data(ble_dut=ble_dut, dut_address=ble_dut_address, adv_data_type=3,
                                   data_len=len(adv_data), adv_data=adv_data, adv_handle=0, scan_resp_len=0)
    sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                            duration=0, max_ae_events=0, adv_handle=0, adv_async_required=0)
    status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
        enable=1,
        filter_duplicates=0,
        duration=0,
        period=0,
        remote_address=ble_dut_address
    )
    for i in range(10):
        # Initiate connection
        remote_wiseconnect3.interfaces.wifi.ble_extended_connect_with_params(
            remote_dev_addr=ble_dut_address,
            remote_addr_type=1  # Use correct address type
        )
        time.sleep(10)  # Wait for connection to establish

        # Disconnect the client address
        remote_wiseconnect3.interfaces.wifi.ble_disconnect(ble_client_address)
        time.sleep(5)  # Wait for disconnect to process

    status = remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
        enable=0,
        filter_duplicates=0,
        duration=0,
        period=0,
        remote_address=ble_dut_address
    )

@pytest.mark.parametrize(
    "test_case_id, periodic_data_len, adv_handle, pri_adv_phy, sec_adv_phy",
    [
        ("C528647", 30, 0, 1, 1),
    ],
)
@pytest.mark.check()
@pytest.mark.config(
    "wifi_dut",
    wifi={ ... }
)
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={ ... }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
def skip_test_ble_ext_master_connection_disconnection_loop_528645(
    ble_dut, ble_sniffer, sl_collections,
    remote_wiseconnect3, periodic_data_len, adv_handle,
    test_case_id, pri_adv_phy, sec_adv_phy
):

    try:
        # Set up advertising and scanning intervals as per test case
        ADV_INT_MIN = 0x152
        ADV_INT_MAX = 0x152
        SCAN_INTERVAL = 0x35
        SCAN_WINDOW = 0x17
        adv_type= 0
        # Start AE advertising on DUT
        #ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        random_address = "11:44:33:AA:BB:CC"
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        sl_collections.ble_ae_set_params(
            pheripheral_dev=ble_dut,
            adv_event_prop=adv_type,
            own_address_type=0,
            peer_addr_type=0,
            adv_handle=0,
            pri_adv_phy=pri_adv_phy,
            sec_adv_phy=sec_adv_phy,
            scan_req_notify_enable=1,
            adv_filter_policy=0,
            sec_adv_max_skip=1,
            adv_min_interval=ADV_INT_MIN,
            adv_max_interval=ADV_INT_MAX
        )
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=periodic_data_len))
        sl_collections.ble_set_ae_data(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_data_type=1,
            data_len=len(adv_data),
            adv_data=adv_data,
            adv_handle=0
        )
        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            duration=0,
            max_ae_events=0,
            adv_handle=0,
            adv_async_required=0
        )

        # Start AE scanning on DUT
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0,
            scanning_filter_policy=0,
            scanning_phys=1,
            scan_type_sec=1,
            ScanInterval=SCAN_INTERVAL,
            ScanWindow=SCAN_WINDOW,
            scan_type=1,
            remote_addr_type=0,
            scan_interval_sec=SCAN_INTERVAL,
            scan_window_sec=SCAN_WINDOW
        )
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_dut_address
        )
        logger().info("Running simultaneous AE advertising and scanning for 5 minutes...")
        time.sleep(300)
        events_dut = ble_dut.interfaces.bluetooth.get_async_events()
        found_remote = any("Found" in e.event_data for e in events_dut)
        assert found_remote, "Remote AE device not found in DUT scan results"

        # Check scan results on remote device
        events_remote = remote_wiseconnect3.interfaces.wifi.get_async_events()
        found_dut = any("Found" in e.event_data for e in events_remote)
        assert found_dut, "DUT not found in remote AE device scan results"

        # Stop scanning and advertising
        remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=ble_dut_address
        )
        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_enable=0
        )
        logger().info("Simultaneous AE advertising and scanning test completed.")
    except Exception as e:
        logger().info(f"Test failed: {e}")
        assert False