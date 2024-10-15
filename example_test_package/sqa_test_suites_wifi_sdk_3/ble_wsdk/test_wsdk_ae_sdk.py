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
    Si91xConfigFeatureBitMap,
    Si91xBLEExtFeatureBITMAP,
    Si91xBLEFeatureBITMAP,
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

"""
    Test case category : BLE Advertising Extension 
    Device roles       : DUT is performing Peripheral role
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through Teledyne sniffer
"""

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_EXT_ADV_pkt_and_aux_ptr_C528485(ble_dut, sl_collections, ble_sniffer):
    """
    Test case          : This test case will verify Advertising Extention packets for undirected connecable and scannable adv type and aux pointer
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=1, test_case_id="C193693",
                                      adv_handle=0, ble_dut_address=ble_dut_address,
                                      ble_sniffer=ble_sniffer, powersave_p=True)

    #Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38, 39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed: No ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    #Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df["Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed: No Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    #Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
    assert any((df['Chan'].iloc[i:i+3].tolist() == [37, 38, 39] and df['Chan'].iloc[i+3] not in [37, 38, 39]) for i in range(len(df) - 3)), "\n\n **** Test case Failed: No AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
    #Assert if 1M PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets
    assert (df['+PHY Type (LE BB)'] == '1M').all(), "\n\n **** Test case Failed: 1M PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** 1M PHY is used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n")
    #Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
    assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(-2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(bool)).any(), "\n\n **** Test case Failed: AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
    #Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info("\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Assert if AUX_ADV-IND packets PHY does not match with the PHY mentioned in the AUX_EXT_IND packet
    def check_series(df):
        for i in range(len(df) - 2):
            if df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39]:
                aux_phy_values = df['Aux Phy'].iloc[i:i + 3].apply(
                    lambda x: re.search(r'\dM', str(x)).group() if pd.notna(x) else None)
                if aux_phy_values.nunique() == 1:
                    next_phy_type_values = df['+PHY Type (LE BB)'].iloc[i + 3:i + 6]
                    if next_phy_type_values.eq(aux_phy_values.iloc[0]).all() or df['Type'].iloc[i + 3:i + 6].eq(
                            'ADV_EXT_IND').all():
                        continue
                    else:
                        return False
                else:
                    return False
        return True

    result = check_series(df)
    assert result, "\n\n **** Test case Failed: AUX_ADV-IND packets PHY does not match with the PHY mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV-IND packets PHY matches with the PHY mentioned in the AUX_EXT_IND packet ****\n\n")
    #Assert if PDU length is not 7 in ADV_EXT_IND packets
    assert (df.loc[df['Type'] == 'ADV_EXT_IND', 'PDU Length'] == 7).all(), "\n\n **** Test case Failed: PDU length is not 7 in ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** PDU length is 7 in ADV_EXT_IND packets ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
def test_verify_lowest_highest_adv_handle_C528486(ble_dut, sl_collections):
    """
    Test case          : This test case will verify Advertising Extention with lowest and highest adv_handle
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    logger().info(f"\n\n ** Verifying AE with lowest handle ie. 0x00 **\n\n")
    sl_collections.verify_adv(peripheral=ble_dut, adv_type=19, test_case_id="C193694",
                              adv_handle=0, ble_dut_address=ble_dut_address,
                              test_in_progress=True, powersave_p=True
                              )
    logger().info("\n\n **** AE with lowest handle ie. 0x00 is success ****\n\n")

    logger().info(f"\n\n ** Verifying AE with highest handle ie. 0xef **\n\n")
    sl_collections.verify_adv(peripheral=ble_dut, adv_type=19, test_case_id="C193694",
                              adv_handle=239, ble_dut_address=ble_dut_address, powersave_p=True
                              )
    logger().info("\n\n **** AE with highest handle ie. 0xef is success ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_adv_on_channel_37_38_39_C528487(ble_dut, sl_collections, ble_sniffer):
    """
    Test case category : BLE Advertising Extension
    Test case          : This test case will verify Advertising Extention with adv channels on 37,38 and 39
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=1, test_case_id="C193695",
                                    adv_handle=0, ble_dut_address=ble_dut_address,
                                    ble_sniffer=ble_sniffer, powersave_p=True
                              )
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df[
                                                                                     "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no connectable non-scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if PDU length is not 7 in ADV_EXT_IND packets
    assert (df.loc[df[
                       'Type'] == 'ADV_EXT_IND', 'PDU Length'] == 7).all(), "\n\n **** Test case Failed with PDU length is not 7 in ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** PDU length is 7 in ADV_EXT_IND packets ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info("\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_ADV_for_infinite_time_C528488(ble_dut, sl_collections, ble_sniffer):
    """
    Test case category : BLE Advertising Extension
    Test case          : This test case will verify Advertising Extention for infinite time with duration paramerter 0x0000
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                    adv_handle=0, duration=0, test_case_id="C193696", ble_sniffer=ble_sniffer, powersave_p=True)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df[
                                                                                     "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_ADV_for_2560ms_C528489(ble_dut, sl_collections, ble_sniffer):
    """
    Test case category : BLE Advertising Extension
    Test case          : This test case will verify Advertising Extention for 2560ms and verify even RSI_APP_EVENT_EXT_ADV_TERMINATED
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer,
                                    adv_handle=0, duration=256, adv_async_required=1, test_case_id="C193697", powersave_p=True)

    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df[
                                                                                     "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Extract the time part from the original 'Timestamp' column
    df['Time'] = df['Timestamp'].apply(lambda x: re.search(r"\d+:\d+\.\d+", x.strftime('%Y-%m-%d %H:%M:%S.%f')).group())
    # Find indices where the sequence 37, 38, 39 occurs
    sequence = [37, 38, 39]
    indices = df.index[df['Chan'].rolling(window=3).apply(lambda x: list(x) == sequence, raw=True) == 1].tolist()
    logger().info(f"Indices where the sequence 37, 38, 39 occurs: {indices}")
    # Calculate time difference in milliseconds
    time_difference = 0
    if len(indices) > 1:
        first_37_index = indices[0]
        second_37_index = indices[-1]
        first_time = df.loc[first_37_index, 'Time']
        logger().info(f"First time: {first_time}")
        second_time = df.loc[second_37_index, 'Time']
        logger().info(f"Second time: {second_time}")
        # Truncate the fractional seconds to 6 digits
        first_time_str = re.sub(r'(\.\d{6})\d+', r'\1', first_time)
        # Convert the extracted time string to a datetime object
        first_time_obj = datetime.strptime(first_time_str, "%M:%S.%f").time()
        # Truncate the fractional seconds to 6 digits
        second_time_str = re.sub(r'(\.\d{6})\d+', r'\1', second_time)
        # Convert the extracted time string to a datetime object
        second_time_obj = datetime.strptime(second_time_str, "%M:%S.%f").time()
        datetime1 = datetime.combine(datetime.today(), first_time_obj)
        datetime2 = datetime.combine(datetime.today(), second_time_obj)
        time_difference = (datetime2 - datetime1)
        logger().info(f"Time difference in milliseconds: {time_difference}")
    # Convert the string to a float representing seconds
    end = float(2.560)
    # Create a timedelta object
    time_delta = timedelta(seconds=end)
    # Check if the time difference matches the input value within ±10 milliseconds
    tolerance = timedelta(seconds=float(0.15))
    assert abs(
        time_difference - time_delta) <= tolerance, "\n\n **** Test case Failed with the reason time difference does not match the input value within ±10 milliseconds ****\n\n"
    logger().info("\n\n **** DUT stopped advertisement after expected time 2.560sec ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
@pytest.mark.parametrize(
    "min_interval, test_case_id, max_interval, start, stop",
    [
        (32, "C528491", 34, "0.020", "0.022"),
        (34, "C528492", 37, "0.022", "0.025"),
        (8000, "C539201", 16384, "5.000", "10.240"),
        (16384, "C539202", 16384, "10.240", "10.240"),
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_ADV_for_different_interval_min_max_C528491_C528492_C539201_C539202(ble_dut, sl_collections, ble_sniffer, min_interval, test_case_id, max_interval, start, stop):
    """
    Test case category : BLE Advertising Extension
    Test case          : This test case will verify Advertising Extention for 2560ms and verify even RSI_APP_EVENT_EXT_ADV_TERMINATED
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer,
                                    adv_handle=0, duration=0, adv_async_required=1, test_case_id=test_case_id, min_interval=min_interval, max_interval=max_interval, powersave_p=True)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df[
                                                                                     "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Extract time from Timestamp
    df['Time'] = df['Timestamp'].apply(lambda x: re.search(r"\d+:\d+\.\d+", x.strftime('%Y-%m-%d %H:%M:%S.%f')).group())
    # Find indices where the sequence 37, 38, 39 occurs
    sequence = [37, 38, 39]
    indices = df.index[df['Chan'].rolling(window=3).apply(lambda x: list(x) == sequence, raw=True) == 1].tolist()
    logger().info(f"Indices where the sequence 37, 38, 39 occurs: {indices}")
    # Calculate time difference in milliseconds
    time_difference = 0
    if len(indices) > 1:
        first_37_index = indices[0]
        second_37_index = indices[1]
        first_time = df.loc[first_37_index, 'Time']
        logger().info(f"First time: {first_time}")
        second_time = df.loc[second_37_index, 'Time']
        logger().info(f"Second time: {second_time}")
        # Truncate the fractional seconds to 6 digits
        first_time_str = re.sub(r'(\.\d{6})\d+', r'\1', first_time)
        # Convert the extracted time string to a datetime object
        first_time_obj = datetime.strptime(first_time_str, "%M:%S.%f").time()
        # Truncate the fractional seconds to 6 digits
        second_time_str = re.sub(r'(\.\d{6})\d+', r'\1', second_time)
        # Convert the extracted time string to a datetime object
        second_time_obj = datetime.strptime(second_time_str, "%M:%S.%f").time()
        datetime1 = datetime.combine(datetime.today(), first_time_obj)
        datetime2 = datetime.combine(datetime.today(), second_time_obj)
        time_difference = (datetime2 - datetime1)
        logger().info(f"Time difference in milliseconds: {time_difference}")
    # Convert the string to a float representing seconds
    start = float(start)-0.2
    stop = float(stop)+0.2
    # Create a timedelta object
    time_delta1 = timedelta(seconds=start)
    time_delta2 = timedelta(seconds=stop)
    # Check if the time difference matches
    assert time_delta1 <= time_difference <= time_delta2, "\n\n **** Test case Failed with DUT not stopped advertisement after expected time... ****\n\n"
    logger().info("\n\n **** Time difference matches the defined adv interval ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_ADV_for_15_max_event_C528490(ble_dut, sl_collections, ble_sniffer):
    """
    Test case category : BLE Advertising Extension
    Test case          : This test case will verify Advertising Extention for max AE events 200 and verify even RSI_APP_EVENT_EXT_ADV_TERMINATED
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=1, adv_handle=0, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer,
                                    max_ae_events=15, adv_async_required=1, test_case_id="C193698")
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df[
                                                                                     "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    #assert if max AE events are not 15
    assert df[~df['Chan'].isin([37, 38, 39])]['Chan'].count() <= 15, "\n\n **** Test case Failed with Max AE events are not 15... ****\n\n"
    logger().info("\n\n **** Max AE events are 15 ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_ADV_with_randomm_address_C528493(ble_dut, sl_collections, ble_sniffer):
    """
    Test case category : BLE Advertising Extension
    Test case          : This test case will verify Advertising Extention with random address
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    random_address="11:33:33:33:33:11"
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=1, own_address_type=1, ble_dut_address=random_address,
                                      test_case_id="C163701",
                                      random_address=random_address, ble_sniffer=ble_sniffer, powersave_p=True
                                    )
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df[
                                                                                     "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    #assert if DUT not advertising with the defined random address
    assert ((df['Chan'].isin([37, 38, 39])) & (df['Ext Adv Address Type'] == 'random')).any(), "\n\n **** Test case Failed with DUT not advertising with the defined random address... ****\n\n"
    logger().info("\n\n **** DUT advertising with the defined random address ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

"""
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv 
    Device roles       : DUT is performing Peripheral role
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through Teledyne sniffer
"""

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_non_conn_non_scan_ADV_C528494(ble_dut, sl_collections, ble_sniffer):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M
                         with adb data of 1bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, test_case_id="C163702",
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=1,ble_sniffer=ble_sniffer, adv_data="AE_PERIPHERAL_DATA", powersave_p=True)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no Non-connectable non-scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                         "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
    assert any(
        (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        range(len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
    # Assert if 1M PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets
    assert (df[
                '+PHY Type (LE BB)'] == '1M').all(), "\n\n **** Test case Failed with 1M PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n"
    # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
    assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if AUX_ADV_IND packets PHY does not match with the PHY mentioned in the AUX_EXT_IND packet
    def check_series(df):
        for i in range(len(df) - 2):
            if df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39]:
                aux_phy_values = df['Aux Phy'].iloc[i:i + 3].apply(
                    lambda x: re.search(r'\dM', str(x)).group() if pd.notna(x) else None)
                if aux_phy_values.nunique() == 1:
                    next_phy_type_values = df['+PHY Type (LE BB)'].iloc[i + 3:i + 6]
                    if next_phy_type_values.eq(aux_phy_values.iloc[0]).all() or df['Type'].iloc[i + 3:i + 6].eq(
                            'ADV_EXT_IND').all():
                        continue
                    else:
                        return False
                else:
                    return False
        return True

    result = check_series(df)
    assert result, "\n\n **** Test case Failed with AUX_ADV_IND packets PHY does not match with the PHY mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets PHY matches with the PHY mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if PDU length is not 11 in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_ADV_IND', 'PDU Length'] == 11).all(), "\n\n **** Test case Failed with PDU length is not 11 in AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** PDU length is 11 in AUX_ADV_IND packets ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_non_conn_non_scan_ADV_C528495(ble_dut, ble_sniffer, sl_collections):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M
                         with adv data of 0 bytes and max ae events: 0x32 ie.50
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, ble_dut_address=ble_dut_address, adv_type=0, pri_adv_phy=1, test_case_id="C163703",
                                      sec_adv_phy=1, data_len=0, ble_sniffer=ble_sniffer,
                                      max_ae_events=50, adv_async_required=1, adv_data="AE_PERIPHERAL_DATA"
                                   )
    #assert if DUT not advertising with the defined max ae events 50
    assert df['Chan'].value_counts().get(39, 0) == 50, "\n\n **** Test case Failed with DUT not advertising with the defined max ae events 50 ****\n\n"
    logger().info("\n\n **** DUT advertising with the defined max ae events 50 ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_non_conn_non_scan_ADV_C528496(ble_dut, ble_sniffer, sl_collections):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M
                         with adv data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address, test_case_id="C163704",
                                    data_len=31, ble_sniffer=ble_sniffer,
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", powersave_p=True)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                     "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
    assert any(
        (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        range(len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
    # Assert if 1M PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets
    assert (df[
                '+PHY Type (LE BB)'] == '1M').all(), "\n\n **** Test case Failed with 1M PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** 1M PHY is used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n")
    # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
    assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if AUX_ADV-IND packets PHY does not match with the PHY mentioned in the AUX_EXT_IND packet
    def check_series(df):
        for i in range(len(df) - 2):
            if df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39]:
                aux_phy_values = df['Aux Phy'].iloc[i:i + 3].apply(
                    lambda x: re.search(r'\dM', str(x)).group() if pd.notna(x) else None)
                if aux_phy_values.nunique() == 1:
                    next_phy_type_values = df['+PHY Type (LE BB)'].iloc[i + 3:i + 6]
                    if next_phy_type_values.eq(aux_phy_values.iloc[0]).all() or df['Type'].iloc[i + 3:i + 6].eq(
                            'ADV_EXT_IND').all():
                        continue
                    else:
                        return False
                else:
                    return False
        return True

    result = check_series(df)
    assert result, "\n\n **** Test case Failed with AUX_ADV_IND packets PHY does not match with the PHY mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets PHY matches with the PHY mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if PDU length is not 41 in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_ADV_IND', 'PDU Length'] == 41).all(), "\n\n **** Test case Failed with PDU length is not 41 in AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** PDU length is 41 in AUX_ADV_IND packets ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_non_conn_non_scan_ADV_C528497(ble_dut, ble_sniffer, sl_collections):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M
                         with adv data length of 200 bytes and Adv duration is 5 sec: 0x1F4
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=200, test_case_id="C163705",
                                    adv_data="AE_PERIPHERAL_DATA", duration=500, adv_async_required=1, powersave_p=True
                                    )
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                         "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
    assert any(
        (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        range(len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
    # Assert if 1M PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets
    assert (df[
                '+PHY Type (LE BB)'] == '1M').all(), "\n\n **** Test case Failed with 1M PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** 1M PHY is used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n")
    # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
    assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if AUX_ADV-IND packets PHY does not match with the PHY mentioned in the AUX_EXT_IND packet
    def check_series(df):
        for i in range(len(df) - 2):
            if df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39]:
                aux_phy_values = df['Aux Phy'].iloc[i:i + 3].apply(
                    lambda x: re.search(r'\dM', str(x)).group() if pd.notna(x) else None)
                if aux_phy_values.nunique() == 1:
                    next_phy_type_values = df['+PHY Type (LE BB)'].iloc[i + 3:i + 6]
                    if next_phy_type_values.eq(aux_phy_values.iloc[0]).all() or df['Type'].iloc[i + 3:i + 6].eq(
                            'ADV_EXT_IND').all():
                        continue
                    else:
                        return False
                else:
                    return False
        return True
    result = check_series(df)
    assert result, "\n\n **** Test case Failed with AUX_ADV_IND packets PHY does not match with the PHY mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets PHY matches with the PHY mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if PDU length is not 41 in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_ADV_IND', 'PDU Length'] == 210).all(), "\n\n **** Test case Failed with PDU length is not 210 in AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** PDU length is 210 in AUX_ADV_IND packets ****\n\n")
    # Extract the time part from the original 'Timestamp' column
    df['Time'] = df['Timestamp'].apply(lambda x: re.search(r"\d+:\d+\.\d+", x.strftime('%Y-%m-%d %H:%M:%S.%f')).group())
    # Find indices where the sequence 37, 38, 39 occurs
    sequence = [37, 38, 39]
    indices = df.index[df['Chan'].rolling(window=3).apply(lambda x: list(x) == sequence, raw=True) == 1].tolist()
    logger().info(f"Indices where the sequence 37, 38, 39 occurs: {indices}")
    # Calculate time difference in milliseconds
    time_difference = 0
    if len(indices) > 1:
        first_37_index = indices[0]
        second_37_index = indices[-1]
        first_time = df.loc[first_37_index, 'Time']
        logger().info(f"First time: {first_time}")
        second_time = df.loc[second_37_index, 'Time']
        logger().info(f"Second time: {second_time}")
        # Truncate the fractional seconds to 6 digits
        first_time_str = re.sub(r'(\.\d{6})\d+', r'\1', first_time)
        # Convert the extracted time string to a datetime object
        first_time_obj = datetime.strptime(first_time_str, "%M:%S.%f").time()
        # Truncate the fractional seconds to 6 digits
        second_time_str = re.sub(r'(\.\d{6})\d+', r'\1', second_time)
        # Convert the extracted time string to a datetime object
        second_time_obj = datetime.strptime(second_time_str, "%M:%S.%f").time()
        datetime1 = datetime.combine(datetime.today(), first_time_obj)
        datetime2 = datetime.combine(datetime.today(), second_time_obj)
        time_difference = (datetime2 - datetime1)
        logger().info(f"Time difference in milliseconds: {time_difference}")
    # Convert the string to a float representing seconds
    end = float(5.0)
    # Create a timedelta object
    time_delta = timedelta(seconds=end)
    # Check if the time difference matches the input value within ±10 milliseconds
    tolerance = timedelta(seconds=float(0.15))
    assert abs(
        time_difference - time_delta) <= tolerance, "\n\n **** Test case Failed with the reason time difference does not match the input value within ±10 milliseconds ****\n\n"
    logger().info("\n\n **** DUT stopped advertisement after expected time 5sec ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_non_conn_non_scan_ADV_C528498(ble_dut, ble_sniffer, sl_collections):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY LE Coded
                         with adv data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer, pri_adv_phy=3, sec_adv_phy=3,
                                    data_len=31, test_case_id="C163706",
                                    adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", powersave_p=True)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                         "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
    assert any(
        (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        range(len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
    # Assert if LE CODED PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets
    assert (df[
                '+PHY Type (LE BB)'] == '125k').all(), "\n\n **** Test case Failed with LE CODED PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** LE CODED PHY is used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n")
    # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
    assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if PDU length is not 41 in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_ADV_IND', 'PDU Length'] == 41).all(), "\n\n **** Test case Failed with PDU length is not 41 in AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** PDU length is 41 in AUX_ADV_IND packets ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_non_conn_non_scan_ADV_C528499(ble_dut, ble_sniffer, sl_collections):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY LE Coded
                         with adv data of 0 bytes and max ae events: 0x32 ie.50
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=0, test_case_id="C163707",
                                    adv_data="AE_PERIPHERAL_DATA", max_ae_events=50, adv_async_required=1)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no Non-Connectable Non-Scannable advertising mode found
    assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found ****\n\n"
    logger().info("\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if LE CODED PHY is not used on both ADV_EXT_IND packets
    assert (df[
                '+PHY Type (LE BB)'] == '125k').all(), "\n\n **** Test case Failed with LE CODED PHY is not used on both ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** LE CODED PHY is used on both ADV_EXT_IND packets ****\n\n")
    # Assert if PDU length is not 7 in ADV_EXT_IND packets
    assert (df.loc[df[
                       'Type'] == 'ADV_EXT_IND', 'PDU Length'] == 8).all(), "\n\n **** Test case Failed with PDU length is not 8 in ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** PDU length is 8 in ADV_EXT_IND packets ****\n\n")
    #assert if DUT not advertising with the defined max ae events 50
    assert df['Chan'].value_counts().get(39, 0) == 50, "\n\n **** Test case Failed with DUT not advertising with the defined max ae events 50 ****\n\n"
    logger().info("\n\n **** DUT advertising with the defined max ae events 50 ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_non_conn_non_scan_ADV_C528500(ble_dut, ble_sniffer, sl_collections):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY LE CODED
                         with adv data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer,
                                      pri_adv_phy=3, sec_adv_phy=3, data_len=1, test_case_id="C163708", adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", powersave_p=True)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                         "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
    assert any(
        (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        range(len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
    # Assert if LE CODED PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets
    assert (df[
                '+PHY Type (LE BB)'] == '125k').all(), "\n\n **** Test case Failed with LE CODED PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** LE CODED PHY is used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n")
    # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
    assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if PDU length is not 11 in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_ADV_IND', 'PDU Length'] == 11).all(), "\n\n **** Test case Failed with PDU length is not 11 in AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** PDU length is 11 in AUX_ADV_IND packets ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_non_conn_non_scan_ADV_C528501(ble_dut, ble_sniffer, sl_collections):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY LE Coded
                         with adv data length of 200 bytes and Adv duration is 5 sec: 0x1F4
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=200, test_case_id="C163709",
                                    adv_data=200*"A", duration=500, adv_async_required=1, powersave_p=True)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                         "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
    assert any(
        (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        range(len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
    # Assert if LE CODED PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets
    assert (df[
                '+PHY Type (LE BB)'] == '125k').all(), "\n\n **** Test case Failed with LE CODED PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** LE CODED PHY is used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n")
    # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
    assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if PDU length is not 41 in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_ADV_IND', 'PDU Length'] == 210).all(), "\n\n **** Test case Failed with PDU length is not 210 in AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** PDU length is 210 in AUX_ADV_IND packets ****\n\n")
    # Extract the time part from the original 'Timestamp' column
    df['Time'] = df['Timestamp'].apply(lambda x: re.search(r"\d+:\d+\.\d+", x.strftime('%Y-%m-%d %H:%M:%S.%f')).group())
    # Find indices where the sequence 37, 38, 39 occurs
    sequence = [37, 38, 39]
    indices = df.index[df['Chan'].rolling(window=3).apply(lambda x: list(x) == sequence, raw=True) == 1].tolist()
    logger().info(f"Indices where the sequence 37, 38, 39 occurs: {indices}")
    # Calculate time difference in milliseconds
    time_difference = 0
    if len(indices) > 1:
        first_37_index = indices[0]
        second_37_index = indices[-1]
        first_time = df.loc[first_37_index, 'Time']
        logger().info(f"First time: {first_time}")
        second_time = df.loc[second_37_index, 'Time']
        logger().info(f"Second time: {second_time}")
        # Truncate the fractional seconds to 6 digits
        first_time_str = re.sub(r'(\.\d{6})\d+', r'\1', first_time)
        # Convert the extracted time string to a datetime object
        first_time_obj = datetime.strptime(first_time_str, "%M:%S.%f").time()
        # Truncate the fractional seconds to 6 digits
        second_time_str = re.sub(r'(\.\d{6})\d+', r'\1', second_time)
        # Convert the extracted time string to a datetime object
        second_time_obj = datetime.strptime(second_time_str, "%M:%S.%f").time()
        datetime1 = datetime.combine(datetime.today(), first_time_obj)
        datetime2 = datetime.combine(datetime.today(), second_time_obj)
        time_difference = (datetime2 - datetime1)
        logger().info(f"Time difference in milliseconds: {time_difference}")
    # Convert the string to a float representing seconds
    end = float(5.0)
    # Create a timedelta object
    time_delta = timedelta(seconds=end)
    # Check if the time difference matches the input value within ±10 milliseconds
    tolerance = timedelta(seconds=float(0.15))
    assert abs(
        time_difference - time_delta) <= tolerance, "\n\n **** Test case Failed with the reason time difference does not match the input value within ±10 milliseconds ****\n\n"
    logger().info("\n\n **** DUT stopped advertisement after expected time 5sec ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_non_conn_non_scan_ADV_C528502(ble_dut, ble_sniffer, sl_collections):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M, 2M
                         with adv data of 1 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address,
                                      ble_sniffer=ble_sniffer,
                                      pri_adv_phy=1, sec_adv_phy=2, data_len=1, test_case_id="C163710", adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", powersave_p=True)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if primary PHY is not 1M on ADV_EXT_IND packets
    assert (df[df['Chan'].isin([37, 38, 39])]['+PHY Type (LE BB)'] == '1M').all(), "\n\n **** Test case Failed with primary PHY is not 1M on ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
    # Assert if Secondary PHY is not 2M on AUX_ADV_IND packets
    assert (df[~df['Chan'].isin([37, 38, 39])]['+PHY Type (LE BB)'] == '2M').all(), "\n\n **** Test case Failed with Secondary PHY is not 2M on AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** Secondary PHY is 2M on AUX_ADV_IND packets ****\n\n")
    # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                         "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
    assert any(
        (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        range(len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
    # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
    assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if PDU length is not 11 in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_ADV_IND', 'PDU Length'] == 11).all(), "\n\n **** Test case Failed with PDU length is not 11 in AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** PDU length is 11 in AUX_ADV_IND packets ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_non_conn_non_scan_ADV_C528503(ble_dut, ble_sniffer, sl_collections):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri PHY is 1M and sec PHY is 2M
                         with adv data of 0 bytes and max ae events: 0x32 ie.50
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, data_len=0, test_case_id="C163711",
                                    adv_data="AE_PERIPHERAL_DATA", max_ae_events=50, adv_async_required=1)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if primary PHY is not 1M on ADV_EXT_IND packets
    assert (df[df['Chan'].isin([37, 38, 39])]['+PHY Type (LE BB)'] == '1M').all(), "\n\n **** Test case Failed with primary PHY is not 1M on ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
    # Assert if there is no non-connectable non-scannable advertising mode found
    assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found ****\n\n"
    logger().info("\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    assert df['Chan'].value_counts().get(39,
                                         0) == 50, "\n\n **** Test case Failed with DUT not advertising with the defined max ae events 50 ****\n\n"
    logger().info("\n\n **** DUT advertising with the defined max ae events 50 ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_non_conn_non_scan_ADV_C528504(ble_dut, ble_sniffer, sl_collections):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M, 2M
                         with adv data of 31 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address,
                                      ble_sniffer=ble_sniffer,
                                      pri_adv_phy=1, sec_adv_phy=2, data_len=31, test_case_id="C163712", adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", powersave_p=True)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if primary PHY is not 1M on ADV_EXT_IND packets
    assert (df[df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '1M').all(), "\n\n **** Test case Failed with primary PHY is not 1M on ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
    # Assert if Secondary PHY is not 2M on AUX_ADV_IND packets
    assert (df[~df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '2M').all(), "\n\n **** Test case Failed with Secondary PHY is not 2M on AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** Secondary PHY is 2M on AUX_ADV_IND packets ****\n\n")
    # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                         "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
    assert any(
        (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        range(len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
    # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
    assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if PDU length is not 11 in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_ADV_IND', 'PDU Length'] == 41).all(), "\n\n **** Test case Failed with PDU length is not 41 in AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** PDU length is 41 in AUX_ADV_IND packets ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_non_conn_non_scan_ADV_C163713(ble_dut, ble_sniffer, sl_collections):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri and sec PHY 1M, 2M
                         with adv data of 474 bytes
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=0, adv_handle=1, ble_dut_address=ble_dut_address,
                                      ble_sniffer=ble_sniffer,
                                      pri_adv_phy=1, sec_adv_phy=2, data_len=474, test_case_id="C163713", adv_data="AE_PERIPHERAL_DATA_1_2_3_4_5_6@", powersave_p=True)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if primary PHY is not 1M on ADV_EXT_IND packets
    assert (df[df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '1M').all(), "\n\n **** Test case Failed with primary PHY is not 1M on ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
    # Assert if Secondary PHY is not 2M on AUX_ADV_IND packets
    assert (df[~df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '2M').all(), "\n\n **** Test case Failed with Secondary PHY is not 2M on AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** Secondary PHY is 2M on AUX_ADV_IND packets ****\n\n")
    # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                         "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
    assert any(
        (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        range(len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
    # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
    assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if PDU length is not 11 in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_ADV_IND', 'PDU Length'] == 485).all(), "\n\n **** Test case Failed with PDU length is not 485 in AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** PDU length is 485 in AUX_ADV_IND packets ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_non_conn_non_scan_ADV_C528505(ble_dut, ble_sniffer, sl_collections):
    """
    Test case category : LE Ext Adv - Non connectable Non Scannable undirected adv
    Test case          : This test case will verify Non connectable Non Scannable undirected with pri PHY is 1M and sec PHY is 2M
                         with adv data length of 200 bytes and Adv duration is 5 sec: 0x1F4
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    """
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, data_len=200, test_case_id="C163714",
                                    adv_data="AE_PERIPHERAL_DATA", duration=500, adv_async_required=1, powersave_p=True)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if primary PHY is not 1M on ADV_EXT_IND packets
    assert (df[df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '1M').all(), "\n\n **** Test case Failed with primary PHY is not 1M on ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
    # Assert if Secondary PHY is not 2M on AUX_ADV_IND packets
    assert (df[~df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '2M').all(), "\n\n **** Test case Failed with Secondary PHY is not 2M on AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** Secondary PHY is 2M on AUX_ADV_IND packets ****\n\n")
    # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                         "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
    assert any(
        (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        range(len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
    # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
    assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if PDU length is not 210 in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_ADV_IND', 'PDU Length'] == 210).all(), "\n\n **** Test case Failed with PDU length is not 210 in AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** PDU length is 210 in AUX_ADV_IND packets ****\n\n")
    # Extract the time part from the original 'Timestamp' column
    df['Time'] = df['Timestamp'].apply(lambda x: re.search(r"\d+:\d+\.\d+", x.strftime('%Y-%m-%d %H:%M:%S.%f')).group())
    # Find indices where the sequence 37, 38, 39 occurs
    sequence = [37, 38, 39]
    indices = df.index[df['Chan'].rolling(window=3).apply(lambda x: list(x) == sequence, raw=True) == 1].tolist()
    logger().info(f"Indices where the sequence 37, 38, 39 occurs: {indices}")
    # Calculate time difference in milliseconds
    time_difference = 0
    if len(indices) > 1:
        first_37_index = indices[0]
        second_37_index = indices[-1]
        first_time = df.loc[first_37_index, 'Time']
        logger().info(f"First time: {first_time}")
        second_time = df.loc[second_37_index, 'Time']
        logger().info(f"Second time: {second_time}")
        # Truncate the fractional seconds to 6 digits
        first_time_str = re.sub(r'(\.\d{6})\d+', r'\1', first_time)
        # Convert the extracted time string to a datetime object
        first_time_obj = datetime.strptime(first_time_str, "%M:%S.%f").time()
        # Truncate the fractional seconds to 6 digits
        second_time_str = re.sub(r'(\.\d{6})\d+', r'\1', second_time)
        # Convert the extracted time string to a datetime object
        second_time_obj = datetime.strptime(second_time_str, "%M:%S.%f").time()
        datetime1 = datetime.combine(datetime.today(), first_time_obj)
        datetime2 = datetime.combine(datetime.today(), second_time_obj)
        time_difference = (datetime2 - datetime1)
        logger().info(f"Time difference in milliseconds: {time_difference}")
    # Convert the string to a float representing seconds
    end = float(5.0)
    # Create a timedelta object
    time_delta = timedelta(seconds=end)
    # Check if the time difference matches the input value within ±10 milliseconds
    tolerance = timedelta(seconds=float(0.15))
    assert abs(
        time_difference - time_delta) <= tolerance, "\n\n **** Test case Failed with the reason time difference does not match the input value within ±10 milliseconds ****\n\n"
    logger().info("\n\n **** DUT stopped advertisement after expected time 5sec ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

"""
    Test case category : LE Ext Adv - Scannable Non Connectable Undirected Adv with scan_response_data on DUT and primary phy is 1M, sec phy is 1M.Ref device doing the LE_Ext_Scan for the adv packets
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    Fixures used       : ble_sniffer - To caputre BLE OTA logs through Teledyne sniffer
"""
@pytest.mark.parametrize(
    "adv_type, test_case_id, data_len, scan_req_notify_enable",
    [
        (2, "C528506", 1, 0),
        (2, "C528507", 31, 0),
        (2, "C528508", 200, 0),
        (2, "C528509", 200, 1),
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_Scannable_non_conn_ADV_C528506_C528509(ble_dut, ble_sniffer, sl_collections,
                                        adv_type, test_case_id, data_len, scan_req_notify_enable):
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=data_len, scan_resp_len=1, test_case_id=test_case_id,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", scan_req_notify_enable=scan_req_notify_enable, adv_handle=0,
                                    ble_sniffer=ble_sniffer, powersave_p=True)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no Non-Connectable Scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Scannable") & (df[
                                                                                         "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Non-Connectable Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
    assert any(
        (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        range(len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
    # Assert if 1M PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets
    assert (df[
                '+PHY Type (LE BB)'] == '1M').all(), "\n\n **** Test case Failed with 1M PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** 1M PHY is used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n")
    # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
    assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if AUX_ADV-IND packets PHY does not match with the PHY mentioned in the AUX_EXT_IND packet
    def check_series(df):
        for i in range(len(df) - 2):
            if df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39]:
                aux_phy_values = df['Aux Phy'].iloc[i:i + 3].apply(
                    lambda x: re.search(r'\dM', str(x)).group() if pd.notna(x) else None)
                if aux_phy_values.nunique() == 1:
                    next_phy_type_values = df['+PHY Type (LE BB)'].iloc[i + 3:i + 6]
                    if next_phy_type_values.eq(aux_phy_values.iloc[0]).all() or df['Type'].iloc[i + 3:i + 6].eq(
                            'ADV_EXT_IND').all():
                        continue
                    else:
                        return False
                else:
                    return False
        return True

    result = check_series(df)
    assert result, "\n\n **** Test case Failed with AUX_ADV_IND packets PHY does not match with the PHY mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets PHY matches with the PHY mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if PDU length is not 11 in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_ADV_IND', 'PDU Length'] == data_len+10).all(), f"\n\n **** Test case Failed with PDU length is not {data_len+10} in AUX_ADV_IND packets ****\n\n"
    logger().info(f"\n\n **** PDU length is {data_len+10} in AUX_ADV_IND packets ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

"""
    Test case category : LE Ext Adv - Scannable undirected adv with scan_response_data on DUT and primary phy is LE Coded Phy, sec phy is LE Coded Phy.Ref device doing the LE_Ext_Scan for the adv packets 
    Device roles       : DUT is performing Peripheral role 
    Fixures used       : ble_sniffer - To caputre BLE OTA logs through Teledyne sniffer
"""
@pytest.mark.parametrize(
    "adv_type, test_case_id, data_len, scan_req_notify_enable",
    [
        (2, "C528510", 1, 0),
        (2, "C528511", 31, 0),
        (2, "C528512", 200, 0),
        (2, "C528513", 200, 1),
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_Scannable_undirected_ADV_C528510_C528513(ble_dut, remote_wiseconnect3, ble_sniffer, sl_collections,
                                        adv_type, test_case_id, data_len, scan_req_notify_enable):
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer, scanning_phys=4,
                                    pri_adv_phy=3, sec_adv_phy=3, data_len=data_len, scan_resp_len=data_len, test_case_id=test_case_id,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", scan_req_notify_enable=scan_req_notify_enable, adv_handle=0, central=remote_wiseconnect3,ble_client_address=ble_client_address, powersave_p=True)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no Non-Connectable Scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Scannable") & (df[
                                                                                         "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Non-Connectable Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
    assert any(
        (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        range(len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
    # Assert if LE CODED PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets
    assert (df[
                '+PHY Type (LE BB)'] == '125k').all(), "\n\n **** Test case Failed with LE CODED PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** LE CODED PHY is used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n")
    # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
    assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if PDU length is not data_len in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_ADV_IND', 'PDU Length'] == data_len+10).any(), f"\n\n **** Test case Failed with PDU length is not {data_len+10} in AUX_ADV_IND packets ****\n\n"
    logger().info(f"\n\n **** PDU length is {data_len+10} in AUX_ADV_IND packets ****\n\n")
    # Assert if PDU length is not data_len in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] == data_len + 8).all(), f"\n\n **** Test case Failed with PDU length is not {data_len + 8} in AUX_SCAN_RSP packets ****\n\n"
    logger().info(f"\n\n **** PDU length is {data_len + 8} in AUX_SCAN_RSP packets ****\n\n")
    # Assert if there is no AUX_SCAN_RSP packet found on 37, 38, 39 channels
    assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
        [37, 38, 39]) == False).all(), "\n\n **** Test case Failed with AUX_SCAN_RSP packet found on 37, 38, 39 channels ****\n\n"
    logger()
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
"""
    Test case category : LE Ext Adv - Scannable undirected adv with scan_response_data on DUT and primary phy is 1M, sec phy is 2M Phy.Ref device doing the LE_Ext_Scan for the adv packets
    Device roles       : DUT is performing Peripheral role 
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through Teledyne sniffer, wifi sniffer: TO validate caputured OTA logs through NUC(wireshark), 
                    bt_sniffer: To capture OTA logs through Ellysis.
"""
@pytest.mark.parametrize(
    "adv_type, test_case_id, data_len",
    [
        (2, "C528514", 1),
        (2, "C528515", 31),
        (2, "C528516", 200),
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_Scannable_undirected_ADV_C528514_C528516(ble_dut, ble_sniffer, remote_wiseconnect3, sl_collections,
                                        adv_type, test_case_id, data_len):
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer,
                                    pri_adv_phy=1, sec_adv_phy=2, data_len=data_len, scan_resp_len=data_len, test_case_id=test_case_id,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", scan_req_notify_enable=0,
                                    adv_handle=0, ble_client_address=ble_client_address, central=remote_wiseconnect3, scanning_phys=1, powersave_p=True)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Scannable") & (df[
                                                                                     "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Non-Connectable Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
    assert calculate_offset(
        df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
    logger().info(
        "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
    assert any(
        (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        range(len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
    # Assert if primary PHY is not 1M on ADV_EXT_IND packets
    assert (df[df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '1M').all(), '\n\n **** Test case Failed with primary PHY is not 1M on ADV_EXT_IND packets ****\n\n'
    logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
    # Assert if Secondary PHY is not 2M on AUX_ADV_IND packets
    assert (df[~df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '2M').all(), '\n\n **** Test case Failed with Secondary PHY is not 2M on AUX_ADV_IND packets ****\n\n'
    logger().info("\n\n **** Secondary PHY is 2M on AUX_ADV_IND packets ****\n\n")
    # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
    assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if PDU length is not data_len in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] == data_len + 8).all(), f"\n\n **** Test case Failed with PDU length is not {data_len + 8} in AUX_SCAN_RSP packets ****\n\n"
    logger().info(f"\n\n **** PDU length is {data_len + 8} in AUX_SCAN_RSP packets ****\n\n")
    #assert if PUD length is not dat_len in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_ADV_IND', 'PDU Length'] == data_len+10).all(), f"\n\n **** Test case Failed with PDU length is not {data_len+10} in AUX_ADV_IND packets ****\n\n"
    # Assert if there is no AUX_SCAN_RSP packet found on 37, 38, 39 channels
    assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin([37, 38, 39]) == False).all(), "\n\n **** Test case Failed with AUX_SCAN_RSP packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** AUX_SCAN_RSP packet found on 37,38,39 channels ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
"""
    Test case category : LE Ext Adv with filter policy enabled during LE Ext Adv 
    Device roles       : DUT is performing Peripheral role 
    Fixures used       : ble_sniffer - To caputre BLE OTA logs through Teledyne sniffer
"""
@pytest.mark.parametrize(
    "adv_type, test_case_id, adv_filter_policy, event_type",
    [
        (2, "C528575", 1, "0x2"),
        (1, "C528576", 2, "0x1"),
        (1, "C528577", 3, "0x1"),
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_AE_Scannable_filter_policy_C528575_C528577(ble_dut, ble_sniffer, remote_wiseconnect3, sl_collections,
                                        adv_type, test_case_id, adv_filter_policy, event_type):
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address,
                                    data_len=31, whitelist=1, adv_filter_policy=adv_filter_policy, test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    adv_handle=0, ble_sniffer=ble_sniffer, ble_client_address=ble_client_address, central=remote_wiseconnect3, powersave_p=True)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    if test_case_id == "C528575":
        # Assert if there is no non-connectable scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Scannable") & (df[
                                                                                     "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Scannable advertising mode found or Aux Pointer is not present ****\n\n"
        logger().info("\n\n **** Non-Connectable Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    else:
        # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df[
                                                                                         "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
        logger().info("\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
    assert any(
        (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        range(len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
    # Assert if primary PHY is not 1M on ADV_EXT_IND packets
    assert (df[df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '1M').all(), '\n\n **** Test case Failed with primary PHY is not 1M on ADV_EXT_IND packets ****\n\n'
    logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
    # Assert if Secondary PHY is not 1M on AUX_ADV_IND packets
    assert (df[~df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '1M').all(), '\n\n **** Test case Failed with Secondary PHY is not 1M on AUX_ADV_IND packets ****\n\n'
    logger().info("\n\n **** Secondary PHY is 1M on AUX_ADV_IND packets ****\n\n")
    # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
    assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
    # Assert if there is no AUX_SCAN_RSP packet found on 37, 38, 39 channels
    assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
        [37, 38, 39]) == False).all(), "\n\n **** Test case Failed with AUX_SCAN_RSP packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** AUX_SCAN_RSP packet found on 37,38,39 channels ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
"""
    Test case category : Overlapping Extended Advertising Events with primary phy as 1M and Secondary phy as 2M  
    Device roles       : DUT is performing Peripheral role
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through Teledyne sniffer, wifi sniffer: TO validate caputured OTA logs through NUC(wireshark), 
                    bt_sniffer: To capture OTA logs through Ellysis.
"""
# @pytest.mark.parametrize(
#     "adv_type, test_case_id, sec_adv_max_skip, event_type",
#     [
#         (1, "C163814", 1, "0x0"),
#         (1, "C163815", 15, "0x0"),
#         (1, "C163816", 255, "0x0"),
#         (1, "C163817", 8, "0x1"),
#         (4, "C163818", 8, "0x0"),
#         (5, "C163819", 1, "0x1"),
#     ],
# )
# @pytest.mark.ble_client("bt_wiseconnect")
# def test_verify_AE_Secondary_adv_with_max_skip_1_C163814_C163820(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer,
#                                         adv_type, test_case_id, sec_adv_max_skip, event_type):
#     ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
#     packet_filter1 = f"nordic_ble.phy == 0 && (btle.extended_advertising_header.mode == {event_type})"
#     rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
#                                     min_interval=320, max_interval=352, sec_adv_max_skip=sec_adv_max_skip, data_len=31,
#                                     pri_adv_phy=1, sec_adv_phy=2, test_case_id=test_case_id, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
#                                     adv_handle=0, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer,
#                                     packet_filter1={packet_filter1:"Positive"}, powersave_p=True)

"""
    Test case category : Two Advertising Sets with primary phy as 1M and sec phy as 2M 
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    Fixures used       : ble_sniffer - To caputre BLE OTA logs through Teledyne sniffer
"""
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, pri_adv_phy, sec_adv_phy, test_case_id, adv_handle, adv_handle_s2, min_interval, max_interval, min_interval_s2, max_interval_s2",
    [
        (1, 2, 0, 1, 1, 2, "C528578", 0, 1, 32, 32, 48, 48),
        (2, 0, 200, 120, 1, 2, "C528579", 0, 1, 32, 32, 48, 48),
        (1, 0, 120, 200, 1, 2, "C528580", 0, 1, 32, 32, 48, 48),
        (5, 6, 31, 31, 1, 2, "C528581", 0, 1, 32, 32, 48, 48),
        # (6, 4, 0, 31, 1, 2, "C528582", 0, 1, 32, 32, 48, 48),
        (5, 4, 31, 1,  1, 2, "C528583", 0, 1, 32, 32, 48, 48),
        (1, 4, 200, 1,  1, 2, "C528584", 0, 1, 32, 32, 48, 48),
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_2ADV_sets_PHY_1M_2M_C528578_to_C528584(ble_dut, ble_sniffer, remote_wiseconnect3, sl_collections,
                                        adv_type, adv_type_s2, data_len, data_len_s2, pri_adv_phy,
                                        sec_adv_phy, test_case_id, adv_handle, adv_handle_s2, min_interval, max_interval, min_interval_s2, max_interval_s2):
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2, ble_dut_address=ble_dut_address,
                                    min_interval=min_interval, max_interval=max_interval, data_len=data_len, data_len_s2=data_len_s2, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, test_case_id=test_case_id,
                                    adv_handle=adv_handle, adv_handle_s2=adv_handle_s2, ble_sniffer=ble_sniffer,
                                   ble_client_address=ble_client_address, central=remote_wiseconnect3, min_interval_s2=min_interval_s2, max_interval_s2=max_interval_s2, powersave_p=True)
    if adv_type in [1,5] or adv_type_s2 in [1,5]:
        # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df[
                                                                                      "Aux Pointer"] == "Present")]) >= 1, '\n\n **** Test case Failed with no Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n'
        logger().info("\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df[(df['Advertising Mode'] == 'Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))]['PDU Length'] > (data_len if adv_type == 1 else data_len_s2)).all(), "\n\n **** Test case Failed with PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type == 1 else data_len_s2} in AUX_ADV_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    if adv_type == [2,6] or adv_type_s2 == [2,6]:
        # Assert if there is no non-connectable scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Scannable") & (df[
                                                                                         "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Scannable advertising mode found or Aux Pointer is not present ****\n\n"
        logger().info("\n\n **** Non-Connectable Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df[(df['Advertising Mode'] == 'Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))]['PDU Length'] > (data_len if adv_type == 1 else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type == 1 else data_len_s2} in AUX_ADV_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    if adv_type in [0,4] or adv_type_s2 in [0,4]:
        # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                      "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with no Non-Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
        logger().info("\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df[(df['Advertising Mode'] == 'Non-Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))]['PDU Length'] > (data_len if adv_type in [0] else data_len_s2)).all(), "\n\n **** Test case Failed with PDU length is not data_len in AUX_ADV_IND packets ****\n\n"
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
        [37, 38, 39]) == False).all(), "\n\n **** Test case Failed with AUX_SCAN_RSP packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** AUX_SCAN_RSP packet found on 37,38,39 channels ****\n\n")
    # Assert if primary PHY is not 1M on ADV_EXT_IND packets
    assert (df[df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '1M').all(), "\n\n **** Test case Failed with primary PHY is not 1M on ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
    # Assert if secondary PHY is not 2M on AUX_ADV_IND packets
    assert (df[~df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '2M').all(), "\n\n **** Test case Failed with secondary PHY is not 2M on AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** Secondary PHY is 2M on AUX_ADV_IND packets ****\n\n")
    # Assert if PDU length is not data_len in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len).all() or (df.loc[df[
                       'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len_s2).all(), "\n\n **** Test case Failed with PDU length is not data_len in AUX_SCAN_RSP packets ****\n\n"
    logger().info(f"\n\n **** PDU length is {data_len} or {data_len_s2} in AUX_SCAN_RSP packets ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

"""
    Test case category : Two Advertising Sets with primary phy as LE Coded and sec phy as LE Coded  
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    Fixures used       : ble_sniffer - To caputre BLE OTA logs through Teledyne sniffer
"""
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, pri_adv_phy, sec_adv_phy, test_case_id, adv_handle, adv_handle_s2,",
    [
        (1, 2, 200, 200, 3, 3, "C528585", 0, 1),
        (2, 0, 200, 120, 3, 3, "C528586", 0, 1),
        (1, 6, 120, 200, 3, 3, "C528587", 0, 1),
        (5, 6, 31, 31, 3, 3, "C528588", 0, 1),
        # (6, 4, 0, 31, 3, 3, "C528589", 0, 1),
        (5, 0, 31, 1,  3, 3, "C528590", 0, 1),
        (1, 4, 200, 31,  3, 3, "C528591", 0, 1),
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_2ADV_sets_PHY_LECoded_C528585_to_C528591(ble_dut, ble_sniffer, remote_wiseconnect3, sl_collections,
                                        adv_type, adv_type_s2, data_len, data_len_s2, pri_adv_phy,
                                        sec_adv_phy, test_case_id, adv_handle, adv_handle_s2):
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2, ble_dut_address=ble_dut_address, ble_sniffer=ble_sniffer,
                                    min_interval=48, max_interval=48, min_interval_s2=64, max_interval_s2=64, data_len=data_len, data_len_s2=data_len_s2, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, test_case_id=test_case_id,
                                    adv_handle=adv_handle, adv_handle_s2=adv_handle_s2, scanning_phys=4, ble_client_address=ble_client_address, central=remote_wiseconnect3, powersave_p=True)
    if adv_type in [1,5] or adv_type_s2 in [1,5]:
        # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df[
                                                                                      "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info("\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df[(df['Advertising Mode'] == 'Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))]['PDU Length'] > (data_len if adv_type in [1,5] else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type in [1,5] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    if adv_type in [0,4] or adv_type_s2 in [0,4]:
        # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                      "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info("\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df[(df['Advertising Mode'] == 'Non-Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))]['PDU Length'] > (data_len if adv_type in [0,4] else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type in [0,4] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    if adv_type in [2,6] or adv_type_s2 in [2,6]:
        # Assert if there is no non-connectable scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Scannable") & (df[
                                                                                         "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info("\n\n **** Non-Connectable Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df[(df['Advertising Mode'] == 'Non-Connectable Scannable') & (~df['Chan'].isin([37, 38, 39]))]['PDU Length'] > (data_len if adv_type in [2,6] else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type in [2,6] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
        [37, 38, 39]) == False).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
    logger().info("\n\n **** AUX_SCAN_RSP packet found on 37,38,39 channels ****\n\n")
    # Assert if primary PHY is not LE CODED on ADV_EXT_IND packets
    assert (df[df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '125k').all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
    logger().info("\n\n **** Primary PHY is LE CODED on ADV_EXT_IND packets ****\n\n")
    # Assert if Secondary PHY is not LE CODED on AUX_ADV_IND packets
    assert (df[~df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '125k').all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
    logger().info("\n\n **** Secondary PHY is LE CODED on AUX_ADV_IND packets ****\n\n")
    # Assert if PDU length is not data_len in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len).all() or (df.loc[df[
                       'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len_s2).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
    logger().info(f"\n\n **** PDU length is {data_len} or {data_len_s2} in AUX_SCAN_RSP packets ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

"""
    Test case category : Two Advertising Sets with Legacy Adv and Extended Adv
    Device roles       : DUT is performing Peripheral role where Reference is performing Central
    Fixures used       : ble_sniffer - To caputre BLE OTA logs through Teledyne sniffer
"""
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2",
    [
        (1, 16, 200, 31, "C528592", 0, 1),
        (19, 2, 31, 200, "C528593", 0, 1),
        (18, 0, 31, 200, "C528594", 0, 1),
        (5, 21, 0, 0,  "C528595", 0, 1),
        # (25, 6, 0, 200, "C528596", 0, 1),
        (4, 16, 120, 31, "C528597", 0, 1),
        (2, 19, 120, 31, "C528598", 0, 1),
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_2ADV_sets_Legacy_Extended_C528592_to_C528598(ble_dut, ble_sniffer, remote_wiseconnect3, sl_collections,
                                        adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2,
                                        ):
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2, ble_dut_address=ble_dut_address,
                                    min_interval=32, max_interval=32, min_interval_s2=48, max_interval_s2=48, data_len=data_len, data_len_s2=data_len_s2, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    test_case_id=test_case_id, adv_handle=adv_handle, adv_handle_s2=adv_handle_s2, ble_sniffer=ble_sniffer,
                                    ble_client_address=ble_client_address, central=remote_wiseconnect3, powersave_p=True)
    if adv_type in [1,5] or adv_type_s2 in [1,5]:
        # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df[
                                                                                      "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info("\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df[(df['Advertising Mode'] == 'Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))]['PDU Length'] > (data_len if adv_type in [1,5] else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type in [1,5] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    if adv_type in [2,6] or adv_type_s2 in [2,6]:
        # Assert if there is no non-connectable scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Scannable") & (df[
                                                                                         "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info("\n\n **** Non-Connectable Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df[(df['Advertising Mode'] == 'Non-Connectable Scannable') & (~df['Chan'].isin([37, 38, 39]))]['PDU Length'] > (data_len if adv_type in [2,6] else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type in [2,6] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    if adv_type in [0,4] or adv_type_s2 in [0,4]:
        # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                      "Aux Pointer"] == "Present")]) >= 1, "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info("\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df[(df['Advertising Mode'] == 'Non-Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))]['PDU Length'] > (data_len if adv_type in [0,4] else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type in [0,4] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    if adv_type in [16] or adv_type_s2 in [16]:
        # Assert if there is no ADV_NONCONN_IND advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Type'] == "ADV_NONCONN_IND") & (df[
                                                                                      "Aux Pointer"] != "Present")]) >= 1, "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info("\n\n **** ADV_NONCONN_IND advertising mode found and Aux Pointer is not present ****\n\n")
        # Assert if PDU length is not data_len in ADV_NONCONN_IND packets
        assert (df[(df['Type'] == 'ADV_NONCONN_IND') & (df['Chan'].isin([37, 38, 39]))]['Len'] > (data_len if adv_type in [16] else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type in [16] else data_len_s2} in ADV_NONCONN_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    if adv_type in [19] or adv_type_s2 in [19]:
        # Assert if there is no ADV_NONCONN_IND advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Type'] == "ADV_IND") & (df[
                                                                                      "Aux Pointer"] != "Present")]) >= 1, "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info("\n\n **** ADV_IND advertising mode found and Aux Pointer is not present ****\n\n")
        # Assert if PDU length is not data_len in ADV_NONCONN_IND packets
        assert (df[(df['Type'] == 'ADV_IND') & (df['Chan'].isin([37, 38, 39]))]['Len'] > (data_len if adv_type in [19] else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type in [19] else data_len_s2} in ADV_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    if adv_type in [18] or adv_type_s2 in [18]:
        # Assert if there is no ADV_NONCONN_IND advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Type'] == "ADV_SCAN_IND") & (df[
                                                                                      "Aux Pointer"] != "Present")]) >= 1, "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info("\n\n **** ADV_SCAN_IND advertising mode found and Aux Pointer is not present ****\n\n")
        # Assert if PDU length is not data_len in ADV_NONCONN_IND packets
        assert (df[(df['Type'] == 'ADV_SCAN_IND') & (df['Chan'].isin([37, 38, 39]))]['Len'] > (data_len if adv_type in [18] else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type in [18] else data_len_s2} in ADV_SCAN_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    if adv_type in [21] or adv_type_s2 in [21]:
        # Assert if there is no ADV_NONCONN_IND advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Type'] == "ADV_DIRECT_IND") & (df[
                                                                                      "Aux Pointer"] != "Present")]) >= 1, "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info("\n\n **** ADV_DIRECT_IND advertising mode found and Aux Pointer is not present ****\n\n")
        # Assert if PDU length is not data_len in ADV_NONCONN_IND packets
        assert (df[(df['Type'] == 'ADV_DIRECT_IND') & (df['Chan'].isin([37, 38, 39]))]['Len'] > (data_len if adv_type in [21] else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type in [21] else data_len_s2} in ADV_DIRECT_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    # Assert if primary PHY is not 1M on ADV_EXT_IND packets
    assert (df[df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '1M').all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
    logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
    # Assert if Secondary PHY is not 1M on AUX_ADV_IND packets
    assert (df[~df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '1M').all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
    logger().info("\n\n **** Secondary PHY is 1M on AUX_ADV_IND packets ****\n\n")
    # Assert if PDU length is not data_len in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len).all() or (df.loc[df[
                       'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len_s2).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
    logger().info(f"\n\n **** PDU length is {data_len} or {data_len_s2} in AUX_SCAN_RSP packets ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

    """
    Test case category : Two Advertising Sets with Random Addr: primary phy as LE Coded and sec phy as LE Coded
    Device roles       : DUT is performing Peripheral role and Reference is performing Central role
    Fixures used       : ble_sniffer - To caputre BLE OTA logs through Teledyne sniffer
    """
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2",
    [
        (1, 2, 200, 200, "C528599", 0, 1),
        (2, 0, 200, 120, "C528600", 0, 1),
        (1, 6, 120, 200, "C528601", 0, 1),
        (5, 6, 31, 31,  "C528602", 0, 1),
        # (6, 4, 0, 31, "	C528603", 0, 1),
        (5, 0, 31, 1, "C528604", 0, 1),
        (1, 4, 200, 31, "C528605", 0, 1),
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_2ADV_sets_Legacy_Extended_C528599_to_C528605(ble_dut, ble_sniffer, remote_wiseconnect3, sl_collections,
                                        adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2,
                                        ):
    random_address="11:33:33:33:33:11"
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2, ble_dut_address=random_address,
                                    pri_adv_phy=3, sec_adv_phy=3, min_interval=48, max_interval=48, min_interval_s2=64, max_interval_s2=64, data_len=data_len, data_len_s2=data_len_s2, random_address=random_address, random_address_s2=random_address,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id, adv_handle=adv_handle,
                                    adv_handle_s2=adv_handle_s2, ble_sniffer=ble_sniffer, ble_client_address=ble_client_address, central=remote_wiseconnect3, powersave_p=True)
    if adv_type in [1,5] or adv_type_s2 in [1,5]:
        # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df[
                                                                                      "Aux Pointer"] == "Present") & (df[
                                                                                      "Ext Adv Address Type"] == "random")]) >= 1, "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info("\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df[(df['Advertising Mode'] == 'Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))]['PDU Length'] > (data_len if adv_type in [1,5] else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type in [1,5] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    if adv_type in [0,4] or adv_type_s2 in [0,4]:
        # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Non-Scannable") & (df[
                                                                                      "Aux Pointer"] == "Present") & (df[
                                                                                      "Ext Adv Address Type"] == "random")]) >= 1, "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info("\n\n **** Non-Connectable Non-Scannable advertising mode found and Aux Pointer is present and is advertising with random address ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df[(df['Advertising Mode'] == 'Non-Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))]['PDU Length'] > (data_len if adv_type in [0,4] else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type in [0,4] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    if adv_type in [2,6] or adv_type_s2 in [2,6]:
        # Assert if there is no non-connectable scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[(df['Advertising Mode'] == "Non-Connectable Scannable") & (df[
                                                                                         "Aux Pointer"] == "Present") & (df[
                                                                                      "Ext Adv Address Type"] == "random")]) >= 1, "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info("\n\n **** Non-Connectable Scannable advertising mode found and Aux Pointer is present and is advertising with random address ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df[(df['Advertising Mode'] == 'Non-Connectable Scannable') & (~df['Chan'].isin([37, 38, 39]))]['PDU Length'] > (data_len if adv_type in [2,6] else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type in [2,6] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
        [37, 38, 39]) == False).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
    logger().info("\n\n **** AUX_SCAN_RSP packets are not found ****\n\n")
    # Assert if primary PHY is not LE Coded on ADV_EXT_IND packets
    assert (df[df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '125k').all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
    logger().info("\n\n **** Primary PHY is LE CODED on ADV_EXT_IND packets ****\n\n")
    # Assert if secondary PHY is not LE Coded on AUX_ADV_IND packets
    assert (df[~df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '125k').all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
    logger().info("\n\n **** Secondary PHY is LE CODED on AUX_ADV_IND packets ****\n\n")
    # Assert if PDU length is not data_len in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len).all() or (df.loc[df[
                       'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len_s2).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
    logger().info(f"\n\n **** PDU length is {data_len} or {data_len_s2} in AUX_SCAN_RSP packets ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

"""
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another handle. Primary phy =1M and Sec Phy 1M
    Device roles       : DUT is performing Peripheral role and Reference is performing Central role
    Fixures used       : ble_sniffer - To caputre BLE OTA logs through Teledyne sniffer
"""
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2",
    [
        (1, 2, 200, 200, "C528606", 0, 1),
        (2, 0, 200, 120, "C528607", 0, 1),
        (1, 6, 120, 200, "C528608", 0, 1),
        (5, 6, 31, 31,  "C528609", 0, 1),
        (6, 4, 0, 31, "C528610", 0, 1),
        (5, 0, 31, 0, "C528611", 0, 1),
        (1, 4, 200, 31, "C528612", 0, 1),
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_2ADV_sets_Legacy_Extended_C528606_to_C528612(ble_dut, ble_sniffer, remote_wiseconnect3, sl_collections,
                                        adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2,
                                        ):
    random_address="11:33:33:33:33:11"
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, min_interval=32, max_interval=32,  min_interval_s2=48, max_interval_s2=48, data_len=data_len, data_len_s2=data_len_s2, random_address_s2=random_address,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id, adv_handle=adv_handle,
                                    adv_handle_s2=adv_handle_s2, ble_sniffer=ble_sniffer, ble_client_address=ble_client_address, central=remote_wiseconnect3, powersave_p=True)
    if adv_type in [1,5] or adv_type_s2 in [1,5]:
        # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[
                        (df['Advertising Mode'] == "Connectable Non-Scannable") &
                        (df['Aux Pointer'] == "Present") &
                        (df.apply(lambda row: row['Ext Adv Address Type'] == ("random" if adv_type_s2 in [1, 5] else "public"), axis=1))
                    ]) >= 1, "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** Connectable Non-Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if adv_type_s2 in [1, 5] else 'public'} ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df[(df['Advertising Mode'] == 'Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))]['PDU Length'] > (data_len if adv_type in [1,5] else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type in [1,5] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    if adv_type in [0,4] or adv_type_s2 in [0,4]:
        # Assert if there is no non-connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[
                       (df['Advertising Mode'] == "Non-Connectable Non-Scannable") &
                       (df['Aux Pointer'] == "Present") &
                       (df.apply(
                           lambda row: row['Ext Adv Address Type'] == ("random" if adv_type_s2 in [0, 4] else "public"),
                           axis=1))
                       ]) >= 1, "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** Non-Connectable Non-Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if adv_type_s2 in [0, 4] else 'public'} ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df[(df['Advertising Mode'] == 'Non-Connectable Non-Scannable') & (~df['Chan'].isin([37, 38, 39]))]['PDU Length'] > (data_len if adv_type in [0,4] else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type in [0,4] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    if adv_type in [2,6] or adv_type_s2 in [2,6]:
        # Assert if there is no connectable non-scannable advertising mode found and Aux Pointer is present
        assert len(df.loc[
                       (df['Advertising Mode'] == "Non-Connectable Scannable") &
                       (df['Aux Pointer'] == "Present") &
                       (df.apply(
                           lambda row: row['Ext Adv Address Type'] == ("random" if adv_type_s2 in [2, 6] else "public"),
                           axis=1))
                       ]) >= 1, "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** Non-Connectable Scannable advertising mode found, Aux Pointer is present and is advertising with {'random' if adv_type_s2 in [2, 6] else 'public'} ****\n\n")
        # Assert if PDU length is not data_len in AUX_ADV_IND packets
        assert (df[(df['Advertising Mode'] == 'Non-Connectable Scannable') & (~df['Chan'].isin([37, 38, 39]))]['PDU Length'] > (data_len if adv_type in [2,6] else data_len_s2)).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
        logger().info(f"\n\n **** PDU length is {data_len if adv_type in [2,6] else data_len_s2} in AUX_ADV_IND packets ****\n\n")
        # Assert if the calculated offset does not match with the time difference between the last channel index and the random channel index
        assert calculate_offset(
            df), "\n\n **** Test case Failed: Calculated Offset does not match with the time difference between the last channel index and the random channel index ****\n\n"
        logger().info(
            "\n\n **** Calculated Offset matches with the time difference between the last channel index and the random channel index ****\n\n")
    assert (df[df['Type'] == 'AUX_SCAN_RSP']['Chan'].isin(
        [37, 38, 39]) == False).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
    logger().info("\n\n **** AUX_SCAN_RSP packets are not found ****\n\n")
    # Assert if primary PHY is not 1M on ADV_EXT_IND packets
    assert (df[df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '1M').all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
    logger().info("\n\n **** Primary PHY is 1M on ADV_EXT_IND packets ****\n\n")
    # Assert if secondary PHY is not 1M on AUX_ADV_IND packets
    assert (df[~df['Chan'].isin([37, 38, 39])][
                '+PHY Type (LE BB)'] == '1M').all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
    logger().info("\n\n **** Secondary PHY is 1M on AUX_ADV_IND packets ****\n\n")
    # Assert if PDU length is not data_len in AUX_ADV_IND packets
    assert (df.loc[df[
                       'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len).all() or (df.loc[df[
                       'Type'] == 'AUX_SCAN_RSP', 'PDU Length'] > data_len_s2).all(), "\n\n **** Test case Failed with the reason no match found..! ****\n\n"
    logger().info(f"\n\n **** PDU length is {data_len} or {data_len_s2} in AUX_SCAN_RSP packets ****\n\n")
    logger().info("\n\n **** Test case is passed successfully..! ****\n\n")

"""
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another handle. Primary phy =1M and Sec Phy 2M
    Device roles       : DUT is performing Peripheral role and Reference is performing Central role
    Fixures used       : ble_sniffer - To caputre BLE OTA logs through Teledyne sniffer
"""
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2",
    [
        (1, 2, 200, 200, "C528613", 0, 1),
        (2, 0, 200, 120, "C528614", 0, 1),
        (1, 6, 120, 200, "C528615", 0, 1),
        (5, 6, 31, 31,  "C528616", 0, 1),
        (6, 4, 0, 31, "C528617", 0, 1),
        (5, 0, 31, 0, "C528618", 0, 1),
        (1, 4, 200, 31, "C528619", 0, 1),
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
            "ble_custom_ext_features": Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLEExtFeatureBITMAP.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features" : Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_PERIPHERALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_MAX_NBR_ATT_REC | Si91xBLEFeatureBITMAP.SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBITMAP.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBITMAP.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_2ADV_sets_Legacy_Extended_C1638255_to_C1638461(ble_dut, ble_sniffer, remote_wiseconnect3, sl_collections,
                                        adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2,
                                        event_type_1, event_type_2):
    random_address="11:33:33:33:33:11"
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=2, min_interval=32, max_interval=32,  min_interval_s2=48, max_interval_s2=48, data_len=data_len, data_len_s2=data_len_s2, random_address_s2=random_address,
                                    adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id, adv_handle=adv_handle,
                                    adv_handle_s2=adv_handle_s2, ble_sniffer=ble_sniffer, ble_client_address=ble_client_address, central=remote_wiseconnect3, powersave_p=True)

"""
    Test case category : Two adv sets using public addr of DUT on one handle and Random addr on another. Primary phy =LE COded and Sec Phy LE Coded
    Device roles       : DUT is performing Peripheral role 
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through Teledyne sniffer, wifi sniffer: TO validate caputured OTA logs through NUC(wireshark), 
                    bt_sniffer: To capture OTA logs through Ellysis.
"""
@pytest.mark.parametrize(
    "adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2",
    [
        (0, 1, 0, 0, "C163862", 0, 1),
        (1, 0, 0, 191, "C163863", 0, 1),
        (0, 5, 191, 0, "C163864", 0, 1),
        (0, 2, 191, 191,  "C163865", 0, 1),
        (1, 4, 200, 200, "C163866", 0, 1),
        (0, 1, 200, 0, "C163867", 0, 1),
        (0, 5, 474, 0, "C163868", 0, 1),
    ],
)
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_2ADV_sets_Legacy_Extended_C1638262_to_C1638468(ble_dut, rs_helper_ble, bt_sniffer,
                                        adv_type, adv_type_s2, data_len, data_len_s2, test_case_id, adv_handle, adv_handle_s2,
                                        ):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    random_address="11:33:33:33:33:11"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=adv_type, adv_type_s2=adv_type_s2, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=3, sec_adv_phy=3, min_interval=32, max_interval=32, data_len=data_len, data_len_s2=data_len_s2,
                                    random_address_s2=random_address, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id, adv_handle=adv_handle,
                                    adv_handle_s2=adv_handle_s2, powersave_p=True)

"""
    Test case category : 
    1. Enable - Disable Ext Adv in Loop while ref device is continously scanning for adv type = scannable undirected (C163869 to C163880)
    2. Enable - Disable Ext Adv in Loop ,adv type = non conn non scan undirected (C163881 to C163886)
    Device roles       : DUT is performing Peripheral role 
"""
@pytest.mark.parametrize(
    "adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, event_type_1, random_address",
    [
        (1, 32, 40, "C163869", 1, 1, "0x1", None),
        (1, 32, 40, "C163870", 1, 2, "0x1", None),
        (1, 32, 40, "C163871", 3, 3, "0x1", None),
        (1, 32, 40, "C163872", 1, 1, "0x1", "11:33:33:33:33:11"),
        (1, 32, 40, "C163873", 2, 2, "0x1", "11:33:33:33:33:11"),
        (1, 32, 40, "C163874", 3, 3, "0x1", "11:33:33:33:33:11"),
        (1, 80, 160, "C163875", 1, 1, "0x1", None),
        (1, 80, 160, "C163876", 1, 2, "0x1", None),
        (1, 80, 160, "C163877", 3, 3, "0x1", None),
        (1, 80, 160, "C163878", 1, 1, "0x1", "11:33:33:33:33:11"),
        (1, 80, 160, "C163879", 2, 2, "0x1", "11:33:33:33:33:11"),
        (1, 80, 160, "C163880", 3, 3, "0x1", "11:33:33:33:33:11"),
        (0, 32, 40, "C163881", 1, 1, "0x0", None),
        (0, 32, 40, "C163882", 1, 2, "0x0", None),
        (0, 32, 40, "C163883", 3, 3, "0x0", None),
        (0, 32, 40, "C163884", 1, 1, "0x0", "11:33:33:33:33:11"),
        (0, 32, 40, "C163885", 2, 2, "0x0", "11:33:33:33:33:11"),
        (0, 32, 40, "C163886", 3, 3, "0x0", "11:33:33:33:33:11"),
    ],
)
@pytest.mark.ble_client("bt_wiseconnect")
def test_verify_Enable_Disable_Ext_Adv_scannable_undirected_C163869_C163886(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer, bt_sniffer,
                                        adv_type, min_interval, max_interval, test_case_id, pri_adv_phy, sec_adv_phy, event_type_1, random_address):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    packet_filter1 = f"(btle.extended_advertising_header.mode == {event_type_1})"
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=adv_type, ble_dut_address=ble_dut_address, bt_sniffer=bt_sniffer,
                                    pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, max_ae_events=20, adv_async_required=True,  min_interval=min_interval, max_interval=max_interval,
                                    data_len=19, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id=test_case_id, adv_handle=0,
                                    ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer, loop_count=5,
                                    packet_filter1={packet_filter1:"Positive"}, random_address=random_address, powersave_p=True)

## Negative Test scenarios

""" Test case : This test case will verify 0x04c error, when legacy and ext adv started together with single adv set"""
def test_verify_Negative_case_C163735(ble_dut, rs_helper_ble):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=160, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id="C163736",
                                    dont_cleanup=True, test_in_progress=True)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=17, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id="C163736",
                                    error_expected= "Error code: 0x4e0c Msg: Command disallowed Command")

"""Test case : This test case will verify invalid adv handle"""
@pytest.mark.skip ("test case is not failing with invalid adv handle")
def test_verify_Negative_case_C163736(ble_dut, rs_helper_ble, ble_sniffer, wifi_sniffer):
    packet_filter1 = f"(btle.extended_advertising_header.mode == 0x0)"
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=0, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=160, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", test_case_id="C163736",
                                    adv_handle=300000, packet_filter1={packet_filter1:"Positive"}, ble_sniffer=ble_sniffer, wifi_sniffer=wifi_sniffer)

"""Test case: This test case will verify terminated callback event with error 60, wit duration value 256ms"""
def test_verify_Negative_case_C163737(ble_dut, rs_helper_ble):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    duration=256, adv_async_required=True)

"""Test case: This test case will verify terminated callback event with error 67, with max ae events value 0x5"""
def test_verify_Negative_case_C163738(ble_dut, rs_helper_ble):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    max_ae_events=5, adv_async_required=True)

"""Test case: This test case will verify invalid adv handle error 0x4e42 for set_adv_data command"""
def test_verify_Negative_case_C163739(ble_dut, rs_helper_ble):
    ble_dut_address=rs_helper_ble.ble_start(ble_dut=ble_dut)
    rs_helper_ble.BLE_AE().verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                    pri_adv_phy=1, sec_adv_phy=1, data_len=31, adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                    invalid_data_hdl=99, dont_cleanup=True, error_expected= "0x4e42")

"""Test case: This test case will verify error 0x4e12 after setting filter_duplicates =2 and duraion/period =0 during scan enable"""
def test_verify_Negative_case_C163740(ble_dut, rs_helper_ble):
    rs_helper_ble.BLE_AE().verify_ae_scan(central=ble_dut, filter_duplicates=2, error_expected="0x4e12", dont_cleanup=True)

"""Test case: This test case will verify error 0x4e12 after setting duraion is greater or equal to period during scan enable"""
def test_verify_Negative_case_C163741(ble_dut, rs_helper_ble):
    rs_helper_ble.BLE_AE().verify_ae_scan(central=ble_dut, duration=500, period=500, error_expected="0x4e12", dont_cleanup=True)

"""Test case: This test case will verify error 0x4e12 after setting scan enable with own add type as random and not setting random add prior"""
def test_verify_Negative_case_C163742(ble_dut, rs_helper_ble):
    rs_helper_ble.BLE_AE().verify_ae_scan(central=ble_dut, own_addr_type=1, error_expected="0x4e12", dont_cleanup=True)

"""Test case: This test case will verify error 0x4e12 not come after setting scan enable with own add type as random and setting random add prior"""
@pytest.mark.skip ("set random address is failing")
def test_verify_Negative_case_C163743(ble_dut, rs_helper_ble):
    rs_helper_ble.BLE_AE().verify_ae_scan(central=ble_dut, own_addr_type=1, random_address="AA:BB:CC:11:23:33")

"""Test case: This test case will verify error 0x4e12 not come after setting scan enable with own add type as random and setting random add prior"""
@pytest.mark.skip ("Expected error is not observed")
def test_verify_Negative_case_C163744(ble_dut, rs_helper_ble):
    rs_helper_ble.BLE_AE().verify_ae_scan(central=ble_dut, interval=48, window=49)