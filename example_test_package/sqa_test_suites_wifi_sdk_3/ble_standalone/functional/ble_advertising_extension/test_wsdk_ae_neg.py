import pytest
import pandas as pd
import re
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
from utf.utils.logger import get_logger
from datetime import timedelta, datetime
from utf_wiseconnect_3.tests.sl_status import SLStatus


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
        Bhuvaneswari
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
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
@pytest.mark.test_src_map_id('C528658')
def test_verify_incorrect_handle_value_C528658(ble_dut, ble_sniffer, sl_collections):
    """ Verifying the 0x12 for incorrect adv handle value in set ext adv parameters."""
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
        ble_dut.interfaces.wifi.ble_get_max_no_of_supp_adv_sets(no_adv_sets=1)
        ble_dut.interfaces.bluetooth.ble_set_ae_params(adv_event_prop=0, adv_handle=240, primary_adv_intterval_min=48,
                                                       primary_adv_intterval_max=48, own_addr_type=0, peer_addr_type=0,
                                                       remote_dev_addr="00:00:00:00:00:00", primary_adv_phy= 1,
                                                       sec_adv_phy=1, sec_adv_max_skip=1, scan_req_notify_enable=1,
                                                       adv_filter_policy=0, timeout=30,
                                                       expected_status=SLStatus.SL_STATUS_BT_INVALID_PARAMETER)
        logger().info("Expected error and received error matches successfully")
    except Exception as error:
        logger().info(f"Excepted error does not match with the received error: {error}")


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
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
@pytest.mark.test_src_map_id('C528659')
def test_verify_limited_duration_in_le_ext_adv_enable_command_C528659(ble_dut, ble_sniffer, sl_collections):
    """ Verifying limited duration Ext Advertisng by changing the duration parameter in the LE_EXT_ADV_Enable command."""
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    df = sl_collections.verify_adv(peripheral=ble_dut, adv_type=1, ble_dut_address=ble_dut_address,
                                   ble_sniffer=ble_sniffer,
                                   pri_adv_phy=1, sec_adv_phy=1, data_len=31, test_case_id="528659",
                                   adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA", duration=500, adv_async_required=1, powersave_p=True)
    # Assert if there is no ADV_EXT_IND packet found on 37, 38, 39 channels
    assert all(df.loc[df['Chan'].isin([37, 38,
                                       39]), 'Type'] == 'ADV_EXT_IND'), "\n\n **** Test case Failed with no ADV_EXT_IND packet found on 37, 38, 39 channels ****\n\n"
    logger().info("\n\n **** ADV_EXT_IND packet found on 37,38,39 channels ****\n\n")
    # Assert if there is no Connectable Non-Scannable advertising mode found and Aux Pointer is present
    assert len(df.loc[(df['Advertising Mode'] == "Connectable Non-Scannable") & (df["Aux Pointer"] == "Present")]) >= 1,\
        "\n\n **** Test case Failed with no Connectable Non-Scannable advertising mode found or Aux Pointer is not present ****\n\n"
    logger().info("\n\n **** Connectable Non-Scannable advertising mode found and Aux Pointer is present ****\n\n")
    # Assert if there is no AUX_ADV_IND packet found after three ADV_EXT_IND packets
    assert any(
        (df['Chan'].iloc[i:i + 3].tolist() == [37, 38, 39] and df['Chan'].iloc[i + 3] not in [37, 38, 39]) for i in
        range(
            len(df) - 3)), "\n\n **** Test case Failed with no AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n"
    logger().info("\n\n **** AUX_ADV_IND packet found after three ADV_EXT_IND packets ****\n\n")
    # Assert if 1M PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets
    assert (df[
                '+PHY Type (LE BB)'] == '1M').any(), "\n\n **** Test case Failed with 1M PHY is not used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n"
    logger().info("\n\n **** 1M PHY is used on both AUX_EXT_IND and AUX_ADV_IND packets ****\n\n")
    # Assert if AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet
    assert (df['Chan'].rolling(window=3).apply(lambda x: list(x) == [37, 38, 39], raw=False).shift(-2).fillna(
        False).astype(bool) & df['LL Channel'].rolling(window=3).apply(lambda x: len(set(x)) == 1, raw=False).shift(
        -2).fillna(False).astype(bool) & (df['LL Channel'].shift(-2) == df['Chan'].shift(-3)).fillna(False).astype(
        bool)).any(), "\n\n **** Test case Failed with AUX_ADV_IND packets channel index does not match with the channel index mentioned in the AUX_EXT_IND packet ****\n\n"
    logger().info(
        "\n\n **** AUX_ADV_IND packets channel index matches with the channel index mentioned in the AUX_EXT_IND packet ****\n\n")
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
    # Extract the time part from the original 'Timestamp' column
    df['Time'] = df['Timestamp'].apply(lambda x: re.search(r"\d+:\d+\.\d+", str(x)).group())
    # Find indices where the sequence 37, 38, 39 occurs
    sequence = [37, 38, 39]
    indices = df.index[df['Chan'].rolling(window=3).apply(lambda x: list(x) == sequence, raw=True) == 1].tolist()

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
    tolerance = timedelta(seconds=float(0.45))
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
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
@pytest.mark.test_src_map_id('C528661')
def test_verify_non_existing_adv_handle_C528661(ble_dut, ble_sniffer, sl_collections):
    """Verifying 0x42 error code for non-existing adv_hdle in le_set_ext_adv_data command.Checking the same for
    LE_Set_Ext_Scan_Response_data command. Check the same for LE_Set_Ext_Adv_Enable command."""
    ble_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, set_smp=1)
    ble_dut.interfaces.bluetooth.ble_set_ae_params(adv_handle=0, primary_adv_intterval_min=48,
                                                   primary_adv_intterval_max=48, own_addr_type=0, sec_adv_max_skip=1,
                                                   peer_addr_type=0)
    ble_dut.interfaces.bluetooth.ble_set_ae_data(type=1, adv_handle=68, operation=3,
                                                 data_len=25, data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                                 expected_status=SLStatus.SL_STATUS_BT_INVALID_DATA_HANDLE)
    ble_dut.interfaces.bluetooth.ble_set_ae_data(type=1, adv_handle=0, operation=3,
                                                 data_len=25, data="AE_PERIPHERAL_DATA_AE_PERIPHERA")
    ble_dut.interfaces.bluetooth.ble_set_ae_data(type=3, adv_handle=68, operation=3,
                                                 data_len=25, data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
                                                 expected_status=SLStatus.SL_STATUS_BT_INVALID_DATA_HANDLE)


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
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
@pytest.mark.test_src_map_id('C528662')
def test_verify_scan_enable_without_random_address_C528662(ble_dut, ble_sniffer, sl_collections):
    """Test case: This test case will verify error 0x4e12 after setting scan enable with own add type as random and not setting random add prior"""
    sl_collections.verify_ae_scan(central=ble_dut, own_addr_type=1,
                                  error_expected=SLStatus.SL_STATUS_BT_INVALID_PARAMETER, dont_cleanup=True)


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
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
@pytest.mark.test_src_map_id('C528663')
def test_verify_error_duration_period_equal_in_le_ext_scan_enable_C528663(ble_dut, ble_sniffer, sl_collections):
    """ Verifying that 0x12 error is observed when duration is equal or greater than period in LE_EXT_SCAN_ENABLE
    command."""
    sl_collections.verify_ae_scan(central=ble_dut, duration=500, period=500,
                                  error_expected=SLStatus.SL_STATUS_BT_INVALID_PARAMETER, dont_cleanup=True)


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
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
@pytest.mark.test_src_map_id('C528664')
def test_verify_error_filter_duplicate_in_le_ext_scan_enable_C528664(ble_dut, ble_sniffer, sl_collections):
    """ Verifying the 0x4e12 error is observed when filter_duplicate = 0x02 and duration/period is zero in
    LE_EXT_SCAN_ENABLE command."""
    sl_collections.verify_ae_scan(central=ble_dut, filter_duplicates=2,
                                  error_expected=SLStatus.SL_STATUS_BT_INVALID_PARAMETER, dont_cleanup=True)
