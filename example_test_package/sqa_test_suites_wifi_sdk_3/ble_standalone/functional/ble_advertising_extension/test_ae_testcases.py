import pytest
import pandas as pd
import re
import string
from example_test_package.conftest import rs_helper_ble
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertService
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertLevelCharacteristic
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import (BodySensorLocationCharacteristic,
                                                                                HeartRateControlPointCharacteristic,
                                                                                HeartRateMeasurementCharacterstic)
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService, HealthThermometerMeasurementCharacteristic
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
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
from utf.interfaces.bluetooth.bluetooth_interface import (
    BluetoothInterface,
    BTRole,
    BTProfile,
    BTEvents,
    BLEPermissions,
    )

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
import random
lock = threading.Lock()

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


def _normalize_sniffer_df(df: pd.DataFrame) -> pd.DataFrame:
    # Normalize column names across different exports
    col_map = {}
    for c in df.columns:
        lc = str(c).strip().lower()
        if lc in ("type", "packet type", "pdu type"):
            col_map[c] = "Type"
        elif lc in ("chan", "channel", "rf channel"):
            col_map[c] = "Chan"
        elif lc in ("timestamp", "time"):
            col_map[c] = "Timestamp"
        elif lc in ("advA", "advertiser address", "advertiser"):
            col_map[c] = "Advertiser Address"
    if col_map:
        df = df.rename(columns=col_map)

    # Ensure expected columns exist (create missing as empty where safe)
    if "Type" not in df.columns:
        raise AssertionError("Sniffer CSV missing required column: Type")
    if "Chan" not in df.columns:
        df["Chan"] = pd.NA

    # Normalize types to canonical names
    def norm_type(v: object) -> str:
        s = str(v).upper()
        m = re.search(r"\b(ADV_EXT_IND|AUX_ADV_IND)\b", s)
        return m.group(1) if m else s.strip()

    df["Type_norm"] = df["Type"].apply(norm_type)
    # Chan sometimes comes as strings; coerce to numeric
    df["Chan"] = pd.to_numeric(df["Chan"], errors="coerce")
    return df


def validate_adv_ext_ind_and_aux_adv_ind_ota(
    exported_csv_file: str,
    test_case_id: str,
    require_channel_checks: bool = True,
    min_adv_ext_ind: int = 1,
    min_aux_adv_ind: int = 1,
) -> None:
    """
    OTA validation for BLE Advertising Extensions:
      - ADV_EXT_IND must be present (primary PDU)
      - AUX_ADV_IND must be present (secondary PDU)

    `exported_csv_file` should be returned by:
      ble_sniffer.interfaces.sniffer.export_to_csv("LE", "LE ADV")
    """
    df = pd.read_csv(exported_csv_file)
    df = _normalize_sniffer_df(df)

    adv_ext = df[df["Type_norm"] == "ADV_EXT_IND"]
    aux_adv = df[df["Type_norm"] == "AUX_ADV_IND"]

    assert len(adv_ext) >= min_adv_ext_ind, (
        f"[{test_case_id}] No/insufficient ADV_EXT_IND packets found "
        f"(found={len(adv_ext)}, expected>={min_adv_ext_ind})"
    )
    assert len(aux_adv) >= min_aux_adv_ind, (
        f"[{test_case_id}] No/insufficient AUX_ADV_IND packets found "
        f"(found={len(aux_adv)}, expected>={min_aux_adv_ind})"
    )
    logger().info(f'\n\naux_adv_in packets found:{len(aux_adv)}')
    logger().info(f'\n\nadv_ext_ind packets found:{len(adv_ext)}')
    if require_channel_checks:
        # Primary advertising channels: 37/38/39
        prim_ok = adv_ext["Chan"].isin([37, 38, 39]).any()
        # Secondary is typically on data channels 0-36
        sec_ok = aux_adv["Chan"].between(0, 36, inclusive="both").any()

        assert prim_ok, f"[{test_case_id}] ADV_EXT_IND not observed on channels 37/38/39"
        assert sec_ok, f"[{test_case_id}] AUX_ADV_IND not observed on any data channel 0-36"


def connect_devices(self):
    logger().info("Connecting BLE devices...")
    self.ble_dut.interfaces.wifi.ble_extended_connect_with_params(
        remote_dev_addr=self.ble_client_address,
        remote_addr_type=0,
        initiator_filter_policy=0,
        init_phys=7,
        ConnIntervalMin=160,
        ConnIntervalMax=160, timeout=180
    )
    time.sleep(60)
    state = self.ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"Device state: {state_int}")
    assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
    # Link Key Extraction
    logger().info("Extracting link key...")
    tw = Stopwatch()
    link_key = ""
    while tw.elapsed_sec < 120:
        events = self.ble_dut.interfaces.wifi.get_async_events()
        logger().info(f"Link key events: {events}")
        for event in events:
            if "link_key" in event.event_data:
                logger().info(f"Link key event data: {event.event_data}")
                event_data = event.event_data
                link_key_data = re.findall("link_key::.*", event_data)
                link_key_data_str = re.split(":<", link_key_data[0])
                link_key_data_hex = re.split(":", link_key_data_str[0])
                link_key = "0x"
                for hex_data_part in link_key_data_hex:
                    hex_data_part = hex_data_part.replace(" ", "")
                    if len(hex_data_part) == 1:
                        hex_data_part = '0' + hex_data_part
                    link_key = link_key + hex_data_part
            else:
                continue
        if link_key:
            break
    link_key = link_key.replace(" ", "")
    link_key = link_key.replace("link_key", "")
    link_key_pattern = r"(0x[0-9a-fA-F]+)"
    # Apply the regex
    match = re.search(link_key_pattern, link_key)
    if match:
        link_key = match.group(1)  # Extract the matched link key
        print(f"Extracted Link Key: {link_key}")
    else:
        print("Link key not found.")
    assert len(link_key) > 0, "Link key is not extracted"
    self.link_key = link_key  # Store the extracted link key
    return link_key


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

def service_discovery_on_remote(ble_dut, ble_client_address, service_uuid=None, char_uuid=None, characteristic=None):
    logger().info("\n\n ***** Performing GATT profile discovery on Remote (raspi)  ***** \n\n\n")
    # get all profiles
    uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_client_address, async_timeout=120)
    #logger().info(f"UUIds {uuids}")
    if len(uuids)==0:
        time.sleep(2)
        uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_client_address,
                                                               async_timeout=120)
        logger().info(f"UUIds {uuids}")

    assert len(uuids) > 0, "uuids are empty"
    #  resolve profile
    start_handle, end_handle, data = ble_dut.interfaces.wifi.ble_get_profile_async(
        ble_remote_dev_address=ble_client_address,
        uuid=int(str(service_uuid), 16),
        async_timeout=60)
    logger().info(f"start_handle:{start_handle}, end_handle:{end_handle}")
    assert start_handle is not None
    assert end_handle is not None
    #
    char_uuids, write_handles, char_properties = ble_dut.interfaces.wifi.ble_get_char_services_async(
        ble_remote_dev_address=ble_client_address,
        start_handle=int(start_handle, 16),
        end_handle=int(end_handle, 16),
        async_timeout=60)
    logger().info(
        f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
        f"{char_properties}")

    assert char_uuid in char_uuids, "Unable to find {} uuid".format(char_uuid)
    index = char_uuids.index(char_uuid)
    logger().info(f"UUID's are:{char_uuids}")
    logger().info(f"write_handles:{write_handles}")
    logger().info(f"index:{index}")
    logger().info(f"characteristic:{characteristic}")
    logger().info(f"char_properties:{int(char_properties[index])}")
    logger().info(type(characteristic))
    logger().info(type(int(char_properties[index])))
    logger().info("validateing the characteristic property")
    assert char_properties[index].isdigit(), "Character property found is not an integer"
    assert characteristic == int(char_properties[index]), "Invalid character property found"
    write_handle = int(write_handles[index], 16)
    logger().info(f"write_handle:{write_handle}")
    assert write_handle > 0, "Unable to get write handle for configured service"

    return write_handle
def service_discovery_on_remote_1(remote_wiseconnect3, ble_client_address, service_uuid=None, char_uuid=None, characteristic=None):
    logger().info("\n\n ***** Performing GATT profile discovery on Remote (raspi)  ***** \n\n\n")
    # get all profiles
    uuids = remote_wiseconnect3.interfaces.sapi.ble_get_profiles_async(ble_remote_dev_address=ble_client_address, async_timeout=120)
    #logger().info(f"UUIds {uuids}")
    if len(uuids)==0:
        time.sleep(2)
        uuids = remote_wiseconnect3.interfaces.sapi.ble_get_profiles_async(ble_remote_dev_address=ble_client_address,
                                                               async_timeout=120)
        logger().info(f"UUIds {uuids}")

    assert len(uuids) > 0, "uuids are empty"
    #  resolve profile
    start_handle, end_handle, data = remote_wiseconnect3.interfaces.sapi.ble_get_profile_async(
        ble_remote_dev_address=ble_client_address,
        uuid=int(str(service_uuid), 16),
        async_timeout=60)
    logger().info(f"start_handle:{start_handle}, end_handle:{end_handle}")
    assert start_handle is not None
    assert end_handle is not None
    char_uuids, write_handles, char_properties = remote_wiseconnect3.interfaces.sapi.ble_get_char_services_async(
        ble_remote_dev_address=ble_client_address,
        start_handle=int(start_handle, 16),
        end_handle=int(end_handle, 16),
        async_timeout=60)
    logger().info(
        f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
        f"{char_properties}")

    assert char_uuid in char_uuids, "Unable to find {} uuid".format(char_uuid)
    index = char_uuids.index(char_uuid)
    logger().info(f"UUID's are:{char_uuids}")
    logger().info(f"write_handles:{write_handles}")
    logger().info(f"index:{index}")
    logger().info(f"characteristic:{characteristic}")
    logger().info(f"char_properties:{int(char_properties[index])}")
    logger().info(type(characteristic))
    logger().info(type(int(char_properties[index])))
    logger().info("validateing the characteristic property")
    assert char_properties[index].isdigit(), "Character property found is not an integer"
    assert characteristic == int(char_properties[index]), "Invalid character property found"
    write_handle = int(write_handles[index], 16)
    logger().info(f"write_handle:{write_handle}")
    assert write_handle > 0, "Unable to get write handle for configured service"
    return write_handle

def configure_buffer_mode(self, mode=None, count=None):
    logger().info(f"*******Configure Buffer Mode:{mode} and Buffer count:{count} ****************")
    self.ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=self.ble_client_address,
                                                            buffer_mode=mode,
                                                            buffer_count=count)
    logger().info(f"*******Configure Buffer Mode:{mode} and Buffer count:{count} Success ****************")


def service_discovery_on_dut(ble_dut, service_uid=None, char_uid=None):
    time.sleep(3)
    servs, chars = ble_dut.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
    time.sleep(5)
    logger().info(f"{servs} {chars}")
    assert len(servs) > 0, "no services fetched"
    assert len(chars) > 0, "fetched characters are empty"

    char_path, char_props = ble_dut.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
        services=servs,
        service_uid=service_uid,
        char_uid=char_uid)
    time.sleep(5)
    logger().info(f"{char_props}")
    assert char_path, "characters are empty"
    assert len(char_props) > 0, "length of characters is 0"
    logger().info("------CHARACTERISTICS----")
    return char_path, char_props

def buffer_configuration_mode(ble_dut, ble_client_address, buffer_mode, buffer_count):
    logger().info(f"*******Configure Buffer Mode:{buffer_mode} and Buffer count:{buffer_count} ****************")
    ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                       buffer_mode=buffer_mode,
                                                       buffer_count=buffer_count)
    logger().info(f"*******Configure Buffer Mode:{buffer_mode} and Buffer count:{buffer_count} Success ****************")

def ble_ae_slave(ble_dut, remote_wiseconnect3s, ble_dut_address, ble_client_address, sl_collections, pri_adv_phy=1, sec_adv_phy=1, link_key1=None):
    ble_dut.interfaces.wifi.ble_set_smp(set_smp=0)
    remote_wiseconnect3s[0].interfaces.wifi.ble_set_smp(set_smp=1)
    remote_wiseconnect3s[0].interfaces.wifi.ble_get_max_no_of_supp_adv_sets(no_adv_sets=1)
    adv_type = 1
    time.sleep(60)
    remote_wiseconnect3s[0].interfaces.wifi.ble_ae_set_scan_params(ble_addr_type=0,
                                                   scanning_phys=1,
                                                   scanning_filter_policy=0,
                                                   scan_type=1,
                                                   scan_type_sec=1,
                                                   ScanInterval=48,
                                                   ScanWindow=48,
                                                   remote_addr_type=0,
                                                   scan_interval_sec=48,
                                                   scan_window_sec=30)
    logger().info("******* scan enable second peer ****************")
    remote_wiseconnect3s[0].interfaces.wifi.ble_ae_set_scan_enable(enable=1,
                                                   filter_duplicates=0,
                                                   duration=0,
                                                   period=0, remote_address=ble_dut_address)

    remote_wiseconnect3s[0].interfaces.wifi.ble_ae_set_scan_enable(enable=0,
                                                   filter_duplicates=0,
                                                   duration=0, period=0,
                                                   remote_address=ble_dut_address)
    time.sleep(4)
    logger().info("getting the device state")
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"\nDevice state: {state_int}")
    retries = 3
    for retry in range(retries):
        try:
            remote_wiseconnect3s[0].interfaces.wifi.ble_extended_connect_with_params(remote_dev_addr=ble_dut_address,
                                                                     remote_addr_type=0,
                                                                     initiator_filter_policy=0,
                                                                     init_phys=7,
                                                                     ConnIntervalMin=50,
                                                                     ConnIntervalMax=50)
            time.sleep(60)
            logger().info("\nChecking connection status of BLE")
            state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            logger().info(f"\nDevice state: {state_int}")
            assert state_int == 8, "DUT BLE device is not in connected state"
            break
        except Exception as ex:
            logger().info(f"Exception occurred while connecting to BLE device: {str(ex)}")
            logger().info(f"BLE connection failed with retries {retry + 1}")
            if retry == retries - 1:
                raise

    tw = Stopwatch()
    link_key2 = ""
    while tw.elapsed_sec < 180:
        events = ble_dut.interfaces.bluetooth.get_async_events()  # since_time=0)
        logger().info(f"---------------->Events: {events}")
        for event in events:
            logger().info(f"---------------->Event Data: {event.event_data}")
            if "link_key" in event.event_data:
                event_data = event.event_data
                link_key_data = re.findall("((?<=link_key:: ).*:)", event_data)[-1]
                logger().info(f"link_key_data : {link_key_data}")
                link_key = '0x' + "".join(
                    [i.strip() if len(i.strip()) == 2 else '0' + i.strip() for i in link_key_data.split(":")][:16])
                if link_key1 != link_key:
                    logger().info(f"LINK-GENERATED:{link_key}")
                    link_key2 = link_key
                    break
            else:
                continue
        if link_key1 != link_key2 and link_key2:
            logger().info(f"LINK-GENERATED:{link_key2}")
            break
    logger().info(f"-------link_key1--------:{link_key1}")
    logger().info(f"----------link_key2----------:{link_key2}")
    logger().info(f"**************Second Link Key Extracted: {link_key2}***************")
    assert len(link_key2) == 34, f"link key is not proper format"
    return link_key2

def ble_ae_master(ble_dut, remote_wiseconnect3,  sl_collections, ble_client_address, ble_dut_address, adv_data, pri_adv_phy=1, sec_adv_phy=1, remote_wiseconnect3s=None):
    ble_dut.interfaces.wifi.ble_set_smp(set_smp=1)
    remote_wiseconnect3.interfaces.wifi.ble_set_smp(set_smp=0)
    logger().info("\n\n ***** Configuring AE advertising parameters ***** \n\n")
    #ble_dut.interfaces.wifi.ble_get_max_no_of_supp_adv_sets(no_adv_sets=1)
    adv_type = 1
    random_address= "11:44:33:AA:BB:CC"
    adv_data_2 = "HeartRate_Peripheral_2"
    # set0
    sl_collections.ble_ae_set_params(
        pheripheral_dev=ble_dut,
        peer_address=ble_client_address,
        adv_event_prop=0x02,  # Scannable
        own_address_type=1,  # Random address
        peer_addr_type=0,  # Public peer address
        adv_handle=0,
        pri_adv_phy=1,  # 1M PHY
        sec_adv_phy=1,
        scan_req_notify_enable=1,
        adv_filter_policy=0,
        sec_adv_max_skip=1,
        adv_min_interval=48,
        adv_max_interval=48
    )
    time.sleep(2)
    # Set 1: Coded PHY, connectable with public address
    sl_collections.ble_ae_set_params(
        pheripheral_dev=ble_dut,
        adv_event_prop=0x01,  # Connectable
        peer_address=ble_dut_address,
        own_address_type=0,  # Public address
        peer_addr_type=0,  # Public peer address
        adv_handle=1,
        pri_adv_phy=3,  # Coded PHY
        sec_adv_phy=3,
        scan_req_notify_enable=1,
        adv_filter_policy=0,
        sec_adv_max_skip=1,
        adv_min_interval=100,  # Changed from 30 to 48 for consistency
        adv_max_interval=100  # Changed from 30 to 48 for consistency
    )
    time.sleep(2)
    ble_dut.interfaces.bluetooth.set_ae_set_random_address(random_address=random_address, adv_handle=0)
    time.sleep(4)
    logger().info(f'----> main dut  seto')
    # Set advertising data for both handles
    sl_collections.ble_set_ae_data(
        ble_dut=ble_dut,
        dut_address=random_address,
        adv_data_type=3,
        data_len=len(adv_data),
        adv_data=adv_data,
        adv_handle=0
    )
    time.sleep(2)
    time.sleep(2)
    logger().info(f'----> main dut set1')
    sl_collections.ble_set_ae_data(
        ble_dut=ble_dut,
        dut_address=ble_dut_address,
        adv_data_type=3,
        data_len=len(adv_data_2),
        adv_data=adv_data_2,
        adv_handle=1
    )
    time.sleep(6)
    # Start advertising for both sets
    logger().info(f'----> @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@main dut start advertising set 0 @@@@@@@@@@@@@@@@@@@@@@@@@@')
    status_0 = sl_collections.ble_ae_start_advertising(
        ble_dut=ble_dut,
        dut_address=random_address,
        duration=0,
        max_ae_events=0,
        adv_handle=0,
        adv_async_required=0
    )
    logger().info(f"Advertising handle 0 status: {status_0}")
    time.sleep(2)
    logger().info(f'----> @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@main dut start advertising set 1 @@@@@@@@@@@@@@@@@@@@@@@@@@')
    status_1 = sl_collections.ble_ae_start_advertising(
        ble_dut=ble_dut,
        dut_address=ble_dut_address,
        duration=0,
        max_ae_events=0,
        adv_handle=1,
        adv_async_required=0
    )
    logger().info(f"Advertising handle 1 status: {status_1}")
    # Wait a moment for advertising to stabilize
    time.sleep(2)
    remote_wiseconnect3.interfaces.wifi.ble_set_ae_params(adv_handle=0, adv_event_prop=adv_type,
                                                          primary_adv_intterval_min=48,
                                                          primary_adv_intterval_max=48,
                                                          own_addr_type=0,
                                                          peer_addr_type=0,
                                                          remote_dev_addr=ble_dut_address,
                                                          primary_adv_phy=pri_adv_phy,
                                                          sec_adv_max_skip=1,
                                                          sec_adv_phy=sec_adv_phy,
                                                          scan_req_notify_enable=1,
                                                          adv_filter_policy=0,
                                                          timeout=30)
    remote_wiseconnect3.interfaces.wifi.ble_set_ae_data(type=1, adv_handle=0, operation=0,
                                                        data_len=len(adv_data), data=adv_data)

    remote_wiseconnect3.interfaces.wifi.ble_set_ae_data(type=3, adv_handle=0, operation=0,
                                                        data_len=len(adv_data), data=adv_data)

    logger().info(f"#######################stating advertising om frist peer ##################")
    remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=1, no_of_sets=1, adv_handle=0, duration=0,
                                                                 max_ae_events=0,
                                                                 )
    time.sleep(60)
    if remote_wiseconnect3s:
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_params(adv_handle=0, adv_event_prop=adv_type,
                                                                  primary_adv_intterval_min=48,
                                                                  primary_adv_intterval_max=48,
                                                                  own_addr_type=0,
                                                                  peer_addr_type=0,
                                                                  remote_dev_addr=ble_dut_address,
                                                                  primary_adv_phy=pri_adv_phy,
                                                                  sec_adv_max_skip=1,
                                                                  sec_adv_phy=sec_adv_phy,
                                                                  scan_req_notify_enable=1,
                                                                  adv_filter_policy=0,
                                                                  timeout=30)

        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_data(type=1, adv_handle=0, operation=0,
                                                                data_len=len(adv_data), data=adv_data)

        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_data(type=3, adv_handle=0, operation=0,
                                                                data_len=len(adv_data), data=adv_data)

        logger().info(f"#######################stating advertising on second peer ##################")
        remote_wiseconnect3s[0].interfaces.wifi.ble_start_ae_advertising(enable=1, no_of_sets=1, adv_handle=0, duration=0,
                                                                         max_ae_events=0,
                                                                         )
        time.sleep(10)

    ble_dut.interfaces.bluetooth.ble_ae_set_scan_params(
        ble_addr_type=0,  # LE_PUBLIC_ADDRESS
        scanning_filter_policy=0,  # RSI_BLE_SCAN_FILTER_TYPE
        scanning_phys=5,  # (PHY_1M | PHY_LE_CODED) = 1 | 3 = 4
        scan_type_sec=1,  # Active scanning for 1M PHY
        ScanInterval=100,  # LE_SCAN_INTERVAL for 1M PHY (256)
        ScanWindow=50,  # LE_SCAN_WINDOW for 1M PHY (80)
        scan_type=1,  # Active scanning for Coded PHY
        remote_addr_type=0,
        scan_interval_sec=100,  # SEC_PHY_LE_SCAN_INTERVAL for Coded PHY (256)
        scan_window_sec=50  # SEC_PHY_LE_SCAN_WINDOW for Coded PHY (80)
    )

    logger().info("******* scan enable main dut ******* \n\n ****************")

    # Enable scanning
    ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
        enable=1,  # RSI_BLE_START_SCAN
        filter_duplicates=0,  # BLE_SCAN_ENABLE_FILTER_DUP
        duration=0,  # BLE_SCAN_DUR
        period=0,  # BLE_SCAN_PERIOD
        remote_address=ble_client_address
    )
    logger().info("\n\nenable power save in ble dut")
    ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
    time.sleep(30)
    logger().info("#######################scan disable on main dut  ##################")
    ble_dut.interfaces.wifi.ble_ae_set_scan_enable(enable=0, filter_duplicates=0, duration=0, period=0,
                                                   remote_address=ble_client_address)
    retries = 1
    for retry in range(retries):
        try:
            logger().info("#######################performing the connection from main dut to peer1 ##################")
            ble_dut.interfaces.bluetooth.ble_extended_connect_with_params(remote_dev_addr=ble_client_address,
                                                                          remote_addr_type=0, initiator_filter_policy=0,
                                                                          init_phys=7, ConnIntervalMin=50,
                                                                          ConnIntervalMax=50)
            time.sleep(60)
            logger().info("\nChecking connection status of BLE")
            state = ble_dut.interfaces.bluetooth.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            logger().info(f"\nDevice state: {state_int}")
            logger().info(f"CONNECTED STATE: {BLEDeviceState.Connected}")
            # assert state_int == 8, "DUT BLE device is not in connected state"
            break
        except Exception as ex:
            logger().info(f"Exception occurred while connecting to BLE device: {str(ex)}")
            logger().info(f"BLE connection failed with retries {retry + 1}")
            # if retry == retries - 1:
            #     raise
    logger().info(f"ble client address 1: {ble_client_address}")
    tw = Stopwatch()
    link_key1 = ""
    while tw.elapsed_sec < 120:
        events = ble_dut.interfaces.bluetooth.get_async_events()  # since_time=0)
        for event in events:
            if "link_key" in event.event_data:
                event_data = event.event_data
                link_key_data = re.findall("(?<=link_key:: ).*:", event_data)[0]
                logger().info(f"link_key_data : {link_key_data}")
                link_key1 = '0x' + "".join(
                    [i.strip() if len(i.strip()) == 2 else '0' + i.strip() for i in link_key_data.split(":")][:16])
            else:
                continue
        if link_key1:
            break
    logger().info(f"**************First Link Key Extracted: {link_key1}***************")
    assert len(link_key1) == 34, f"link key is not proper format"
    return link_key1
def service_discovery_on_dut(ble_dut, service_uid=None, char_uid=None):
    time.sleep(3)
    servs, chars = ble_dut.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
    time.sleep(5)
    logger().info(f"{servs} {chars}")
    assert len(servs) > 0, "no services fetched"
    assert len(chars) > 0, "fetched characters are empty"

    char_path, char_props = ble_dut.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
        services=servs,
        service_uid=service_uid,
        char_uid=char_uid)
    time.sleep(5)
    logger().info(f"{char_props}")
    assert char_path, "characters are empty"
    assert len(char_props) > 0, "length of characters is 0"
    logger().info("------CHARACTERISTICS----")
    return char_path, char_props

class TxNotificationFunctionality:
    def __init__(self, ble_dut=None, ble_clients=None, ble_client_address=None, data=None, service_uid=None, char_uid=None,
                 char_path=None, allocated_mem_addr=None, notification_count=None):
        super().__init__()
        self.ble_dut = ble_dut
        self.ble_clients = ble_clients
        self.ble_client_address = ble_client_address
        self.data = data
        self.service_uid = service_uid
        self.char_uid = char_uid
        self.char_path = char_path
        self.allocated_mem_addr = allocated_mem_addr
        self.notification_count = notification_count

    def run(self):
        self.notification_count = 15
        logger().info(f"NOTIFICATION COUNT:{self.notification_count}")
        def write():
            logger().info("******************** Start TX Notifications functionality ***********************")
            self.ble_dut.interfaces.wifi.ble_notify_custom_value(ble_remote_dev_address=self.ble_client_address,
                                                                 data=self.data, data_address=self.allocated_mem_addr)
            time.sleep(5)
            logger().info("******************** Validate Data ********************")
            # notifications = self.ble_clients.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
            # logger().info(f' *********************** Notification is {notifications} ***********************')


        notification_count = 0
        time.sleep(1)

        if self.notification_count:
            for i in range(self.notification_count):
                logger().info(f"******tx notification count {notification_count} and range:{i}")
                with lock:
                    write()
                time.sleep(1)

        else:
            sw = Stopwatch()
            while sw.elapsed_sec <= self.notify_time:
                with lock:
                    write()
                    notification_count += 1

        if not self.notification_count:
            self.notification_count = notification_count
        logger().info(f"TX_Notification count: {self.notification_count}")

class TxNotificationFunctionality_1:
    def __init__(self, ble_dut=None, ble_clients=None, ble_client_address=None, data=None, service_uid=None, char_uid=None,
                 char_path=None, allocated_mem_addr=None, notification_count=None):
        super().__init__()
        self.ble_dut = ble_dut
        self.ble_clients = ble_clients
        self.ble_client_address = ble_client_address
        self.data = data
        self.service_uid = service_uid
        self.char_uid = char_uid
        self.char_path = char_path
        self.allocated_mem_addr = allocated_mem_addr
        self.notification_count = notification_count

    def run(self):
        self.notification_count = 15
        logger().info(f"NOTIFICATION COUNT:{self.notification_count}")
        def write():
            logger().info("******************** Start TX Notifications functionality ***********************")
            self.ble_dut.interfaces.sapi.ble_notify_custom_value(ble_remote_dev_address=self.ble_client_address,
                                                                 data=self.data, data_address=self.allocated_mem_addr)
            time.sleep(5)
            logger().info("******************** Validate Data ********************")
            # notifications = self.ble_clients.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
            # logger().info(f' *********************** Notification is {notifications} ***********************')


        notification_count = 0
        time.sleep(1)

        if self.notification_count:
            for i in range(self.notification_count):
                logger().info(f"******tx notification count {notification_count} and range:{i}")
                with lock:
                    write()
                time.sleep(1)

        else:
            sw = Stopwatch()
            while sw.elapsed_sec <= self.notify_time:
                with lock:
                    write()
                    notification_count += 1

        if not self.notification_count:
            self.notification_count = notification_count
        logger().info(f"TX_Notification count: {self.notification_count}")

class RxNotificationFunctionality:
    def __init__(self, ble_dut=None, ble_clients=None, ble_dut_address=None, data=None, svc=None, charc=None,
                 rx_notification_count=None, notify_time=600, allocated_mem_addr=None):
        self.ble_dut = ble_dut
        self.ble_clients = ble_clients
        self.ble_dut_address = ble_dut_address
        self.data = data
        self.svc = svc
        self.charc = charc
        self.rx_notification_count = rx_notification_count
        self.notify_time = notify_time
        self.allocated_mem_addr = allocated_mem_addr

    def run(self):
        self.rx_notification_count = 15
        def write():
            logger().info("---------write data to ble client-------------")
            self.ble_clients.interfaces.wifi.ble_notify_custom_value(ble_remote_dev_address=self.ble_dut_address,
                                                                     data=self.data,
                                                                     data_address=self.allocated_mem_addr)
            time.sleep(3)
            # self.ble_clients.interfaces.wifi.send_gatt_charc_notification(self.svc, self.charc, self.data)
            logger().info("---------send_gatt_charc_notification-------------")
        rx_notification_count = 0
        time.sleep(1)
        try:
            if self.rx_notification_count:
                for i in range(self.rx_notification_count):
                    logger().info(f"******rx notification count {rx_notification_count} and range:{i}")
                    with lock:
                        logger().info("lock")
                        write()
                    time.sleep(1)
            else:
                sw = Stopwatch()
                while sw.elapsed_sec <= self.notify_time:
                    with lock:
                        write()
                        rx_notification_count += 1
        except Exception as e:
            logger().info(e)
        if not self.rx_notification_count:
            self.rx_notification_count = rx_notification_count

        logger().info(f"RX_Notification count: {self.rx_notification_count}")

@pytest.mark.parametrize(
    " test_case_id, pri_adv_phy, sec_adv_phy, adv_type",
    [
        ( "C538064", 1, 1, 0),
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
def test_ble_ae_simultaneous_scanning_and_advertising_C538064(ble_dut, ble_sniffer, sl_collections,  remote_wiseconnect3, periodic_data_len, adv_handle,test_case_id, pri_adv_phy, adv_type,
                                                                               sec_adv_phy ):
    try:
        # Set up advertising and scanning intervals as per test case
        ADV_INT_MIN = 0x152
        ADV_INT_MAX = 0x152
        SCAN_INTERVAL = 0x35
        SCAN_WINDOW = 0x17
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        adv_type= 0
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_ble_ae_simultaneous_scanning_and_advertising_C538064")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        random_address = "11:44:33:AA:BB:CC"
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        remote_wiseconnect3.interfaces.wifi.ble_set_ae_params(adv_handle=0, adv_event_prop=adv_type,
                                                              primary_adv_intterval_min=48,
                                                              primary_adv_intterval_max=48,
                                                              own_addr_type=0,
                                                              peer_addr_type=0,
                                                              remote_dev_addr=ble_dut_address,
                                                              primary_adv_phy=1,  # pri_adv_phy,
                                                              sec_adv_max_skip=1,
                                                              sec_adv_phy=sec_adv_phy,
                                                              scan_req_notify_enable=1,
                                                              adv_filter_policy=0,
                                                              timeout=30)

        remote_wiseconnect3.interfaces.wifi.ble_set_ae_data(type=1, adv_handle=0, operation=0,
                                                            data_len=len(adv_data), data=adv_data)

        remote_wiseconnect3.interfaces.wifi.ble_set_ae_data(type=3, adv_handle=0, operation=0,
                                                            data_len=len(adv_data), data=adv_data)
        logger().info('*********************start advertise on peer 1****************')
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=1, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0,
                                                                     )

        sl_collections.ble_ae_set_params(
            pheripheral_dev=ble_dut,
            #adv_event_prop=adv_type,
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

        logger().info('*****************starting advertis on main dut')
        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            duration=0,
            max_ae_events=0,
            adv_handle=0,
            adv_async_required=0
        )
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        time.sleep(10)



        # Start AE scanning on DUT
        ble_dut.interfaces.bluetooth.ble_ae_set_scan_params(
            ble_addr_type=0,  # LE_PUBLIC_ADDRESS
            scanning_filter_policy=0,  # RSI_BLE_SCAN_FILTER_TYPE
            scanning_phys=5,  # (PHY_1M | PHY_LE_CODED) = 1 | 3 = 4
            scan_type_sec=1,  # Active scanning for 1M PHY
            ScanInterval=100,  # LE_SCAN_INTERVAL for 1M PHY (256)
            ScanWindow=50,  # LE_SCAN_WINDOW for 1M PHY (80)
            scan_type=1,  # Active scanning for Coded PHY
            remote_addr_type=0,
            scan_interval_sec=100,  # SEC_PHY_LE_SCAN_INTERVAL for Coded PHY (256)
            scan_window_sec=50  # SEC_PHY_LE_SCAN_WINDOW for Coded PHY (80)
        )
        logger().info("Step 5: Enable scanning from main device")
        # Enable scanning
        ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
            enable=1,  # RSI_BLE_START_SCAN
            filter_duplicates=0,  # BLE_SCAN_ENABLE_FILTER_DUP
            duration=0,  # BLE_SCAN_DUR
            period=0  # BLE_SCAN_PERIOD
            # remote_address=ble_client_address
        )
        time.sleep(8)
        # Run for 5 minutes
        logger().info("Running simultaneous AE advertising and scanning for 5 minutes...")
        time.sleep(30)
        events = remote_wiseconnect3.interfaces.wifi.get_async_events()
        logger().info(f'events{events}')

        ble_sniffer.interfaces.sniffer.stop_capture()
        time.sleep(2)
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(10)

        # Export to CSV for analysis
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "LE ADV")

        # Validate captured files
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            if os.path.exists(captured_file):
                file_size = os.path.getsize(captured_file)
                assert file_size > 0, f"Capture file {captured_file} is empty"
                logger().info(f"✓ Capture file validated: {captured_file} ({file_size} bytes)")

        if exported_csv_file:
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            if os.path.exists(exported_csv_file):
                file_size = os.path.getsize(exported_csv_file)
                assert file_size > 0, f"CSV file {exported_csv_file} is empty"
                logger().info(f"✓ CSV file validated: {exported_csv_file} ({file_size} bytes)")

        logger().info(f"✓ Test case {test_case_id} completed successfully")
        logger().info("✓ BLE AE dual role advertising and scanning working correctly")
        df = pd.read_csv(exported_csv_file)
        df = _normalize_sniffer_df(df)

        adv_ext = df[df["Type_norm"] == "ADV_EXT_IND"]
        aux_adv = df[df["Type_norm"] == "AUX_ADV_IND"]

        assert len(adv_ext) >= 1, (
            f"[{test_case_id}] No/insufficient ADV_EXT_IND packets found "

        )
        logger().info(f'\nadv_ext_ind packets found:{len(adv_ext)}')
        assert len(aux_adv) >= 1, (
            f"[{test_case_id}] No/insufficient AUX_ADV_IND packets found "

        )
        logger().info(f'\naux_adv packets found:{len(aux_adv)}')

        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_enable=0
        )
        logger().info("Simultaneous AE advertising and scanning test completed.")

    except Exception as e:
        logger().info(f"Test failed: {e}")
        assert False


@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "768359", 1, 1),
    ],
)
@pytest.mark.check()
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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_BLE_advertising_and_scanning_with_two_sets_enabled_C768359(ble_dut, ble_sniffer,
                                                                               sl_collections,
                                                                               remote_wiseconnect3,remote_wiseconnect3s, adv_type,
                                                                               test_case_id, pri_adv_phy,
                                                                               sec_adv_phy):
    try:
        # Start BLE on DUT and get addresses
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_verify_BLE_advertising_and_scanning_with_two_sets_enabled_C768359")
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(
            set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(
            set_smp=0)  # capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        random_address = "11:44:33:AA:BB:CC"
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        adv_data_2 = "".join(random.choices(string.ascii_uppercase + string.digits, k=30))
        remote_wiseconnect3.interfaces.wifi.ble_set_ae_params(adv_handle=0, adv_event_prop=adv_type,
                                                              primary_adv_intterval_min=48,
                                                              primary_adv_intterval_max=48,
                                                              own_addr_type=0,
                                                              peer_addr_type=0,
                                                              remote_dev_addr=ble_dut_address,
                                                              primary_adv_phy=1,#pri_adv_phy,
                                                              sec_adv_phy=1,
                                                              sec_adv_max_skip=1,
                                                              #sec_adv_phy=sec_adv_phy,
                                                              scan_req_notify_enable=1,
                                                              adv_filter_policy=0,
                                                              timeout=30)

        remote_wiseconnect3.interfaces.wifi.ble_set_ae_data(type=1, adv_handle=0, operation=0,
                                                            data_len=len(adv_data), data=adv_data)

        remote_wiseconnect3.interfaces.wifi.ble_set_ae_data(type=3, adv_handle=0, operation=0,
                                                            data_len=len(adv_data), data=adv_data)

        logger().info('***************starting advertise on peer 1')
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=1, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0,
                                                                     )
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_params(adv_handle=0, adv_event_prop=adv_type,
                                                              primary_adv_intterval_min=48,
                                                              primary_adv_intterval_max=48,
                                                              own_addr_type=0,
                                                              peer_addr_type=0,
                                                              remote_dev_addr=ble_dut_address,
                                                              primary_adv_phy=3,#pri_adv_phy,
                                                              sec_adv_phy=3,
                                                              sec_adv_max_skip=1,
                                                              #sec_adv_phy=sec_adv_phy,
                                                              scan_req_notify_enable=1,
                                                              adv_filter_policy=0,
                                                              timeout=30)
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_data(type=1, adv_handle=0, operation=0,
                                                            data_len=len(adv_data), data=adv_data)

        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_data(type=3, adv_handle=0, operation=0,
                                                            data_len=len(adv_data), data=adv_data)
        logger().info('*************starting advertis peer 2')
        remote_wiseconnect3s[0].interfaces.wifi.ble_start_ae_advertising(enable=1, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0,
                                                                     )
        #set0
        sl_collections.ble_ae_set_params(
            pheripheral_dev=ble_dut,
            peer_address=ble_client_address,
            adv_event_prop=0x02,  # Scannable
            own_address_type=1,  # Random address
            peer_addr_type=0,  # Public peer address
            adv_handle=0,
            pri_adv_phy=1,  # 1M PHY
            sec_adv_phy=1,
            scan_req_notify_enable=1,
            adv_filter_policy=0,
            sec_adv_max_skip=1,
            adv_min_interval=48,
            adv_max_interval=48
        )
        time.sleep(2)
        # Set 1: Coded PHY, connectable with public address
        sl_collections.ble_ae_set_params(
            pheripheral_dev=ble_dut,
            adv_event_prop=0x01,  # Connectable
            peer_address=ble_dut_address,
            own_address_type=0,  # Public address
            peer_addr_type=0,  # Public peer address
            adv_handle=1,
            pri_adv_phy=3,  # Coded PHY
            sec_adv_phy=3,
            scan_req_notify_enable=1,
            adv_filter_policy=0,
            sec_adv_max_skip=1,
            adv_min_interval=100,  # Changed from 30 to 48 for consistency
            adv_max_interval=100  # Changed from 30 to 48 for consistency
        )
        time.sleep(2)
        ble_dut.interfaces.bluetooth.set_ae_set_random_address(random_address=random_address, adv_handle=0)
        time.sleep(4)
        logger().info(f'---->  seto')
        # Set advertising data for both handles
        sl_collections.ble_set_ae_data(
            ble_dut=ble_dut,
            dut_address=random_address,
            adv_data_type=3,
            data_len=len(adv_data),
            adv_data=adv_data,
            adv_handle=0
        )
        time.sleep(2)
        time.sleep(2)
        logger().info(f'---->  set1')
        sl_collections.ble_set_ae_data(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_data_type=3,
            data_len=len(adv_data_2),
            adv_data=adv_data_2,
            adv_handle=1
        )
        time.sleep(6)
        # Start advertising for both sets
        logger().info(f'starting advertise 1 main dut ')
        status_0 = sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=random_address,
            duration=0,
            max_ae_events=0,
            adv_handle=0,
            adv_async_required=0
        )
        logger().info(f"Advertising handle 0 status: {status_0}")
        time.sleep(2)
        logger().info('starting second advertis on main dut')
        status_1 = sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            duration=0,
            max_ae_events=0,
            adv_handle=1,
            adv_async_required=0
        )
        logger().info(f"Advertising handle 1 status: {status_1}")
        # Wait a moment for advertising to stabilize
        time.sleep(2)
        logger().info("Both advertising sets started successfully")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                           psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(2)
        ble_dut.interfaces.bluetooth.ble_ae_set_scan_params(
            ble_addr_type=0,  # LE_PUBLIC_ADDRESS
            scanning_filter_policy=0,  # RSI_BLE_SCAN_FILTER_TYPE
            scanning_phys=5,  # (PHY_1M | PHY_LE_CODED) = 1 | 3 = 4
            scan_type_sec=1,  # Active scanning for 1M PHY
            ScanInterval=100,  # LE_SCAN_INTERVAL for 1M PHY (256)
            ScanWindow=50,  # LE_SCAN_WINDOW for 1M PHY (80)
            scan_type=1,  # Active scanning for Coded PHY
            remote_addr_type=0,
            scan_interval_sec=100,  # SEC_PHY_LE_SCAN_INTERVAL for Coded PHY (256)
            scan_window_sec=50  # SEC_PHY_LE_SCAN_WINDOW for Coded PHY (80)
        )
        logger().info("Step 5: Enable scanning from main dut device")
        # Enable scanning
        ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
            enable=1,  # RSI_BLE_START_SCAN
            filter_duplicates=0,  # BLE_SCAN_ENABLE_FILTER_DUP
            duration=0,  # BLE_SCAN_DUR
            period=0,  # BLE_SCAN_PERIOD
            remote_address=ble_client_address
        )
        time.sleep(8)
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
        sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_enable=0
        )


    except Exception as e:
        logger().info(f"Test failed: {e}")
        assert False


@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "626222", 1, 1),
    ],
)
@pytest.mark.check()
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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.parametrize("periodic_data_len, adv_handle", [(30, 0)])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_ae_scanning_with_enable_disable_two_sets_loop_C626222(ble_dut, ble_sniffer,
                                                                               sl_collections,
                                                                               remote_wiseconnect3, remote_wiseconnect3s, adv_type,
                                                                               periodic_data_len, adv_handle,
                                                                               test_case_id, pri_adv_phy,
                                                                               sec_adv_phy):
    try:
        random_address = "11:44:33:AA:BB:CC"
        random_address_ref = "11:22:33:AA:BB:CC"
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=30))
        adv_data_2 = "".join(random.choices(string.ascii_uppercase + string.digits, k=30))
        # Start BLE on DUT and get addresses
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_rx_notification_C626222")
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(
            set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(
            set_smp=0)  # capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        random_address = "11:44:33:AA:BB:CC"
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        adv_data_2 = "".join(random.choices(string.ascii_uppercase + string.digits, k=30))
        remote_wiseconnect3.interfaces.wifi.ble_set_ae_params(adv_handle=0, adv_event_prop=adv_type,
                                                              primary_adv_intterval_min=48,
                                                              primary_adv_intterval_max=48,
                                                              own_addr_type=0,
                                                              peer_addr_type=0,
                                                              remote_dev_addr=ble_dut_address,
                                                              primary_adv_phy=1,  # pri_adv_phy,
                                                              sec_adv_max_skip=1,
                                                              sec_adv_phy=sec_adv_phy,
                                                              scan_req_notify_enable=1,
                                                              adv_filter_policy=0,
                                                              timeout=30)
        remote_wiseconnect3.interfaces.wifi.ble_set_ae_data(type=1, adv_handle=0, operation=0,
                                                            data_len=len(adv_data), data=adv_data)

        remote_wiseconnect3.interfaces.wifi.ble_set_ae_data(type=3, adv_handle=0, operation=0,
                                                            data_len=len(adv_data), data=adv_data)

        logger().info("\n *****  AE advertising  peer 1 ***** \n\n")
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=1, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0,
                                                                     )
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_params(adv_handle=0, adv_event_prop=adv_type,
                                                                  primary_adv_intterval_min=48,
                                                                  primary_adv_intterval_max=48,
                                                                  own_addr_type=0,
                                                                  peer_addr_type=0,
                                                                  remote_dev_addr=ble_dut_address,
                                                                  primary_adv_phy=3,  # pri_adv_phy,
                                                                  sec_adv_max_skip=1,
                                                                  sec_adv_phy=sec_adv_phy,
                                                                  scan_req_notify_enable=1,
                                                                  adv_filter_policy=0,
                                                                  timeout=30)


        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_data(type=1, adv_handle=0, operation=0,
                                                                data_len=len(adv_data), data=adv_data)

        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_data(type=3, adv_handle=0, operation=0,
                                                                data_len=len(adv_data), data=adv_data)
        logger().info("\n *****  advertising  peer 2 ***** \n\n")
        remote_wiseconnect3s[0].interfaces.wifi.ble_start_ae_advertising(enable=1, no_of_sets=1, adv_handle=0,
                                                                         duration=0,
                                                                         max_ae_events=0,
                                                                         )
        # set1
        sl_collections.ble_ae_set_params(
            pheripheral_dev=ble_dut,
            peer_address=ble_dut_address,
            adv_event_prop=0x02,  # Scannable
            own_address_type=1,  # Random address
            peer_addr_type=0,  # Public peer address
            adv_handle=0,
            pri_adv_phy=1,  # 1M PHY
            sec_adv_phy=1,
            scan_req_notify_enable=1,
            adv_filter_policy=0,
            sec_adv_max_skip=1,
            adv_min_interval=48,
            adv_max_interval=48
        )
        time.sleep(2)
        # Set 2: Coded PHY, connectable with public address
        sl_collections.ble_ae_set_params(
            pheripheral_dev=ble_dut,
            adv_event_prop=0x01,  # Connectable
            peer_address=ble_dut_address,
            own_address_type=0,  # Public address
            peer_addr_type=0,  # Public peer address
            adv_handle=1,
            pri_adv_phy=3,  # Coded PHY
            sec_adv_phy=3,
            scan_req_notify_enable=1,
            adv_filter_policy=0,
            sec_adv_max_skip=1,
            adv_min_interval=100,  # Changed from 30 to 48 for consistency
            adv_max_interval=100  # Changed from 30 to 48 for consistency
        )
        time.sleep(2)
        ble_dut.interfaces.bluetooth.set_ae_set_random_address(random_address=random_address, adv_handle=0)
        time.sleep(4)
        logger().info(f'---->  seto')
        # Set advertising data for both handles
        sl_collections.ble_set_ae_data(
            ble_dut=ble_dut,
            dut_address=random_address,
            adv_data_type=3,
            data_len=len(adv_data),
            adv_data=adv_data,
            adv_handle=0
        )
        time.sleep(2)
        time.sleep(2)
        logger().info(f'---->  set1')
        sl_collections.ble_set_ae_data(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_data_type=3,
            data_len=len(adv_data_2),
            adv_data=adv_data_2,
            adv_handle=1
        )
        time.sleep(6)
        # Start advertising for both sets
        ble_dut.interfaces.bluetooth.ble_ae_set_scan_params(
            ble_addr_type=0,  # LE_PUBLIC_ADDRESS
            scanning_filter_policy=0,  # RSI_BLE_SCAN_FILTER_TYPE
            scanning_phys=5,  # (PHY_1M | PHY_LE_CODED) = 1 | 3 = 4
            scan_type_sec=1,  # Active scanning for 1M PHY
            ScanInterval=100,  # LE_SCAN_INTERVAL for 1M PHY (256)
            ScanWindow=50,  # LE_SCAN_WINDOW for 1M PHY (80)
            scan_type=1,  # Active scanning for Coded PHY
            remote_addr_type=0,
            scan_interval_sec=100,  # SEC_PHY_LE_SCAN_INTERVAL for Coded PHY (256)
            scan_window_sec=50  # SEC_PHY_LE_SCAN_WINDOW for Coded PHY (80)
        )

        logger().info("\n ***** enbleling the scan on main dut ***** \n\n")
        ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
            enable=1,  # RSI_BLE_START_SCAN
            filter_duplicates=0,  # BLE_SCAN_ENABLE_FILTER_DUP
            duration=0,  # BLE_SCAN_DUR
            period=0  # BLE_SCAN_PERIOD
            # remote_address=ble_client_address
        )
        time.sleep(8)
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        time.sleep(10)
        for _ in range(15):
            logger().info('****************starting advertising in main dut set 0 ***** \n\n')
            status_0 = sl_collections.ble_ae_start_advertising(
                ble_dut=ble_dut,
                dut_address=random_address,
                duration=0,
                max_ae_events=0,
                adv_handle=0,
                adv_async_required=0
            )
            time.sleep(2)
            logger().info("\n ***** Successfully second AE advertising  main DUT set 1 ***** \n\n")
            status_1 = sl_collections.ble_ae_start_advertising(
                ble_dut=ble_dut,
                dut_address=ble_dut_address,
                duration=0,
                max_ae_events=0,
                adv_handle=1,
                adv_async_required=0
            )
            time.sleep(2)
            logger().info("\n ***** stop AE advertising  main DUT ***** \n\n")

            sl_collections.ble_ae_start_advertising(
                ble_dut=ble_dut,
                dut_address=random_address,
                adv_handle=0,
                adv_enable=0
            )
            time.sleep(2)
            logger().info("\n ***** stop second AE advertising  main DUT ***** \n\n")

            sl_collections.ble_ae_start_advertising(
                ble_dut=ble_dut,
                dut_address=ble_dut_address,
                adv_handle=1,
                adv_enable=0
            )
            time.sleep(2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(10)

        # Export to CSV for analysis
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "LE ADV")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            if os.path.exists(captured_file):
                file_size = os.path.getsize(captured_file)
                assert file_size > 0, f"Capture file {captured_file} is empty"
                logger().info(f" Capture file validated: {captured_file} ({file_size} bytes)")

        if exported_csv_file:
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            if os.path.exists(exported_csv_file):
                file_size = os.path.getsize(exported_csv_file)
                assert file_size > 0, f"CSV file {exported_csv_file} is empty"
                logger().info(f" CSV file validated: {exported_csv_file} ({file_size} bytes)")

        df = pd.read_csv(exported_csv_file)
        df = _normalize_sniffer_df(df)

        adv_ext = df[df["Type_norm"] == "ADV_EXT_IND"]
        aux_adv = df[df["Type_norm"] == "AUX_ADV_IND"]

        assert len(adv_ext) >= 1, (
            f"[{test_case_id}] No/insufficient ADV_EXT_IND packets found "

        )
        logger().info(f'\nadv_ext_ind packets found:{len(adv_ext)}')
        assert len(aux_adv) >= 1, (
            f"[{test_case_id}] No/insufficient AUX_ADV_IND packets found "

        )
        logger().info(f'\naux_adv_in packets found:{len(aux_adv)}')
    except Exception as e:
        logger().info(f'e{e}')


@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "C538063", 1, 1),
    ],
)
@pytest.mark.check()
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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_ble_ae_dual_role_adv_and_scan_interval_C538063(ble_dut, ble_sniffer,
                                                                               sl_collections,
                                                                               remote_wiseconnect3, remote_wiseconnect3s, adv_type,

                                                                               test_case_id, pri_adv_phy,
                                                                               sec_adv_phy):
    try:
        # Start BLE on DUT and get addresses
        random_address = "11:44:33:AA:BB:CC"
        random_address_ref = "11:22:33:AA:BB:CC"
        ADV_INT_MIN = 0xA0  # RSI_BLE_ADV_INT_MIN = 0xA0 (160 * 0.625ms = 100ms)
        ADV_INT_MAX = 0xA0  # RSI_BLE_ADV_INT_MAX = 0xA0 (160 * 0.625ms = 100ms)
        SCAN_INTERVAL = 0xA0  # LE_SCAN_INTERVAL = 0xA0 (160 * 0.625ms = 100ms)
        SCAN_WINDOW = 0xA0  # LE_SCAN_WINDOW = 0xA0 (160 * 0.625ms = 100ms)
        TIMEOUT = 300
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=30))
        adv_data_2 = "".join(random.choices(string.ascii_uppercase + string.digits, k=30))
        # Start BLE on DUT and get addresses

        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_rx_notification_C538063")

        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(
            set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(
            set_smp=0)  # capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        random_address = "11:44:33:AA:BB:CC"
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        adv_data_2 = "".join(random.choices(string.ascii_uppercase + string.digits, k=30))
        remote_wiseconnect3.interfaces.wifi.ble_set_ae_params(adv_handle=0, adv_event_prop=adv_type,
                                                              primary_adv_intterval_min=48,
                                                              primary_adv_intterval_max=48,
                                                              own_addr_type=0,
                                                              peer_addr_type=0,
                                                              remote_dev_addr=ble_dut_address,
                                                              primary_adv_phy=1,  # pri_adv_phy,
                                                              sec_adv_max_skip=1,
                                                              sec_adv_phy=sec_adv_phy,
                                                              scan_req_notify_enable=1,
                                                              adv_filter_policy=0,
                                                              timeout=30)
        remote_wiseconnect3.interfaces.wifi.ble_set_ae_data(type=1, adv_handle=0, operation=0,
                                                            data_len=len(adv_data), data=adv_data)

        remote_wiseconnect3.interfaces.wifi.ble_set_ae_data(type=3, adv_handle=0, operation=0,
                                                            data_len=len(adv_data), data=adv_data)
        logger().info('******************starting advertise on peer 1')
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=1, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0,
                                                                     )
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_params(adv_handle=0, adv_event_prop=adv_type,
                                                                  primary_adv_intterval_min=48,
                                                                  primary_adv_intterval_max=48,
                                                                  own_addr_type=0,
                                                                  peer_addr_type=0,
                                                                  remote_dev_addr=ble_dut_address,
                                                                  primary_adv_phy=3,  # pri_adv_phy,
                                                                  sec_adv_phy=3,
                                                                  sec_adv_max_skip=1,
                                                                  #sec_adv_phy=sec_adv_phy,
                                                                  scan_req_notify_enable=1,
                                                                  adv_filter_policy=0,
                                                                  timeout=30)

        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_data(type=1, adv_handle=0, operation=0,
                                                                data_len=len(adv_data), data=adv_data)

        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_data(type=3, adv_handle=0, operation=0,
                                                                data_len=len(adv_data), data=adv_data)
        logger().info('starting advertising peer 2')
        remote_wiseconnect3s[0].interfaces.wifi.ble_start_ae_advertising(enable=1, no_of_sets=1, adv_handle=0,
                                                                         duration=0,
                                                                         max_ae_events=0,
                                                                         )

        # set0
        sl_collections.ble_ae_set_params(
            pheripheral_dev=ble_dut,
            peer_address=ble_dut_address,
            adv_event_prop=0x02,  # Scannable
            own_address_type=1,  # Random address
            peer_addr_type=0,  # Public peer address
            adv_handle=0,
            pri_adv_phy=1,  # 1M PHY
            sec_adv_phy=1,
            scan_req_notify_enable=1,
            adv_filter_policy=0,
            sec_adv_max_skip=1,
            adv_min_interval= 0xA0 ,
            adv_max_interval= 0xA0
        )
        time.sleep(2)
        # Set 1: Coded PHY, connectable with public address
        sl_collections.ble_ae_set_params(
            pheripheral_dev=ble_dut,
            adv_event_prop=0x01,  # Connectable
            peer_address=ble_dut_address,
            own_address_type=0,  # Public address
            peer_addr_type=0,  # Public peer address
            adv_handle=1,
            pri_adv_phy=3,  # Coded PHY
            sec_adv_phy=3,
            scan_req_notify_enable=1,
            adv_filter_policy=0,
            sec_adv_max_skip=1,
            adv_min_interval= 0xA0,  # Changed from 30 to 48 for consistency
            adv_max_interval= 0xA0  # Changed from 30 to 48 for consistency
        )
        time.sleep(2)
        ble_dut.interfaces.bluetooth.set_ae_set_random_address(random_address=random_address, adv_handle=0)
        time.sleep(4)
        logger().info('---->  seto')
        # Set advertising data for both handles
        sl_collections.ble_set_ae_data(
            ble_dut=ble_dut,
            dut_address=random_address,
            adv_data_type=3,
            data_len=len(adv_data),
            adv_data=adv_data,
            adv_handle=0
        )
        time.sleep(4)
        logger().info('---->  set1')
        sl_collections.ble_set_ae_data(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            adv_data_type=3,
            data_len=len(adv_data_2),
            adv_data=adv_data_2,
            adv_handle=1
        )
        time.sleep(6)
        # Start advertising for both sets
        logger().info("Advertising handle 0 main dut")
        status_0 = sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=random_address,
            duration=0,
            max_ae_events=0,
            adv_handle=0,
            adv_async_required=0
        )
        time.sleep(2)
        logger().info("Advertising handle 1 main dut")
        status_1 = sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            duration=0,
            max_ae_events=0,
            adv_handle=1,
            adv_async_required=0
        )
        time.sleep(2)
        logger().info("Both advertising sets started successfully")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                           psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(6)
        ble_dut.interfaces.bluetooth.ble_ae_set_scan_params(
            ble_addr_type=0,  # LE_PUBLIC_ADDRESS
            scanning_filter_policy=0,  # RSI_BLE_SCAN_FILTER_TYPE
            scanning_phys=5,  # (PHY_1M | PHY_LE_CODED) = 1 | 3 = 4
            scan_type_sec=1,  # Active scanning for 1M PHY
            ScanInterval= 100,  # LE_SCAN_INTERVAL for 1M PHY (256)
            ScanWindow= 100,  # LE_SCAN_WINDOW for 1M PHY (80)
            scan_type=1,  # Active scanning for Coded PHY
            remote_addr_type=0,
            scan_interval_sec=100,  # SEC_PHY_LE_SCAN_INTERVAL for Coded PHY (256)
            scan_window_sec=50  # SEC_PHY_LE_SCAN_WINDOW for Coded PHY (80)
        )
        logger().info("Step 5: Enable scanning from main dut device")
        # Enable scanning
        ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
            enable=1,  # RSI_BLE_START_SCAN
            filter_duplicates=0,  # BLE_SCAN_ENABLE_FILTER_DUP
            duration=0,  # BLE_SCAN_DUR
            period=0,  # BLE_SCAN_PERIOD
            remote_address=ble_client_address
        )
        time.sleep(20)
        # Stop sniffer and validate capture files

        ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
            enable=0, filter_duplicates=0, duration=0, period=0, remote_address=ble_client_address)
        # remote_wiseconnect3.interfaces.wifi.ble_stop_advertising()
        ble_sniffer.interfaces.sniffer.stop_capture()
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(10)

        # Export to CSV for analysis
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "LE ADV")

        # Validate captured files
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            if os.path.exists(captured_file):
                file_size = os.path.getsize(captured_file)
                assert file_size > 0, f"Capture file {captured_file} is empty"

        if exported_csv_file:
            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            if os.path.exists(exported_csv_file):
                file_size = os.path.getsize(exported_csv_file)
                assert file_size > 0, f"CSV file {exported_csv_file} is empty"

        df = pd.read_csv(exported_csv_file)
        df = _normalize_sniffer_df(df)

        adv_ext = df[df["Type_norm"] == "ADV_EXT_IND"]
        aux_adv = df[df["Type_norm"] == "AUX_ADV_IND"]

        assert len(adv_ext) >= 1, (
            f"[{test_case_id}] No/insufficient ADV_EXT_IND packets found "

        )

        assert len(aux_adv) >= 1, (
            f"[{test_case_id}] No/insufficient AUX_ADV_IND packets found "

        )
        logger().info(f'\n\naux_adv_in packets found:{len(aux_adv)}')
        logger().info(f'\n\nadv_ext_ind packets found:{len(adv_ext)}')
    except Exception as e:
        logger().error(f"Test failed: {e}")
        # Set advertising data on remote device (complete data)

        assert False, f"Test case {test_case_id} failed: {str(e)}"

    finally:
        # Cleanup
        try:
            sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address, adv_enable=0)
            ble_sniffer.interfaces.sniffer.stop_capture()

        except Exception as cleanup_error:
            logger().warning(f"Cleanup error: {cleanup_error}")
@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (1, "C528645", 1, 1),
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
def test_ble_ext_master_connection_disconnection_loop_528645(ble_dut, ble_sniffer, sl_collections,
                                                             remote_wiseconnect3, adv_type,
                                                             periodic_data_len, adv_handle,
                                                             test_case_id, pri_adv_phy,
                                                             sec_adv_phy):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        logger().info(f"ble dut address is {ble_dut_address}")
        logger().info(f"ble client address is {ble_client_address}")
        adv_data = "AE_PERIPHERAL_DATA_AE_PERIPHERA"
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_ble_ext_master_connection_disconnection_loop_528645")
        remote_wiseconnect3.interfaces.wifi.ble_set_ae_params(adv_handle=0, adv_event_prop=adv_type,
                                                              primary_adv_intterval_min=48,
                                                              primary_adv_intterval_max=48,
                                                              own_addr_type=0,
                                                              peer_addr_type=0,
                                                              remote_dev_addr=ble_dut_address,
                                                              primary_adv_phy=pri_adv_phy,
                                                              sec_adv_max_skip=1,
                                                              sec_adv_phy=sec_adv_phy,
                                                              scan_req_notify_enable=1,
                                                              adv_filter_policy=0,
                                                              timeout=30)

        remote_wiseconnect3.interfaces.wifi.ble_set_ae_data(type=1, adv_handle=0, operation=0,
                                                            data_len=len(adv_data), data=adv_data)

        remote_wiseconnect3.interfaces.wifi.ble_set_ae_data(type=3, adv_handle=0, operation=0,
                                                            data_len=len(adv_data), data=adv_data)

        logger().info('**************starting advertise on peer 1')
        logger().info('**************starting advertise in remote dut **************')
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=1, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0,
                                                                     )
        time.sleep(8)
        logger().info("\n\nenable power save in ble main dut")
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        time.sleep(10)
        ble_dut.interfaces.bluetooth.ble_ae_set_scan_params(
            ble_addr_type=0,  # LE_PUBLIC_ADDRESS
            scanning_filter_policy=0,  # RSI_BLE_SCAN_FILTER_TYPE
            scanning_phys=5,  # (PHY_1M | PHY_LE_CODED) = 1 | 3 = 4
            scan_type_sec=1,  # Active scanning for 1M PHY
            ScanInterval=100,  # LE_SCAN_INTERVAL for 1M PHY (256)
            ScanWindow=50,  # LE_SCAN_WINDOW for 1M PHY (80)
            scan_type=1,  # Active scanning for Coded PHY
            remote_addr_type=0,
            scan_interval_sec=100,  # SEC_PHY_LE_SCAN_INTERVAL for Coded PHY (256)
            scan_window_sec=50  # SEC_PHY_LE_SCAN_WINDOW for Coded PHY (80)
        )
        # Connection/disconnection loop
        for i in range(10):
            logger().info(f"\n========== Connection Loop Iteration {i + 1} ==========")
            # 1. Enable scanning to find the device
            logger().info("******* scan enable main dut ******* \n\n ****************")

            # Enable scanning
            ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
                enable=1,  # RSI_BLE_START_SCAN
                filter_duplicates=0,  # BLE_SCAN_ENABLE_FILTER_DUP
                duration=0,  # BLE_SCAN_DUR
                period=0,  # BLE_SCAN_PERIOD
                remote_address=ble_client_address
            )

            time.sleep(5)  # Wait for scan to find device
            ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
                enable=0,  # RSI_BLE_START_SCAN
                filter_duplicates=0,  # BLE_SCAN_ENABLE_FILTER_DUP
                duration=0,  # BLE_SCAN_DUR
                period=0,  # BLE_SCAN_PERIOD
                remote_address=ble_client_address
            )
            try:
                ble_dut.interfaces.bluetooth.ble_extended_connect_with_params(remote_dev_addr=ble_client_address,
                                                                              remote_addr_type=0,
                                                                              initiator_filter_policy=0,
                                                                              init_phys=7, ConnIntervalMin=50,
                                                                              ConnIntervalMax=50)
                time.sleep(60)
                logger().info("\nChecking connection status of BLE")
                state = ble_dut.interfaces.bluetooth.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                logger().info(f"\nDevice state: {state_int}")
                logger().info(f"CONNECTED STATE: {BLEDeviceState.Connected}")

                time.sleep(30)  # Wait for connection to establish
                # Verify connection state

            except Exception as e:
                logger().error(f"Connection failed at iteration {i + 1}: {e}")
                continue
            # 4. Disconnect using the REMOTE device address (not ble_client_address)
            try:
                time.sleep(30)
                try:
                    ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
                    time.sleep(5)
                except Exception as e:
                    remote_wiseconnect3.interfaces.wifi.ble_disconnect(ble_dut_address)

                # ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
                # time.sleep(5)  # Wait for disconnection to complete


            except Exception as e:
                logger().error(f"Disconnection error: {e}")
            time.sleep(20)
            try:
                time.sleep(10)
                remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=1, no_of_sets=1, adv_handle=0,
                                                                             duration=0,
                                                                             max_ae_events=0,
                                                                             )
            except Exception as e:
                pass
        try:
            remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(
                enable=0,
                filter_duplicates=0,
                duration=0,
                period=0,
                remote_address=ble_dut_address
            )
        except:
            pass
    except Exception as e:
        logger().error(f"Test {test_case_id} failed with error: {e}")
        # Cleanup on failure
        assert False, f"Test failed: {e}"
    finally:

        ble_sniffer.interfaces.sniffer.stop_capture()

@pytest.mark.parametrize(
    "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
    [
        (0, "19877", 1, 1),
    ],
)
@pytest.mark.check()
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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_connection_stability_with_two_centrals_C19877(ble_dut, ble_sniffer,
                                                                               sl_collections,
                                                                               remote_wiseconnect3,remote_wiseconnect3s, adv_type,
                                                                               test_case_id, pri_adv_phy,
                                                                               sec_adv_phy):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_ble_connection_stability_with_two_centrals_C19877")

        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(
            set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(
            set_smp=0)  # capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        random_address = "11:44:33:AA:BB:CC"
        adv_data = "HeartRate_Peripheral_1"
        adv_data_2 = "HeartRate_Peripheral_2"

        bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        assert bt_dut_address, "failed to initiate ble in dut"
        time.sleep(2)
        logger().info(" ======= start ble remote secondary DUT")
        address = remote_wiseconnect3.interfaces.sapi.ble_gatt_start(set_smp=0)
        ble_client_address = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', address).group(0)
        assert ble_client_address, "failed to initiate ble in remote dut"
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        logger().info(f"address_is{ble_client_address}")
        ble_client_address_2 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(
            set_smp=1)
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1bb1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1bb1)
        remote_wiseconnect3.interfaces.wifi.ble_add_service(uid=0xAABB)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_serv_att(uid=0x1bb1)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_val_att(uid=0x1bb1)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0xAABB)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x1bb1)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x1bb1)
        logger().info(" ======= start ble adv in remote secondary DUT")
        remote_wiseconnect3.interfaces.sapi.ble_start_advertising()
        time.sleep(1)
        logger().info(" ======= start scanning in remote side")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=50)
        time.sleep(5)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')
        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(10)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        retries = 3
        for retry in range(retries):
            try:
                ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=ble_client_address, timeout=120)

                #time.sleep(180)
                time.sleep(60)
                logger().info("\nChecking connection status of BLE")
                state = remote_wiseconnect3.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                logger().info(f"\nDevice state: {state_int}")
                # assert state_int == 8, "DUT BLE device is not in connected state"
                break
            except Exception as ex:
                logger().info(f"Exception occurred while connecting to BLE device: {str(ex)}")
                logger().info(f"BLE connection failed with retries {retry + 1}")
                if retry == retries - 1:
                    raise

        tw = Stopwatch()
        link_key1 = ""
        while tw.elapsed_sec < 180:
            events = remote_wiseconnect3.interfaces.wifi.get_async_events()  # since_time=0)
            #logger().info(f"---------------->Events: {events}")
            for event in events:
                logger().info(f"---------------->Event Data: {event.event_data}")
                if "link_key" in event.event_data:
                    event_data = event.event_data
                    link_key_data = re.findall("((?<=link_key:: ).*:)", event_data)[-1]
                    logger().info(f"link_key_data : {link_key_data}")
                    link_key1 = '0x' + "".join(
                        [i.strip() if len(i.strip()) == 2 else '0' + i.strip() for i in link_key_data.split(":")][:16])
                    break
                else:
                    break
            if link_key1:
                break


        remote_wiseconnect3.interfaces.sapi.ble_start_advertising()
        time.sleep(1)
        remote_wiseconnect3s[0].interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=50)
        time.sleep(5)

        remote_wiseconnect3s[0].interfaces.wifi.ble_stop_scanning()
        # remote_wiseconnect3s[0].interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=120)
        # time.sleep(180)
        retries = 3
        for retry in range(retries):
            try:
                remote_wiseconnect3s[0].interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address,
                                                                    timeout=120)

                time.sleep(60)
                logger().info("\nChecking connection status of BLE")
                state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                logger().info(f"\nDevice state: {state_int}")
                assert state_int == 8, "DUT BLE device is not in connected state"
                break
            except Exception as ex:
                logger().info(f"Exception occurred while connecting to BLE device: {str(ex)}")
                logger().info(f"BLE connection failed with retries {retry + 1}")
                if retry == retries - 1:
                    raise

        tw = Stopwatch()
        link_key2 = ""
        while tw.elapsed_sec < 180:
            events =remote_wiseconnect3.interfaces.wifi.get_async_events()  # since_time=0)
            # logger().info(f"---------------->Events: {events}")
            for event in events:
                logger().info(f"---------------->Event Data: {event.event_data}")
                if "link_key" in event.event_data:
                    event_data = event.event_data
                    link_key_data = re.findall("((?<=link_key:: ).*:)", event_data)[-1]
                    logger().info(f"second link_key_data : {link_key_data}")
                    link_key2 = '0x' + "".join(
                        [i.strip() if len(i.strip()) == 2 else '0' + i.strip() for i in link_key_data.split(":")][:16])
                    break
                else:
                    break
            if link_key2:
                break

        logger().info(f"Second link key generated at DUT side: {link_key2}, loink1 is {link_key1}")
        logger().info("Starting Notification Functionality Test")
        # allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(adv_data))
        allocated_mem_addr=remote_wiseconnect3.interfaces.sapi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        # ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(adv_data), write_content=adv_data)
        remote_wiseconnect3.interfaces.sapi.load_memory(address=allocated_mem_addr, size=len(adv_data), write_content=adv_data)

        # allocated_mem_addr_2 = remote_wiseconnect3.interfaces.wifi.allocate_memory(size=len(adv_data))
        allocated_mem_addr_2 = ble_dut.interfaces.wifi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr_2, size=len(adv_data),
                    write_content=adv_data)

        allocated_mem_addr_3 = remote_wiseconnect3s[0].interfaces.wifi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3s[0].interfaces.wifi.load_memory(address=allocated_mem_addr_3, size=len(adv_data),
                                                        write_content=adv_data)

        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address, "0xAABB",
                                                     "0x1bb1",
                                                     BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} ****************_1")
        remote_wiseconnect3.interfaces.sapi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_dut_address,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        try:
            write_handle_2 = service_discovery_on_remote( remote_wiseconnect3, ble_client_address_2, "0xAABB",
                                                     "0x1bb1",
                                                     BLEPermissions.DEFAULT)
        except Exception as e:
            logger().info(f"Exception in service discovery for 2nd central: {e}")
            write_handle_2 = service_discovery_on_remote_1(remote_wiseconnect3, ble_client_address_2, "0xAABB",
                                                           "0x1bb1",
                                                           BLEPermissions.DEFAULT)
            raise

        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} ****************_3")
        remote_wiseconnect3.interfaces.sapi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address_2,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} Success1 ****************")
        remote_wiseconnect3.interfaces.sapi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                          handle=(write_handle_1 + 1), enable_notify=1)
        ble_dut.interfaces.bluetooth.ble_set_att_value( ble_remote_dev_address=ble_client_address,handle=(write_handle_1 + 1),enable_notify=1
        )
        remote_wiseconnect3.interfaces.sapi.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                              handle=(write_handle_2 + 1), enable_notify=1)
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_client_address,
                                                       handle=(write_handle_1 + 1), enable_notify=1
                                                       )
        ble_fun_1 = TxNotificationFunctionality_1( remote_wiseconnect3, ble_clients= ble_dut,
                                                allocated_mem_addr=allocated_mem_addr, data=adv_data,
                                                ble_client_address=ble_dut_address, notification_count=50)

        ble_fun_2 = TxNotificationFunctionality_1(remote_wiseconnect3, ble_clients=remote_wiseconnect3s[0],
                                                allocated_mem_addr=allocated_mem_addr, data=adv_data,
                                                ble_client_address=ble_client_address_2, notification_count=50)

        thread1 = threading.Thread(target=ble_fun_1.run)
        thread2 = threading.Thread(target=ble_fun_2.run)
        thread1.start()
        thread2.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")

    except Exception as e:
        logger().error(f"Test {test_case_id} failed with error: {e}")
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        #stoping advertising
        try:
            sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0, max_ae_events=0, adv_handle=0, adv_async_required=0)
        except:
            pass

        # Cleanup on failure
        assert False, f"Test failed: {e}"


# @pytest.mark.parametrize(
#     "adv_type, test_case_id, pri_adv_phy, sec_adv_phy",
#     [
#         (0, "768360", 1, 1),
#     ],
# )

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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
def test_verify_ble_ae_advertising_2sets_scanning_with_peripheral_connection_secure_mode_C768360(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 2M
        """
    # Working
    try:
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_verify_ble_ae_advertising_2sets_scanning_with_peripheral_connection_secure_mode_C768360")
        write_handle_1 = None
        write_handle_2 = None
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        ble_client_address_2  = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)#capability=3, set_smp=0)
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        logger().info(f"BLE-CLIENT-ADDRESS_2:{ble_client_address_2}")
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1bb1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1bb1)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        remote_wiseconnect3.interfaces.wifi.ble_add_service(uid=0xAABB)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_serv_att(uid=0x1bb1)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_val_att(uid=0x1bb1)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=1, sec_adv_phy=2,  remote_wiseconnect3s=remote_wiseconnect3s)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(adv_data), write_content=adv_data)
        allocated_mem_addr_2 = remote_wiseconnect3.interfaces.wifi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3.interfaces.wifi.load_memory(address=allocated_mem_addr_2, size=len(adv_data),
                                                        write_content=adv_data)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address, "0xAABB",
                                                   "0x1bb1",
                                                   BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} ****************_1")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} Success ****************")
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(
            ble_remote_dev_address=ble_dut_address,
            handle=(write_handle_1 + 1),
            enable_notify=1
        )
        ble_fun_1 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                    ble_dut_address=ble_dut_address, data=adv_data, svc=svc,
                                    charc=charc, rx_notification_count=50,
                                    allocated_mem_addr=allocated_mem_addr_2)



        thread1 = threading.Thread(target=ble_fun_1.run)
        #thread2 = threading.Thread(target=ble_fun_2.run)
        thread1.start()
        #thread2.start()
        time.sleep(2)
        thread1.join()
        #thread2.join()
        ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
            enable=1,  # RSI_BLE_START_SCAN
            filter_duplicates=0,  # BLE_SCAN_ENABLE_FILTER_DUP
            duration=0,  # BLE_SCAN_DUR
            period=0  # BLE_SCAN_PERIOD
            # remote_address=ble_client_address
        )
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        # if link_key2 != "":
        #     ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())

        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")

    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)

        # if write_handle_2:
        #     ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
        #                                                    handle=(write_handle_2 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()

        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")

        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")

        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)



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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
def test_verify_ble_ae_advertising_2sets_scanning_with_peripheral_connection_secure_mode_C768361(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 2M
        """
    # Working
    try:
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_verify_ble_ae_advertising_2sets_scanning_with_peripheral_connection_secure_mode_C768361")
        write_handle_1 = None
        write_handle_2 = None

        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        ble_client_address_2  = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)#capability=3, set_smp=0)
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        logger().info(f"BLE-CLIENT-ADDRESS_2:{ble_client_address_2}")
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1bb1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1bb1)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        remote_wiseconnect3.interfaces.wifi.ble_add_service(uid=0xAABB)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_serv_att(uid=0x1bb1)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_val_att(uid=0x1bb1)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3,  sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=1, sec_adv_phy=2, remote_wiseconnect3s= remote_wiseconnect3s)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(adv_data), write_content=adv_data)
        allocated_mem_addr_2 = remote_wiseconnect3.interfaces.wifi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3.interfaces.wifi.load_memory(address=allocated_mem_addr_2, size=len(adv_data),
                                                        write_content=adv_data)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address, "0xAABB",
                                                   "0x1bb1",
                                                   BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} ****************_1")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} Success ****************")
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(
            ble_remote_dev_address=ble_dut_address,
            handle=(write_handle_1 + 1),
            enable_notify=1
        )
        ble_fun_1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                allocated_mem_addr=allocated_mem_addr, data=adv_data,
                                                ble_client_address=ble_client_address, notification_count=50)
        thread1 = threading.Thread(target=ble_fun_1.run)
        #thread2 = threading.Thread(target=ble_fun_2.run)
        thread1.start()
        #thread2.start()
        time.sleep(2)
        thread1.join()
        #thread2.join()
        ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
            enable=1,  # RSI_BLE_START_SCAN
            filter_duplicates=0,  # BLE_SCAN_ENABLE_FILTER_DUP
            duration=0,  # BLE_SCAN_DUR
            period=0  # BLE_SCAN_PERIOD
            # remote_address=ble_client_address
        )
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)

        #ble_dut.interfaces.bluetooth.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")

        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)


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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
def test_verify_ble_ae_advertising_2sets_scanning_with_peripheral_connection_secure_mode_C768362(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 2M
        """
    # Working
    try:
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_verify_ble_ae_advertising_2sets_scanning_with_peripheral_connection_secure_mode_C768362")
        write_handle_1 = None
        write_handle_2 = None
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        ble_client_address_2  = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)#capability=3, set_smp=0)
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        logger().info(f"BLE-CLIENT-ADDRESS_2:{ble_client_address_2}")
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        remote_wiseconnect3.interfaces.wifi.ble_add_service(uid=0xAABB)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3,  sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=1, sec_adv_phy=2, remote_wiseconnect3s=None)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s, ble_dut_address, ble_client_address_2,
                                 sl_collections, pri_adv_phy=1, sec_adv_phy=2, link_key1=link_key1)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(adv_data), write_content=adv_data)
        allocated_mem_addr_2 = remote_wiseconnect3.interfaces.wifi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3.interfaces.wifi.load_memory(address=allocated_mem_addr_2, size=len(adv_data),
                                                        write_content=adv_data)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address, "0xAABB",
                                                   "0x1aa1",
                                                   BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} ****************_1")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} Success ****************")
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(
            ble_remote_dev_address=ble_dut_address,
            handle=(write_handle_1 + 1),
            enable_notify=1
        )
        ble_fun_1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                allocated_mem_addr=allocated_mem_addr, data=adv_data,
                                                ble_client_address=ble_client_address, notification_count=50)
        thread1 = threading.Thread(target=ble_fun_1.run)
        #thread2 = threading.Thread(target=ble_fun_2.run)
        thread1.start()
        #thread2.start()
        time.sleep(2)
        thread1.join()
        #thread2.join()
        ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
            enable=1,  # RSI_BLE_START_SCAN
            filter_duplicates=0,  # BLE_SCAN_ENABLE_FILTER_DUP
            duration=0,  # BLE_SCAN_DUR
            period=0  # BLE_SCAN_PERIOD
            # remote_address=ble_client_address
        )
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        # if link_key2 != "":
        #     ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        adv_type=0
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_params(adv_handle=0, adv_event_prop=adv_type,
                                                                  primary_adv_intterval_min=48,
                                                                  primary_adv_intterval_max=48,
                                                                  own_addr_type=0,
                                                                  peer_addr_type=0,
                                                                  remote_dev_addr=ble_dut_address,
                                                                  primary_adv_phy=3,  # pri_adv_phy,
                                                                  sec_adv_max_skip=1,
                                                                  sec_adv_phy=1,
                                                                  scan_req_notify_enable=1,
                                                                  adv_filter_policy=0,
                                                                  timeout=30)

        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_data(type=1, adv_handle=0, operation=0,
                                                                data_len=len(adv_data), data=adv_data)

        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_data(type=3, adv_handle=0, operation=0,
                                                                data_len=len(adv_data), data=adv_data)
        logger().info("Step 4: Start advertising from peripheral device 2")
        remote_wiseconnect3s[0].interfaces.wifi.ble_start_ae_advertising(enable=1, no_of_sets=1, adv_handle=0,
                                                                         duration=0,
                                                                         max_ae_events=0,
                                                                         )
        time.sleep(5)
        ble_dut.interfaces.bluetooth.ble_ae_set_scan_params(
            ble_addr_type=0,  # LE_PUBLIC_ADDRESS
            scanning_filter_policy=0,  # RSI_BLE_SCAN_FILTER_TYPE
            scanning_phys=5,  # (PHY_1M | PHY_LE_CODED) = 1 | 3 = 4
            scan_type_sec=1,  # Active scanning for 1M PHY
            ScanInterval=100,  # LE_SCAN_INTERVAL for 1M PHY (256)
            ScanWindow=50,  # LE_SCAN_WINDOW for 1M PHY (80)
            scan_type=1,  # Active scanning for Coded PHY
            remote_addr_type=0,
            scan_interval_sec=100,  # SEC_PHY_LE_SCAN_INTERVAL for Coded PHY (256)
            scan_window_sec=50  # SEC_PHY_LE_SCAN_WINDOW for Coded PHY (80)
        )
        logger().info("Step 5: Enable scanning from main device")
        # Enable scanning
        ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
            enable=1,  # RSI_BLE_START_SCAN
            filter_duplicates=0,  # BLE_SCAN_ENABLE_FILTER_DUP
            duration=0,  # BLE_SCAN_DUR
            period=0  # BLE_SCAN_PERIOD
            # remote_address=ble_client_address
        )
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()

        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")

        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)



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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
def test_verify_ble_ae_advertising_2sets_scanning_with_peripheral_connection_secure_mode_C768363(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 2M
        """
    # Working
    try:
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_verify_ble_ae_advertising_2sets_scanning_with_peripheral_connection_secure_mode_C768363")
        write_handle_1 = None
        write_handle_2 = None
        adv_type = 0
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        ble_client_address_2  = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)#capability=3, set_smp=0)
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        logger().info(f"BLE-CLIENT-ADDRESS_2:{ble_client_address_2}")
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1bb1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1bb1)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        remote_wiseconnect3.interfaces.wifi.ble_add_service(uid=0xAABB)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_serv_att(uid=0x1bb1)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_val_att(uid=0x1bb1)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3,  sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=1, sec_adv_phy=2, remote_wiseconnect3s=None)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s, ble_dut_address, ble_client_address_2,
                                 sl_collections, pri_adv_phy=1, sec_adv_phy=2, link_key1=link_key1)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(adv_data), write_content=adv_data)
        allocated_mem_addr_2 = remote_wiseconnect3.interfaces.wifi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3.interfaces.wifi.load_memory(address=allocated_mem_addr_2, size=len(adv_data),
                                                        write_content=adv_data)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address, "0xAABB",
                                                   "0x1bb1",
                                                   BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} ****************_1")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} Success ****************")
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(
            ble_remote_dev_address=ble_dut_address,
            handle=(write_handle_1 + 1),
            enable_notify=1
        )
        ble_fun_1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                allocated_mem_addr=allocated_mem_addr, data=adv_data,
                                                ble_client_address=ble_client_address, notification_count=50)



        thread1 = threading.Thread(target=ble_fun_1.run)
        #thread2 = threading.Thread(target=ble_fun_2.run)
        thread1.start()
        #thread2.start()
        time.sleep(2)
        thread1.join()
        #thread2.join()
        ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(
            enable=1,  # RSI_BLE_START_SCAN
            filter_duplicates=0,  # BLE_SCAN_ENABLE_FILTER_DUP
            duration=0,  # BLE_SCAN_DUR
            period=0  # BLE_SCAN_PERIOD
            # remote_address=ble_client_address
        )
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        # if link_key2 != "":
        #     ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_params(adv_handle=0, adv_event_prop=adv_type,
                                                                  primary_adv_intterval_min=48,
                                                                  primary_adv_intterval_max=48,
                                                                  own_addr_type=0,
                                                                  peer_addr_type=0,
                                                                  remote_dev_addr=ble_dut_address,
                                                                  primary_adv_phy=3,  # pri_adv_phy,
                                                                  sec_adv_max_skip=1,
                                                                  sec_adv_phy=1,
                                                                  scan_req_notify_enable=1,
                                                                  adv_filter_policy=0,
                                                                  timeout=30)
        logger().info("\n ***** Successfully Configured AE advertising parameters ***** \n\n")

        logger().info(f"adv_data: {adv_data}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_data(type=1, adv_handle=0, operation=0,
                                                                data_len=len(adv_data), data=adv_data)
        logger().info(
            f"\n\n ***** AE advertising Data configured successfully on {ble_client_address} with data type: BLE_AE_ADV_DATA_TYPE***** \n\n")
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_ae_data(type=3, adv_handle=0, operation=0,
                                                                data_len=len(adv_data), data=adv_data)
        logger().info("******* start advertise first peer ****************")

        remote_wiseconnect3s[0].interfaces.wifi.ble_start_ae_advertising(enable=1, no_of_sets=1, adv_handle=0,
                                                                         duration=0,
                                                                         max_ae_events=0,
                                                                         )
        time.sleep(5)
        logger().info("******* stop advertise main dut ****************")
        status_1 = sl_collections.ble_ae_start_advertising(
            ble_dut=ble_dut,
            dut_address=ble_dut_address,
            duration=0,
            max_ae_events=0,
            adv_handle=1,
            adv_async_required=0
        )
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)

        ble_dut.interfaces.bluetooth.ble_remove_service()

        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        logger().info("******* stop  advertise first peer ****************")

        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        logger().info("******* stop advertise main dut ****************")

        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)
