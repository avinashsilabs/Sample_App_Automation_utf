import re
from logging import exception
from unittest import expectedFailure

import pytest
import time
import datetime
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xPowerSaveModes, \
    Si91xPowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.utf_config import UtfConfig
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.thread_base import ThreadBase
import os


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(Si917)
        2. EFR32
        3. Raspberry PI4
        4.Sodera sniffer

    Test Steps:
        1. Configure DUT in BLE mode 
        2. Enable advertising on DUT with with different adv type and channel
        3. Verify the ble adv type and channel in sniffer capture.



    Author: Hussain korra
"""

'''=================== Ble-gap IO test cases ===================== '''


class BleMaster_SCANThread(ThreadBase):
    def __init__(self, ble_dut, ble_client):
        super().__init__()
        self.ble_dut = ble_dut
        self.ble_client = ble_client

    def run(self):
        scan_result = ""
        ble_client_address = get_ble_client_addr(self.ble_client)
        logger().info(f"BLE_CLIENT_ADDR : {ble_client_address}")
        logger().info("Start scanning....")
        self.ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=180)
        time.sleep(10)
        events = self.ble_dut.interfaces.bluetooth.get_async_events()
        for event in events:
            if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                if "rsi_ble_simple_central_on_adv_report_event" in event.event_data:
                    logger().info(f" event data : {event.event_data}")
                    scan_result = event.event_data
        logger().info(f" Scan result : {scan_result}")
        return scan_result


def get_ble_client_addr(ble_client):
    ble_client_addr = None
    logger().info(f"fetching BLE client Address: '{ble_client.name}' ")
    rc, stdout, stderr = ble_client.interfaces.bluetooth.shell.execute(f"hcitool dev")
    if rc == 0:
        pattern = r'([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})[\s]'
        ble_client_addr = re.search(pattern, stdout.decode()).group(0).strip()
    else:
        logger().error(f"Unable to fetch ble_client_address:\n{stderr}")
    assert ble_client_addr, "Unable to fetch ble_client_address"
    return ble_client_addr


def check_for_devices_in_scanned_results(ble_interface, bt_dut_address, adv_data):
    """ This function is used to check for devices in scan results """
    sw = Stopwatch()
    previously_found_devices = {}
    while sw.elapsed_sec < 30:
        found_devices = ble_interface.get_devices()
        if previously_found_devices != found_devices:
            logger().info(f"BLE scan results :{found_devices}")
            previously_found_devices = found_devices
        if (
                bt_dut_address in found_devices
                and found_devices[bt_dut_address] == adv_data
        ):
            return True
    return False


class connectasmaster:
    def __init__(self, ble_dut, ble_client, sl_collections, ble_dut_address=None, ble_capability=None, set_smp=0):
        super().__init__()
        self.ble_dut = ble_dut
        self.ble_client = ble_client
        self.ble_dut_address = ble_dut_address
        self.sl_collections = sl_collections
        self.ble_capability = ble_capability
        self.set_smp = set_smp

    def ble_connect(self):
        logger().info("Initialising BLE")
        if self.ble_capability is None:
            logger().info("default capability.....")
            self.ble_dut_address = self.ble_dut.interfaces.wifi.ble_start()
        else:
            logger().info("selected capability.....")
            self.ble_dut_address = self.ble_dut.interfaces.wifi.ble_start(capability=self.ble_capability,
                                                                          set_smp=self.set_smp)
        assert self.ble_dut_address, "failed to initiate ble in dut"

        logger().info(f"Initiating connection.......")
        self.sl_collections.ble_connection(wifi_dut=self.ble_dut,
                                           ble_client=self.ble_client,
                                           ble_dut_address=self.ble_dut_address,
                                           mode="master")
        time.sleep(20)
        logger().info(f"\n\n ***** Successfully connected with Remote *****\n\n")
        logger().info("Checking connection status of BLE")
        state = self.ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"state_int==============>>,  {state_int}")

    def power_save(self):
        self.ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        self.ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

    def ble_disconnect(self, disconnect_from="remote"):
        logger().info("Checking connection status of BLE")
        state = self.ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

        if disconnect_from == "remote":
            logger().info(f"Initiating BLE disconnection from raspi")
            self.ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)
        else:
            logger().info(f"Initiating BLE disconnection from DUT")
            self.ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)


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
                            Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
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
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_undir_adv_with_adv_channel_map_0x01_C664393(ble_dut, sl_collections, ble_sniffer):
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664393")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=128, ble_adv_channel_map=1)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dir_adv_with_adv_channel_map_0x01_C664394(ble_dut, sl_collections, ble_sniffer):
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664394")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=129, ble_adv_channel_map=1)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(5)
        # ble_dut.interfaces.bluetooth.ble_stop_advertising()
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scannable_adv_with_adv_channel_map_0x01_C664395(ble_dut, sl_collections, ble_sniffer):
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664395")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=130, ble_adv_channel_map=1)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_noncon_adv_with_adv_channel_map_0x01_C664396(ble_dut, sl_collections, ble_sniffer):
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664396")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=131, ble_adv_channel_map=1)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_undir_adv_with_adv_channel_map_0x03_C664397(ble_dut, sl_collections, ble_sniffer):
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664397")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=128, ble_adv_channel_map=3)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dir_adv_with_adv_channel_map_0x03_C664398(ble_dut, sl_collections, ble_sniffer):
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664398")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=129, ble_adv_channel_map=3)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(5)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scannable_adv_with_adv_channel_map_0x03_C664399(ble_dut, sl_collections, ble_sniffer):
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664399")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=130, ble_adv_channel_map=3)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_noncon_adv_with_adv_channel_map_0x03_C663400(ble_dut, sl_collections, ble_sniffer):
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C663400")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=131, ble_adv_channel_map=3)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_undir_adv_with_adv_channel_map_0x02_C664340(ble_dut, sl_collections, ble_sniffer):
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664340")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=128, ble_adv_channel_map=2)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dir_adv_with_adv_channel_map_0x02_C664341(ble_dut, sl_collections, ble_sniffer):
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664341")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=129, ble_adv_channel_map=2)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(5)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scannable_adv_with_adv_channel_map_0x02_C664342(ble_dut, sl_collections, ble_sniffer):
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664342")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=130, ble_adv_channel_map=2)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_noncon_adv_with_adv_channel_map_0x02_C664343(ble_dut, sl_collections, ble_sniffer):
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664343")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=131, ble_adv_channel_map=2)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_undirected_adv_with_adv_channel_map_0x04_C664344(ble_dut, sl_collections, ble_sniffer):
    """
    est -Validate BLE undirected advertisement in specific channels
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664344")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=128, ble_adv_channel_map=4)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dir_adv_with_adv_channel_map_0x04_C664345(ble_dut, sl_collections, ble_sniffer):
    """
    est -Validate BLE undirected advertisement in specific channels
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664345")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=129, ble_adv_channel_map=4)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(5)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_adv_with_adv_channel_map_0x04_C664346(ble_dut, sl_collections, ble_sniffer):
    """
    est -Validate BLE undirected advertisement in specific channels
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664346")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=130, ble_adv_channel_map=4)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_noncon_adv_with_adv_channel_map_0x04_C664347(ble_dut, sl_collections, ble_sniffer):
    """
    est -Validate BLE undirected advertisement in specific channels
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664347")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=131, ble_adv_channel_map=4)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_undirected_adv_with_adv_channel_map_0x06_C664348(ble_dut, sl_collections, ble_sniffer):
    """
    est -Validate BLE undirected advertisement in specific channels
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664348")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=128, ble_adv_channel_map=6)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dir_adv_with_adv_channel_map_0x06_C664349(ble_dut, sl_collections, ble_sniffer):
    """
    est -Validate BLE undirected advertisement in specific channels
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664349")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=129, ble_adv_channel_map=6)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(5)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_adv_with_adv_channel_map_0x06_C664350(ble_dut, sl_collections, ble_sniffer):
    """
    est -Validate BLE undirected advertisement in specific channels
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664350")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=130, ble_adv_channel_map=6)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_noncon_adv_with_adv_channel_map_0x06_C664351(ble_dut, sl_collections, ble_sniffer):
    """
    est -Validate BLE undirected advertisement in specific channels
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664351")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=131, ble_adv_channel_map=6)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_undirected_adv_with_adv_channel_map_0x05_C664352(ble_dut, sl_collections, ble_sniffer):
    """
    est -Validate BLE undirected advertisement in specific channels
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664352")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=128, ble_adv_channel_map=5)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dir_adv_with_adv_channel_map_0x05_C664353(ble_dut, sl_collections, ble_sniffer):
    """
    est -Validate BLE undirected advertisement in specific channels
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664353")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=129, ble_adv_channel_map=5)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(5)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_adv_with_adv_channel_map_0x05_C664354(ble_dut, sl_collections, ble_sniffer):
    """
    est -Validate BLE undirected advertisement in specific channels
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664354")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=130, ble_adv_channel_map=5)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(60)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_noncon_adv_with_adv_channel_map_0x05_C664355(ble_dut, sl_collections, ble_sniffer):
    """
    est -Validate BLE undirected advertisement in specific channels
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        logger().info("Sniffer Capturing started")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file="C664355")
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"

        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=131, ble_adv_channel_map=5)
        logger().info("======= enable wifi power save mode on DUT")
        ble_dut.interfaces.bluetooth.set_performance_profile(mode='power_save_low_latency')

        logger().info("======= enable BT power save mode on DUT")
        ble_dut.interfaces.bluetooth.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(5)
        # Mapping Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
        ble_sniffer.interfaces.sniffer.stop_capture()
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
        logger().info(sniffer_data_df.head())
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_noncon_adv_and_conn_C663373(ble_dut, ble_client, sl_collections):
    try:
        logger().info(" ======= set local name")
        set_local_name = "DUT_SLAVE_CON"
        logger().info(f" ======= Setting BLE local name : {set_local_name}")
        time.sleep(5)
        ble_dut.interfaces.wifi.bt_set_local_name(set_local_name)
        status = ble_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f" ======= Getting the local name : {status}")
        assert set_local_name == status, "Set local name and get local name not matched "

        logger().info("Start Ble...")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"
        logger().info("set dut in adv mode...")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=131)

        logger().info("enabling the power save modes ")
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                     psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

        logger().info("start ble scan from remote le device...")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, "failed to initiate ble in remote device"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()

        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert ble_dut.interfaces.bluetooth.ble_address in found_devices
        assert (
                found_devices[ble_dut.interfaces.wifi.ble_address]
                == ble_dut.interfaces.bluetooth.ble_advertising_data
        )
        logger().info("connect to dut from remote le device....")
        try:
            ble_client.interfaces.bluetooth.connect(ble_dut_address)
            time.sleep(60)
        except:
            pass
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == 1  # Advertising state
        logger().info("DUT BLE device is not in a connected state, so the status code is 0x0001 as expected....")
        ble_client.interfaces.bluetooth.close()
        time.sleep(5)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_ble_adv_10250ms_interva_C663366(ble_dut, sl_collections):
    try:
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"
        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_int_min=16400, ble_adv_int_max=16400,
                                                           test_scenario="none")
    except Exception as e:
        assert '0x4e12' in str(e), f"\n****** Testcase failed with {e}******"
        logger().info("******observed error code 0x4E12 which is expected. Hence Testcase passed******")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_ble_adv_2ms_interva_C663370(ble_dut, sl_collections):
    try:
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"
        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_int_min=2, ble_adv_int_max=2, test_scenario="none")
    except Exception as e:
        assert '0x4e12' in str(e), f"\n****** Testcase failed with {e}******"
        logger().info("******observed error code 0x4E12 which is expected. Hence Testcase passed******")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_master_conn_with_5ms_C663372(ble_dut, ble_client, sl_collections):
    """
    Configure DUT in Master and verify connectivity with Undirected connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_ble_sdk_dut_master_undirected_connectable_c19833.logs_{int(time.time())}"):
            logger().info("start ble...")
            ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            assert ble_dut_address, "unable to fetch bd address"
            logger().info(f"Configure Remote LE device in advertising mode")
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
                bt_dut_address=ble_dut_address,
                hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                               "0x40 0x00 "  # Advertising_Interval_Max
                               "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                               "0x00 "  # Own_Address_Type
                               "0x00 "  # Peer_Address_Type
                               "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                               "0x07 "  # Advertising_Channel_Map
                               "0x00"  # Advertising_Filter_Policy
                , scan_resp_data="0x0f 0x0e 0x09 0x75 0x74 0x66 0x5f 0x77 0x69 "
                                 "0x66 0x69 0x5f 0x74 0x65 0x73 " \
                                 "0x74 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                 "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
            )
            assert ble_client_address, "failed to initiate ble in remote device"
            logger().info("Start scanning....")
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
            logger().info("enabling the power save modes ")
            ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                         psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

            logger().info("stop scanning")
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(2)
            logger().info(f"DUT initiating BLE connection with ble_client device")
            ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=ble_client_address, ble_conn_interval_min=4,
                                                     ble_conn_interval_max=4)
            time.sleep(20)
            logger().info("Check connection status of BLE")
            state = ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int != BLEDeviceState.Connected, "DUT is not connected to BLE"

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_master_conn_with_4500ms_C663371(ble_dut, ble_client, sl_collections):
    """
    Configure DUT in Master and verify connectivity with Undirected connectable devices
    :param ble_dut:  Fixture parameter to issue command in DUT.
    :param ble_client:  Fixture parameter to issue command in Remote Raspi BLE device
    """
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_ble_sdk_dut_master_undirected_connectable_c19833.logs_{int(time.time())}"):
            logger().info("start ble...")
            ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            assert ble_dut_address, "unable to fetch bd address"
            logger().info(f"Configure Remote LE device in advertising mode")
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
                bt_dut_address=ble_dut_address,
                hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                               "0x40 0x00 "  # Advertising_Interval_Max
                               "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                               "0x00 "  # Own_Address_Type
                               "0x00 "  # Peer_Address_Type
                               "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                               "0x07 "  # Advertising_Channel_Map
                               "0x00"  # Advertising_Filter_Policy
                , scan_resp_data="0x0f 0x0e 0x09 0x75 0x74 0x66 0x5f 0x77 0x69 "
                                 "0x66 0x69 0x5f 0x74 0x65 0x73 " \
                                 "0x74 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                 "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
            )
            assert ble_client_address, "failed to initiate ble in remote device"
            logger().info("Start scanning....")
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
            logger().info("enabling the power save modes ")
            ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                         psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

            logger().info("stop scanning")
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(2)
            logger().info(f"DUT initiating BLE connection with ble_client device")
            ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=ble_client_address,
                                                     ble_conn_interval_min=3600, ble_conn_interval_max=3600)
            time.sleep(20)
            logger().info("Check connection status of BLE")
            state = ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int != BLEDeviceState.Connected, "DUT is not connected to BLE"

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=ble_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_ble_scan_with_2ms_C663368(ble_dut, sl_collections):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "ble initialization failed in dut"
        logger().info("Start scanning....")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_scan_interval=2, ble_scan_window=2)
    except Exception as e:
        assert "19986" in str(e), f"\n****** Testcase failed with {e}******"
        logger().info("******observed error code 0x4E12 which is expected.Hence Testcase passed******")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_ble_scan_with_10250ms_C663367(ble_dut, sl_collections):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "ble initialization failed in dut"
        logger().info("Start scanning....")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_scan_interval=16400, ble_scan_window=16400)
    except Exception as e:
        assert "19986" in str(e), f"\n****** Testcase failed with {e}******"
        logger().info("******observed error code 0x4E12 which is expected.Hence Testcase passed******")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_ble_scan_window_greter_than_scan_interval_C663369(ble_dut, sl_collections):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "ble initialization failed in dut"
        logger().info("Start scanning....")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_scan_interval=80, ble_scan_window=160)
    except Exception as e:
        assert '0x4046' in str(e), f"\n****** Testcase failed with {e}******"
        logger().info("******observed error code 0x4046 which is expected.Hence Testcase passed******")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_ble_scan_with_random_addr_C663406(ble_dut, sl_collections):
    try:
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "ble initialization failed in dut"
        logger().info("Start scanning....")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_address_type=1)
    except Exception as e:
        assert '0x4e12' in str(e), f"\n****** Testcase failed with {e}******"
        logger().info("******observed error code 0x4E12 which is expected.Hence Testcase passed******")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_ble_adv_with_random_addr_C663407(ble_dut, sl_collections):
    try:
        logger().info("Initiate ble service in DUT")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert ble_dut_address, "failed to initiate ble in dut"
        logger().info("Set DUT in advertise mode")
        ble_dut.interfaces.bluetooth.ble_start_advertising(own_addr_type=1)
    except Exception as e:
        assert '0x4e12' in str(e), f"\n****** Testcase failed with {e}******"
        logger().info("******observed error code 0x4E12 which is expected.Hence Testcase passed******")



