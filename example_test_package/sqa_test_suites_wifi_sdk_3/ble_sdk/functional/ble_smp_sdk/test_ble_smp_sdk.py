import re
import pytest
import time
import os
import datetime
import threading
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth.nrf_blatann import (
    NRFBLEIoCapabilities
)
from blatann.gap.smp import PairingPolicy
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap,\
    Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xBTFeatureBitMap,\
    Si91xCustomFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.utf_config import UtfConfig
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth.nrf_blatann import create_interface, NrfBlatann
from utf.devices import Device


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4, Connect nrf dongle to the setup

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. update SMP params
        3. Initiates ble in DUT 
        4. Connect to the remote device/connect to the dut

    Author: Jyothi Nagireddy
"""


class BLEFunc(ThreadBase):
    def __init__(self, wifi_dut=None, nrf_ble_client=None, ble_sniffer=None, error_code_expected=None, check_error=True, sniffer_check=False, layer_name=None,
                 capture_filename=None, smp_io_capability=None, smp_auth_bond=1, smp_mtim=1, smp_enc_key=1, passkey_state=None, smp_sc=1, cap_on_dongle=None, delay=0):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.nrf_ble_client = nrf_ble_client
        self.ble_sniffer = ble_sniffer
        self.error_code_expected = error_code_expected
        self.check_error = check_error
        self.sniffer_check = sniffer_check
        self.layer_name = layer_name
        self.capture_filename = capture_filename
        self.smp_io_capability = smp_io_capability
        self.smp_auth_bond = smp_auth_bond
        self.smp_mtim = smp_mtim
        self.smp_sc = smp_sc
        self.smp_enc_key = smp_enc_key
        self.passkey_state = passkey_state
        self.cap_on_dongle = cap_on_dongle
        self.delay = delay



    def run(self):
        if self.sniffer_check:
            self.ble_sniffer.interfaces.sniffer.init_sniffer()
            self.ble_sniffer.interfaces.sniffer.start_capture(capture_file=self.capture_filename)

        logger().info("Initiate ble service in DUT")
        ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=1)
        assert ble_dut_address, "failed to initiate ble in dut"
        logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability}")
        self.wifi_dut.interfaces.wifi.ble_set_cap_data(remote_addr_type=1, smp_io_cap=self.smp_io_capability, smp_auth_req_bonding= self.smp_auth_bond, smp_auth_req_mitm=self.smp_mtim,
                                                  smp_auth_req_sc=self.smp_sc, smp_max_enc_key_size=16,
                                                  smp_local_oob_data_flag_not_present=0, smp_enc_key=self.smp_enc_key, smp_id_key=0,
                                                  smp_sign_key=0)
        logger().info(f"Entered the device passkey state")
        self.wifi_dut.interfaces.wifi.ble_modify_passkey_event(passkey_state=self.passkey_state, delay=self.delay)
        logger().info(f"Setting IO capability on nrf dongle: {self.cap_on_dongle}")
        logger().info(f"preparing nRF dongle for secure connection")
        self.nrf_ble_client.interfaces.bluetooth.set_security_params(passcode_pairing=True,
                                                                io_capabilities=self.cap_on_dongle,
                                                                long_term_bonding=True, lesc_pairing=True)
        self.nrf_ble_client.interfaces.bluetooth.register_on_connect()
        self.nrf_ble_client.interfaces.bluetooth.register_on_disconnect()
        self.nrf_ble_client.interfaces.bluetooth.register_on_security_level_changed()
        self.nrf_ble_client.interfaces.bluetooth.register_on_client_pairing_complete()
        self.nrf_ble_client.interfaces.bluetooth.register_passkey_display()
        logger().info(f"Start Advertising on nrf dongle")
        ble_client_address = self.nrf_ble_client.interfaces.bluetooth.start_advertising(local_name="slave11",
                                                                                   timeout_sec=0, auto_restart=False
                                                                                   )
        time.sleep(3)
        logger().info(f"Start scanning and connect to ble client")
        self.wifi_dut.interfaces.wifi.ble_start_scanning(
            ble_client_address=ble_client_address, timeout=30
        )
        timeout = 120
        time.sleep(5)
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info(f"Initiating connection this can take upto {timeout} seconds....")
        self.wifi_dut.interfaces.wifi.ble_connect(
            ble_remote_dev_address=ble_client_address, timeout=timeout
        )

        if self.sniffer_check:
            ble_dut_address_hex = re.split(":", ble_dut_address)
            ble_client_address_hex = re.split(":", ble_client_address)
            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part
            slave_address = "0x"
            for hex_data_part in ble_client_address_hex:
                slave_address = slave_address + hex_data_part
            tw = Stopwatch()
            link_key = ""
            while tw.elapsed_sec < 120:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                for event in events:
                    if "link_key" in event.event_data:
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
            logger().info(f"**************Link Key Extracted: {link_key}***************")
            time.sleep(60)
            self.ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address+f" type=random"])
            # time.sleep(5)
            # self.ble_sniffer.interfaces.sniffer.select_bt_static_devices([slave_address])
            time.sleep(30)
            if link_key != "":
                self.ble_sniffer.interfaces.sniffer.add_link_key(link_key.upper(), master_address, slave_address+f" type=random")
        tw = Stopwatch()
        if self.check_error:
            error_code_expected = ""
            while tw.elapsed_sec < 120:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.BLE_CONNECT:
                        if "resp_status:" in event.event_data:
                            error_code_str = re.findall(r"resp_status: (\w.*)", event.event_data)
                            error_code_received = re.split(",", error_code_str[0])
                if error_code_expected:
                    break
            logger().info(f"********Error_code received : {error_code_received[0]}*************")
            assert error_code_received[0] == self.error_code_expected, f"Not getting the expected error code"
            time.sleep(3)
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        if state_int == 8:
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
            time.sleep(10)
        if self.sniffer_check:
            self.ble_sniffer.interfaces.sniffer.stop_capture()
            captured_files = str(self.ble_sniffer.interfaces.sniffer.local_capture_files).split(';')

            time.sleep(30)
            exported_csv_file = self.ble_sniffer.interfaces.sniffer.export_to_csv("LE", self.layer_name)
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0

            exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(exported_csv_file)
            assert file_size > 0
            sniffer_data_df = self.ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            assert sniffer_data_df is not None



pytestmark = [
    pytest.mark.config(
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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST ,
        },
    )
]



def test_ble_smp_anthencation_verify_passkey_not_entered_C557281(wifi_dut, nrf_ble_client, sl_collections):
    """SMP Anthentication: Verify Passkey Display/Passkey Entry Auth methods timeout occure if passkey is not entered (Initiator:KeyboardOnly Responder: Displayonly"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, testcase_no=557281, error_code_expected="0x4b04", smp_io_capability=2, passkey_state=2,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


def test_ble_smp_anthencation_verify_passkey_not_enterred_C557282(wifi_dut, nrf_ble_client, sl_collections):
    """SMP Anthentication: Verify Passkey Display/Passkey Entry Auth methods timeout occure if passkey is not entered (Initiator:KeyboardDisplay Responder: DisplayYes No"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, testcase_no=557282, error_code_expected="0x4b04", smp_io_capability=4, passkey_state=2,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

def test_ble_smp_anthencation_passkey_entered_incorrectly_C557283(wifi_dut, nrf_ble_client, sl_collections):
    """SMP Anthentication: Verify Passkey Display/Passkey Entry Auth methods fail with "confirm value failed" if passkey is not entered correctly (Initiator:KeyboardOnly Responder: DisplayOnly"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, testcase_no=557283, error_code_expected="0x4b04",  smp_io_capability=2, passkey_state=1,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


def test_ble_smp_anthencation_passkey_entered_incorrectly_C557284(wifi_dut, nrf_ble_client, sl_collections):
    """SMP Anthentication: Verify Passkey Display/Passkey Entry Auth methods fail with "confirm value failed" if passkey is not entered correctly (Initiator:KeyboardOnly Responder: KeyboardOnly"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, testcase_no=557284, error_code_expected="0x4b01", smp_io_capability=2, passkey_state=1,  cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_ONLY)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


def test_ble_smp_anthencation_passkey_not_entered_C557292(wifi_dut, nrf_ble_client, sl_collections, ble_sniffer):
    """Verify combo: [Numeric Comparison][Peripheral Action: Accept][Central Action: No action][Action Order: Peripheral][Expected Behaviour: SMP Timeout]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_sniffer=ble_sniffer, testcase_no=557292, error_code_expected="0x4b04", check_error=True, smp_io_capability=1, passkey_state=1,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

def test_ble_smp_anthencation_passkey_entered_incorrectly_C557288(wifi_dut, nrf_ble_client, sl_collections):
    """Verify combo: [Numeric Comparison][Peripheral Action: Accept][Central Action: No action][Action Order: Peripheral][Expected Behaviour: SMP Timeout]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, testcase_no=557288, error_code_expected="0x4b0c", smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_anthencation_passkey_entered_C557285(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections):
    """Verify combo: [Numeric Comparison][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_sniffer=ble_sniffer, testcase_no=557285, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C557285",  smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_anthencation_passkey_entered_with_delay_C557286(wifi_dut, ble_sniffer, nrf_ble_client, sl_collections):
    """Verify combo: [Numeric Comparison][Peripheral Action: Accept][Central Action: Accept][Action Order: Peripheral, Central][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C557286", smp_io_capability=1, delay = 20, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)