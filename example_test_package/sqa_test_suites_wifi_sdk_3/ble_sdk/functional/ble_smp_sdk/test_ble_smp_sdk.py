import re
import pytest
import time
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
    def __init__(self, wifi_dut=None, nrf_ble_client=None, testcase_no=None, error_code_expected=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.nrf_ble_client = nrf_ble_client
        self.testcase_no = testcase_no
        self.error_code_expected = error_code_expected

    def run(self):
        if self.testcase_no == 557281:
            smp_io_capability = 2
            smp_auth_bond = 1
            smp_mtim = 1
            smp_sc = 1
            smp_enc_key = 1
            passkey_state = 2
            cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY

        if self.testcase_no == 557282:
            smp_io_capability = 4
            smp_auth_bond = 1
            smp_mtim = 1
            smp_sc = 1
            smp_enc_key = 1
            passkey_state = 2
            cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO

        if self.testcase_no == 557283:
            smp_io_capability = 2
            smp_auth_bond = 1
            smp_mtim = 1
            smp_sc = 1
            smp_enc_key = 1
            passkey_state = 1
            cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY

        if self.testcase_no == 557284:
            smp_io_capability = 2
            smp_auth_bond = 1
            smp_mtim = 1
            smp_sc = 1
            smp_enc_key = 1
            passkey_state = 1
            cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_ONLY

        logger().info("Initiate ble service in DUT")
        ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=1)
        assert ble_dut_address, "failed to initiate ble in dut"
        self.wifi_dut.interfaces.wifi.ble_set_cap_data(remote_addr_type=1, smp_io_cap=smp_io_capability, smp_auth_req_bonding= smp_auth_bond, smp_auth_req_mitm=smp_mtim,
                                                  smp_auth_req_sc=smp_sc, smp_max_enc_key_size=16,
                                                  smp_local_oob_data_flag_not_present=0, smp_enc_key=smp_enc_key, smp_id_key=0,
                                                  smp_sign_key=0)
        logger().info(f"Enter the device passkey state")
        self.wifi_dut.interfaces.wifi.ble_modify_passkey_event(passkey_state=passkey_state)

        logger().info(f"preparing nRF dongle for secure connection")
        self.nrf_ble_client.interfaces.bluetooth.set_security_params(passcode_pairing=True,
                                                                io_capabilities=cap_on_dongle,
                                                                long_term_bonding=True, lesc_pairing=True)
        self.nrf_ble_client.interfaces.bluetooth.register_on_connect()
        self.nrf_ble_client.interfaces.bluetooth.register_on_disconnect()
        self.nrf_ble_client.interfaces.bluetooth.register_on_security_level_changed()
        self.nrf_ble_client.interfaces.bluetooth.register_on_client_pairing_complete()
        self.nrf_ble_client.interfaces.bluetooth.register_passkey_display()
        logger().info(f"Start Advertising")
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
        tw = Stopwatch()
        error_code_expected = ""
        while tw.elapsed_sec < 60:
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
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, testcase_no=557281, error_code_expected="0x4b04")
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


def test_ble_smp_anthencation_verify_passkey_not_enterred_C557282(wifi_dut, nrf_ble_client, sl_collections):
    """SMP Anthentication: Verify Passkey Display/Passkey Entry Auth methods timeout occure if passkey is not entered (Initiator:KeyboardDisplay Responder: DisplayYes No"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, testcase_no=557282, error_code_expected="0x4b04")
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

def test_ble_smp_anthencation_passkey_entered_incorrectly_C557283(wifi_dut, nrf_ble_client, sl_collections):
    """SMP Anthentication: Verify Passkey Display/Passkey Entry Auth methods fail with "confirm value failed" if passkey is not entered correctly (Initiator:KeyboardOnly Responder: DisplayOnly"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, testcase_no=557283, error_code_expected="0x4b04")
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


def test_ble_smp_anthencation_passkey_entered_incorrectly_C557284(wifi_dut, nrf_ble_client, sl_collections):
    """SMP Anthentication: Verify Passkey Display/Passkey Entry Auth methods fail with "confirm value failed" if passkey is not entered correctly (Initiator:KeyboardOnly Responder: KeyboardOnly"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, testcase_no=557284, error_code_expected="0x4b01")
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
