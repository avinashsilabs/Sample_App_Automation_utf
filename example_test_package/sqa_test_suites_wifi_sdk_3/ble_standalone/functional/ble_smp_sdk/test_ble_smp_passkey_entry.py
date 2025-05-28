import re
import pytest
import time
import os
import datetime
import threading
from utf.interfaces.bluetooth.nrf_blatann import (
    NRFBLEIoCapabilities, NRFBLEPeerDevAddrTypes
)
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

    Author: Bhuvaneswari
"""


class BLEFunc(ThreadBase):
    def __init__(self, wifi_dut=None, nrf_ble_client=None, ble_client=None, ble_sniffer=None, error_code_expected=None, check_error=True, sniffer_check=False, layer_name=None,
                 capture_filename=None, smp_io_capability=None, encrypted_file=False, smp_auth_bond=1, smp_mtim=1, smp_enc_key=1, passkey_state=None, smp_sc=1, cap_on_dongle=None, delay=0, nrf_connect_to_dut=False,
                 ble_connect_from_raspi=False, pair_connect_from_dut=False, pin_code=None, client_capability=None, dut_capability=None, capability_on_remote=None, mtim_disabled=False, lesc_disabled=False,
                 reconnection_from_remote=False, powersave=True, random_addr_on_dut=False, local_oob_flag=False, nrf_dongle_as_master=False, testcase_no=None, passkey_entry=False, dynamic_passkey=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.nrf_ble_client = nrf_ble_client
        self.ble_client = ble_client
        self.ble_sniffer = ble_sniffer
        self.error_code_expected = error_code_expected
        self.check_error = check_error
        self.sniffer_check = sniffer_check
        self.layer_name = layer_name
        self.dut_capability = dut_capability
        self.capture_filename = capture_filename
        self.smp_io_capability = smp_io_capability
        self.smp_auth_bond = smp_auth_bond
        self.smp_mtim = smp_mtim
        self.smp_sc = smp_sc
        self.smp_enc_key = smp_enc_key
        self.passkey_state = passkey_state
        self.dynamic_passkey = dynamic_passkey
        self.passkey_entry = passkey_entry
        self.cap_on_dongle = cap_on_dongle
        self.delay = delay
        self.nrf_connect_to_dut = nrf_connect_to_dut
        self.ble_connect_from_raspi = ble_connect_from_raspi
        self.pair_connect_from_dut = pair_connect_from_dut
        self.pin_code = pin_code
        self.client_capability = client_capability
        self.capability_on_remote = capability_on_remote
        self.mtim_disabled = mtim_disabled
        self.lesc_disabled = lesc_disabled
        self.reconnection_from_remote = reconnection_from_remote
        self.encrypted_file = encrypted_file
        self.powersave = powersave
        self.random_addr_on_dut = random_addr_on_dut
        self.local_oob_flag = local_oob_flag
        self.nrf_dongle_as_master = nrf_dongle_as_master
        self.testcase_no = testcase_no
        self.ble_dut_address = None
        self.ble_client_address = None
        self.sniffer_data_df = None


    def run(self):
        if self.sniffer_check or self.encrypted_file:
            self.ble_sniffer.interfaces.sniffer.init_sniffer()
            self.ble_sniffer.interfaces.sniffer.start_capture(capture_file=self.capture_filename)
        logger().info("Initiate ble service in DUT")
        logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability}")
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=self.smp_sc, capability=self.smp_io_capability)
        assert self.ble_dut_address, "failed to initiate ble in dut"
        if self.random_addr_on_dut:
            self.ble_dut_address = "11:33:33:33:33:11"
            self.wifi_dut.interfaces.wifi.set_ble_address(ble_address=self.ble_dut_address)
        if self.nrf_connect_to_dut:

            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability}")
            self.wifi_dut.interfaces.wifi.ble_set_cap_data(remote_addr_type=1, smp_io_cap=self.smp_io_capability, smp_auth_req_bonding= self.smp_auth_bond, smp_auth_req_mitm=self.smp_mtim,
                                                      smp_auth_req_sc=self.smp_sc, smp_max_enc_key_size=16,
                                                      smp_local_oob_data_flag_not_present=0, smp_enc_key=self.smp_enc_key, smp_id_key=0,
                                                      smp_sign_key=0)
            logger().info(f"Entered the device passkey state")
            self.wifi_dut.interfaces.wifi.ble_modify_passkey_event(passkey_state=self.passkey_state)
            logger().info(f"Setting IO capability on nrf dongle: {self.cap_on_dongle}")
            logger().info(f"preparing nRF dongle for secure connection")
            if self.mtim_disabled:
                logger().info(f"Capability on dongle: {self.cap_on_dongle}")
                self.nrf_ble_client.interfaces.bluetooth.set_security_params(passcode_pairing=False,
                                                                        io_capabilities=self.cap_on_dongle,
                                                                        long_term_bonding=True, lesc_pairing=True)
            elif self.lesc_disabled:
                logger().info(f"Capability on dongle: {self.capability_on_remote}")
                self.nrf_ble_client.interfaces.bluetooth.set_security_params(passcode_pairing=False,
                                                                        io_capabilities=self.cap_on_dongle,
                                                                        long_term_bonding=True, lesc_pairing=False)
            else:
                logger().info(f"Capability on dongle: {self.cap_on_dongle}")
                self.nrf_ble_client.interfaces.bluetooth.set_security_params(passcode_pairing=True,
                                                                        io_capabilities=self.cap_on_dongle,
                                                                        long_term_bonding=True, lesc_pairing=True)
            self.nrf_ble_client.interfaces.bluetooth.register_on_connect()
            self.nrf_ble_client.interfaces.bluetooth.register_on_disconnect()
            self.nrf_ble_client.interfaces.bluetooth.register_on_security_level_changed()
            self.nrf_ble_client.interfaces.bluetooth.register_on_client_pairing_complete()
            self.nrf_ble_client.interfaces.bluetooth.register_passkey_display()
            # self.nrf_ble_client.interfaces.bluetooth.register_peer_passkey_entry()
            logger().info(f"Start Advertising on nrf dongle")
            self.ble_client_address = self.nrf_ble_client.interfaces.bluetooth.start_advertising(local_name="slave11",
                                                                                       timeout_sec=0, auto_restart=False
                                                                                       )
            time.sleep(3)
            if self.dynamic_passkey:
                self.nrf_ble_client.interfaces.bluetooth.register_dynamic_passkey_entry()
                time.sleep(3)
            logger().info(f"Start scanning and connect to ble client")
            self.wifi_dut.interfaces.wifi.ble_start_scanning(
                ble_client_address=self.ble_client_address, timeout=30
            )
            timeout = 120
            time.sleep(5)
            if self.powersave:
                logger().info("enabling the power save modes ")
                self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                   psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
            logger().info(f"Initiating connection this can take upto {timeout} seconds....")
            if self.passkey_entry:
                def connect():
                    self.wifi_dut.interfaces.wifi.ble_connect(
                        ble_remote_dev_address=self.ble_client_address, timeout=120
                    )

                t = threading.Thread(target=connect)
                t.start()
                tw = Stopwatch()
                pass_key_found = False
                while tw.elapsed_sec < 120:
                    events = self.wifi_dut.interfaces.wifi.get_async_events()
                    for event in events:
                            if "passkey" in event.event_data:
                                passkey = re.findall(r"passkey: ([\d]*)", event.event_data)
                                if passkey[0] is not None:
                                    pass_key_value = str(passkey[0])
                                    logger().info(f"passkey : {pass_key_value}")
                                    self.nrf_ble_client.interfaces.bluetooth.set_passkey(pass_key_value)
                                    time.sleep(60)
                                    state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                                    state_int = int(state) if state.isdigit() else -1
                                    logger().info(f"********{state_int}")
                                    pass_key_found = True
                                    break
                            time.sleep(1)
                    if pass_key_found:
                        break
            else:
                def connect():
                    self.wifi_dut.interfaces.wifi.ble_connect(
                                    ble_remote_dev_address=self.ble_client_address, timeout=timeout
                                )
                t = threading.Thread(target=connect)
                t.start()
                time.sleep(10)
                passkey = self.nrf_ble_client.interfaces.bluetooth.get_passkey()
                logger().info(f"type of passkey : {type(passkey)}")
                logger().info(f"**********{passkey}")
                self.wifi_dut.interfaces.wifi.ble_set_smp_passkey(remote_dev_addr= self.ble_client_address, smp_passkey=passkey)
                time.sleep(30)
                logger().info("Checking connection status of BLE")
                state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                logger().info(f"**********{state_int}****************")
                assert state_int == 8, f"Device disconnected"
        if self.nrf_dongle_as_master:
            self.wifi_dut.interfaces.wifi.ble_set_cap_data(remote_addr_type=0, smp_io_cap=self.smp_io_capability,
                                                           smp_auth_req_bonding=self.smp_auth_bond,
                                                           smp_auth_req_mitm=self.smp_mtim,
                                                           smp_auth_req_sc=self.smp_sc, smp_max_enc_key_size=16,
                                                           smp_local_oob_data_flag_not_present=0,
                                                           smp_enc_key=1, smp_id_key=0,
                                                           smp_sign_key=0)
            logger().info(f"Entered the device passkey state")
            self.wifi_dut.interfaces.wifi.ble_modify_passkey_event(passkey_state=self.passkey_state)
            if self.random_addr_on_dut:
                logger().info("\n\n======= start ble adv in dut with random addr========")
                self.wifi_dut.interfaces.wifi.ble_start_advertising(own_addr_type=1, ble_addr_type=1)
            else:
                logger().info("\n\n======= start ble adv in dut ========")
                self.wifi_dut.interfaces.wifi.ble_start_advertising()
            logger().info("\n\n======= enable power save in ble dut ========")
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                               psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            time.sleep(0.2)
            logger().info(f"Setting IO capability on dongle: {self.cap_on_dongle}")
            self.nrf_ble_client.interfaces.bluetooth.set_security_params(passcode_pairing=True,
                                                                         io_capabilities=self.cap_on_dongle,
                                                                         long_term_bonding=True, lesc_pairing=True)
            self.nrf_ble_client.interfaces.bluetooth.register_on_connect()
            self.nrf_ble_client.interfaces.bluetooth.register_on_disconnect()
            self.nrf_ble_client.interfaces.bluetooth.register_on_security_level_changed()
            self.nrf_ble_client.interfaces.bluetooth.register_on_client_pairing_complete()
            self.nrf_ble_client.interfaces.bluetooth.register_passkey_display()
            scan_timeout = 30
            self.nrf_ble_client.interfaces.bluetooth.set_default_scan_params(timeout_seconds=scan_timeout)
            # Begin Scanning for BLE devices
            self.nrf_ble_client.interfaces.bluetooth.start_scanning()  # this is not async
            found_devices = self.nrf_ble_client.interfaces.bluetooth.get_devices()
            logger().info(f"\n\nFound devices: {found_devices}")
            assert str(self.ble_dut_address) in found_devices
            self.nrf_ble_client.interfaces.bluetooth.stop_scanning()
            self.nrf_ble_client.interfaces.bluetooth.set_connection_parameters(100, 120, 6000)
            connection_status = False
            logger().info("\n\n======= start nRF dongle ========")
            self.ble_client_address = self.nrf_ble_client.interfaces.bluetooth.get_ble_address()
            assert self.ble_client_address is not None
            logger().info(f"**********Initiating connection from dongle****************")
            if self.passkey_entry:
                if self.random_addr_on_dut:
                    self.nrf_ble_client.interfaces.bluetooth.connect(self.ble_dut_address, 30,
                                                                     NRFBLEPeerDevAddrTypes.RANDOM_PRIVATE_NON_RESOLVABLE)
                    time.sleep(2)
                else:
                    self.nrf_ble_client.interfaces.bluetooth.connect(self.ble_dut_address)
                time.sleep(5)
                self.nrf_ble_client.interfaces.bluetooth.register_dynamic_passkey_entry()
                time.sleep(3)
                connection_status = self.nrf_ble_client.interfaces.bluetooth.get_peer_connection_status(
                    self.ble_dut_address)
                logger().info(f"\n\nConnection status: {connection_status}")
                assert connection_status
                self.nrf_ble_client.interfaces.bluetooth.set_peer_security_params(self.ble_dut_address,
                                                                                  passcode_pairing=True,
                                                                                  io_capabilities=self.cap_on_dongle,
                                                                                  lesc_pairing=True,
                                                                                  long_term_bonding=True)

                def pair():
                    self.nrf_ble_client.interfaces.bluetooth.pair(self.ble_dut_address)

                t = threading.Thread(target=pair)
                t.start()
                tw = Stopwatch()
                pass_key_found = False
                while tw.elapsed_sec < 120:
                    events = self.wifi_dut.interfaces.wifi.get_async_events()
                    for event in events:
                        if "passkey" in event.event_data:
                            passkey = re.findall(r"passkey: ([\d]*)", event.event_data)
                            if passkey[0] is not None:
                                pass_key_value = str(passkey[0])
                                logger().info(f"passkey : {pass_key_value}")
                                self.nrf_ble_client.interfaces.bluetooth.set_passkey(pass_key_value)
                                state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                                state_int = int(state) if state.isdigit() else -1
                                logger().info(f"********{state_int}*********")
                                pass_key_found = True
                                break
                        time.sleep(1)
                    if pass_key_found:
                        break
            else:

                if self.random_addr_on_dut:
                    self.nrf_ble_client.interfaces.bluetooth.connect(self.ble_dut_address, 30,
                                                                     NRFBLEPeerDevAddrTypes.RANDOM_PRIVATE_NON_RESOLVABLE)
                    time.sleep(2)
                else:

                    logger().info(f"**********Initiating connection from dongle****************")
                    self.nrf_ble_client.interfaces.bluetooth.connect(self.ble_dut_address)
                    time.sleep(2)

                connection_status = self.nrf_ble_client.interfaces.bluetooth.get_peer_connection_status(
                    self.ble_dut_address)
                logger().info(f"\n\nConnection status: {connection_status}")
                assert connection_status
                self.nrf_ble_client.interfaces.bluetooth.set_peer_security_params(self.ble_dut_address,
                                                                                  passcode_pairing=True,
                                                                                  io_capabilities=self.cap_on_dongle,
                                                                                  lesc_pairing=True,
                                                                                  long_term_bonding=True)

                def pair():
                    self.nrf_ble_client.interfaces.bluetooth.pair(self.ble_dut_address)

                t = threading.Thread(target=pair)
                t.start()
                time.sleep(15)
                passkey = self.nrf_ble_client.interfaces.bluetooth.get_passkey()
                logger().info(f"**********{passkey}")
                self.wifi_dut.interfaces.wifi.ble_set_smp_passkey(remote_dev_addr=self.ble_client_address,
                                                                  smp_passkey=passkey)
                time.sleep(30)
                logger().info("Checking connection status of BLE")
                state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                logger().info(f"**********{state_int}****************")
                assert state_int == 8, f"Device disconnected"
        time.sleep(50)
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        if state_int == 8:
            if self.nrf_dongle_as_master:
                self.nrf_ble_client.interfaces.bluetooth.disconnect(dev_addr=self.ble_dut_address, clear_peer=True)
            else:
                logger().info(f"**********Disconnecting the device****************")
                logger().info(f"ble_client_address: {self.ble_client_address}")
                self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
            time.sleep(10)
        if self.sniffer_check:
            ble_dut_address_hex = re.split(":", self.ble_dut_address)
            ble_client_address_hex = re.split(":", self.ble_client_address)
            master_address = "0x"
            for hex_data_part in ble_dut_address_hex:
                master_address = master_address + hex_data_part
            slave_address = "0x"
            for hex_data_part in ble_client_address_hex:
                slave_address = slave_address + hex_data_part

            if self.ble_connect_from_raspi or self.pair_connect_from_dut:
                logger().info(f"**********pair_connect_from_dut{self.ble_connect_from_raspi}**********")
                self.ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])
                time.sleep(30)
            else:
                logger().info("---------------select-bt-devices-----------------")
                self.ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address+f" type=random"])
                time.sleep(30)
        tw = Stopwatch()
        if self.check_error:
            logger().info("Checking for error code")
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
            logger().info(f"Exported file size: {file_size}")
            assert file_size > 0
            self.sniffer_data_df = self.ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
            assert self.sniffer_data_df is not None


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST ,
        },
    )
]
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_just_works_pairing_Initiator_keyboard_responder_display_C664758(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify JustWorks Pairing method for IOCap, Initiator : No input No output and Responder : keyboard Display with random addr"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP",
                          capture_filename="frontline_capture_C664758",  smp_io_capability=2, passkey_state=2,
                          cap_on_dongle=NRFBLEIoCapabilities.DISPLAY_ONLY,nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df.loc[
                (ble_obj.sniffer_data_df['Code'] == "Pairing Request") & (ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df["Secure Connection Pairing"] == "Yes") & (ble_obj.sniffer_data_df[
                                                                                      'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df['Code'] == "Pairing Response") & (ble_obj.sniffer_data_df['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df["Secure Connection Pairing"] == "Yes")  & (ble_obj.sniffer_data_df[
                                                                                      'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df['Code'] == "Pairing DHKey Check")])==2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)



pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST ,
        },
    )
]

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_display_responder_display_only_C664760(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify JustWorks Pairing method for IOCap, Initiator : Keyboard Display and Responder : Display only"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP",
                          capture_filename="frontline_capture_C664760", smp_io_capability=4, passkey_state=2,
                          cap_on_dongle=NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df.loc[
                       (ble_obj.sniffer_data_df['Code'] == "Pairing Request") & (
                                   ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardDisplay") & (
                                   ble_obj.sniffer_data_df["Secure Connection Pairing"] == "Yes") & (
                                   ble_obj.sniffer_data_df[
                                       'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df['Code'] == "Pairing Response") & (
                    ble_obj.sniffer_data_df['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df[
                                                                                        "Secure Connection Pairing"] == "Yes") & (
                                                           ble_obj.sniffer_data_df[
                                                               'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST ,
        },
    )
]

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_only_responder_display_yesno_C664763(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify JustWorks Pairing method for IOCap, Initiator : Keyboard Only and Responder : Display YesNo"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP",
                          capture_filename="frontline_capture_C664763", smp_io_capability=2, passkey_state=2,
                          cap_on_dongle=NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df.loc[
                       (ble_obj.sniffer_data_df['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardOnly") & (
                               ble_obj.sniffer_data_df["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df[
                                                                                    "Secure Connection Pairing"] == "Yes") & (
                                                       ble_obj.sniffer_data_df[
                                                           'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)



pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST ,
        },
    )
]

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_only_responder_keyboard_only_C664768(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify Passkey Entry Pairing method for IOCap, Initiator : Keyboard Only and Responder : Keyboard Only"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP",
                          capture_filename="frontline_capture_C664768", smp_io_capability=2, passkey_state=0,
                          cap_on_dongle=NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_connect_to_dut=True, passkey_entry=True,
                          dynamic_passkey=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df.loc[
                       (ble_obj.sniffer_data_df['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardOnly") & (
                               ble_obj.sniffer_data_df["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df[
                                                                                    "Secure Connection Pairing"] == "Yes") & (
                                                       ble_obj.sniffer_data_df[
                                                           'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST ,
        },
    )
]

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_only_responder_keyboard_display_664778(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify Passkey Entry Pairing method for IOCap, Initiator : Keyboard Only and Responder : Keyboard Display"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP",
                          capture_filename="frontline_capture_C664778", smp_io_capability=2, passkey_state=2,
                          cap_on_dongle=NRFBLEIoCapabilities.KEYBOARD_DISPLAY, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df.loc[
                       (ble_obj.sniffer_data_df['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardOnly") & (
                               ble_obj.sniffer_data_df["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df[
                                                                                     "Secure Connection Pairing"] == "Yes") & (
                                                       ble_obj.sniffer_data_df[
                                                           'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST ,
        },
    )
]

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_only_responder_display_only_using_random_664783(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify Passkey Entry Pairing method for IOCap, Initiator : Keyboard Only and Responder : Display Only using random address"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP",
                          capture_filename="frontline_capture_C664783", smp_io_capability=2, passkey_state=2,
                          cap_on_dongle=NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True,
                          random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df.loc[
                       (ble_obj.sniffer_data_df['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardOnly") & (
                               ble_obj.sniffer_data_df["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df[
                                                                                    "Secure Connection Pairing"] == "Yes") & (
                                                       ble_obj.sniffer_data_df[
                                                           'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST ,
        },
    )
]

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_display_responder_display_only_using_random_664785(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify Passkey Entry Pairing method for IOCap, Initiator : Keyboard Display and Responder : Display Only using random address"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP",
                          capture_filename="frontline_capture_C664785", smp_io_capability=4, passkey_state=2,
                          cap_on_dongle=NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True,
                          random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df.loc[
                       (ble_obj.sniffer_data_df['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardDisplay") & (
                               ble_obj.sniffer_data_df["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df[
                                                                                    "Secure Connection Pairing"] == "Yes") & (
                                                       ble_obj.sniffer_data_df[
                                                           'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST ,
        },
    )
]

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_only_responder_display_yesno_using_random_664788(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify Passkey Entry Pairing method for IOCap, Initiator : Keyboard Only and Responder : Display YesNo using random address"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP",
                          capture_filename="frontline_capture_C664788", smp_io_capability=2, passkey_state=2,
                          cap_on_dongle=NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True,
                          random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df.loc[
                       (ble_obj.sniffer_data_df['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardOnly") & (
                               ble_obj.sniffer_data_df["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df[
                                                                                    "Secure Connection Pairing"] == "Yes") & (
                                                       ble_obj.sniffer_data_df[
                                                           'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)



pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST ,
        },
    )
]
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_only_responder_keyboard_only_using_random_C664793(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify Passkey Entry Pairing method for IOCap, Initiator : Keyboard Only and Responder : Keyboard Only using random address"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP",
                          capture_filename="frontline_capture_C664793", smp_io_capability=2, passkey_state=0,
                          cap_on_dongle=NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_connect_to_dut=True, passkey_entry=True,
                          dynamic_passkey=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df.loc[
                       (ble_obj.sniffer_data_df['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardOnly") & (
                               ble_obj.sniffer_data_df["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df[
                                                                                    "Secure Connection Pairing"] == "Yes") & (
                                                       ble_obj.sniffer_data_df[
                                                           'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST ,
        },
    )
]

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_only_responder_keyboard_display_using_random_664803(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify Passkey Entry Pairing method for IOCap, Initiator : Keyboard Only and Responder : Keyboard Display using random address"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP",
                          capture_filename="frontline_capture_C664803", smp_io_capability=2, passkey_state=2,
                          cap_on_dongle=NRFBLEIoCapabilities.KEYBOARD_DISPLAY, nrf_connect_to_dut=True,
                          random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df.loc[
                       (ble_obj.sniffer_data_df['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardOnly") & (
                               ble_obj.sniffer_data_df["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df[
                                                                                    "Secure Connection Pairing"] == "Yes") & (
                                                       ble_obj.sniffer_data_df[
                                                           'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST ,
        },
    )
]

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_just_works_pairing_Initiator_keyboard_display_responder_keyboard_only_664770(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify Just works Pairing method for IOCap, Initiator : Keyboard Display and Responder : Keyboard Only"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP",
                          capture_filename="frontline_capture_C664770", smp_io_capability=4, passkey_state=0,
                          cap_on_dongle=NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_connect_to_dut=True, passkey_entry=True,
                          dynamic_passkey=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df.loc[
                       (ble_obj.sniffer_data_df['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardDisplay") & (
                               ble_obj.sniffer_data_df["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df[
                                                                                    "Secure Connection Pairing"] == "Yes") & (
                                                       ble_obj.sniffer_data_df[
                                                           'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST ,
        },
    )
]

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_just_works_pairing_Initiator_keyboard_display_responder_keyboard_only_using_random_664795(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify Just works Pairing method for IOCap, Initiator : Keyboard Display and Responder : Keyboard Only using
    random address"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP",
                          capture_filename="frontline_capture_C664795", smp_io_capability=4, passkey_state=0,
                          cap_on_dongle=NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_connect_to_dut=True, passkey_entry=True,
                          dynamic_passkey=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df.loc[
                       (ble_obj.sniffer_data_df['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardDisplay") & (
                               ble_obj.sniffer_data_df["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df[
                                                                                    "Secure Connection Pairing"] == "Yes") & (
                                                       ble_obj.sniffer_data_df[
                                                           'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST ,
        },
    )
]

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_only_responder_keyboard_display_C663326(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify Passkey Entry Pairing method for IOCap, Initiator : Keyboard Only and Responder : Keyboard Display"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP",
                          capture_filename="frontline_capture_C663326", smp_io_capability=4, passkey_state=0,
                          cap_on_dongle=NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_dongle_as_master=True, passkey_entry=True,
                          )
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df.loc[
                       (ble_obj.sniffer_data_df['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardOnly") & (
                               ble_obj.sniffer_data_df["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df[
                                                                                    "Secure Connection Pairing"] == "Yes") & (
                                                       ble_obj.sniffer_data_df[
                                                           'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                        Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST ,
        },
    )
]
@pytest.mark.check
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_only_responder_keyboard_display_C663351(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify Passkey Entry Pairing method for IOCap, Initiator : Keyboard Only and Responder : Keyboard Display"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP",
                          capture_filename="frontline_capture_C663351", smp_io_capability=4, passkey_state=0,
                          cap_on_dongle=NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_dongle_as_master=True, passkey_entry=True,
                          random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df.loc[
                       (ble_obj.sniffer_data_df['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardOnly") & (
                               ble_obj.sniffer_data_df["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df[
                                                                                    "Secure Connection Pairing"] == "Yes") & (
                                                       ble_obj.sniffer_data_df[
                                                           'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df.loc[(ble_obj.sniffer_data_df[
                                                    'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
