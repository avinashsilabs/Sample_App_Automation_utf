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

    Author: Lenin Kale
"""


class BLEFunc(ThreadBase):
    def __init__(self, wifi_dut=None, nrf_ble_client=None, ble_client=None, ble_sniffer=None, error_code_expected=None, check_error=True, sniffer_check=False, layer_name=None,
                 capture_filename=None, smp_io_capability=None, smp_auth_bond=1, smp_mtim=1,ble_address_type=0, smp_enc_key=1, passkey_state=None, smp_sc=1, cap_on_dongle=None,
                 delay=0, nrf_connect_to_dut=False, ble_connect_from_raspi=False, pair_connect_from_dut=False, pin_code=None, client_capability=None, dut_capability=None, capability_on_remote=None, random_addr_on_dut=False, dynamic_passkey=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_address_type=ble_address_type
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
        self.cap_on_dongle = cap_on_dongle
        self.delay = delay
        self.nrf_connect_to_dut = nrf_connect_to_dut
        self.ble_connect_from_raspi = ble_connect_from_raspi
        self.pair_connect_from_dut = pair_connect_from_dut
        self.pin_code = pin_code
        self.client_capability= client_capability
        self.capability_on_remote = capability_on_remote
        self.sniffer_data_df_1 = None
        self.sniffer_data_df_2 = None
        self.random_addr_on_dut = random_addr_on_dut
        self.dynamic_passkey = dynamic_passkey



    def run(self):
        if self.sniffer_check:
            self.ble_sniffer.interfaces.sniffer.init_sniffer()
            self.ble_sniffer.interfaces.sniffer.start_capture(capture_file=self.capture_filename)
        logger().info("Initiate ble service in DUT")
        logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability}")
        ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=1, capability=self.smp_io_capability)
        if self.random_addr_on_dut:
            ble_dut_address = "11:33:33:33:33:11"
            self.wifi_dut.interfaces.wifi.set_ble_address(ble_address=ble_dut_address)
        assert ble_dut_address, "failed to initiate ble in dut"
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        logger().info("Enabling Wlan and BLE power save ")
        if power_save:
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        if self.nrf_connect_to_dut:

            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability}")
            self.wifi_dut.interfaces.wifi.ble_set_cap_data(remote_addr_type=1, smp_io_cap=self.smp_io_capability, smp_auth_req_bonding= self.smp_auth_bond, smp_auth_req_mitm=self.smp_mtim,
                                                      smp_auth_req_sc=self.smp_sc, smp_max_enc_key_size=16,
                                                      smp_local_oob_data_flag_not_present=0, smp_enc_key=self.smp_enc_key, smp_id_key=0,
                                                      smp_sign_key=0)

            logger().info("Enabled Wlan and BLE power save successfully")
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
            if self.dynamic_passkey:
                logger().info("Registering dynamic passkey entry")
                self.nrf_ble_client.interfaces.bluetooth.register_dynamic_passkey_entry()
                time.sleep(3)
            time.sleep(3)
            self.wifi_dut.interfaces.wifi.set_ble_address(ble_address=ble_dut_address)
            logger().info(f"Start scanning and connect to ble client")
            self.wifi_dut.interfaces.wifi.ble_start_scanning(
            ble_client_address=ble_client_address, ble_address_type=self.ble_address_type, timeout=30
            )

            timeout = 120
            time.sleep(5)
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
            logger().info(f"Initiating connection this can take upto {timeout} seconds....")

            for retry_count in range(0, 3):
                try:
                    self.wifi_dut.interfaces.wifi.ble_connect(
                        ble_remote_dev_address=ble_client_address, timeout=timeout, expected="RSI_BLE_ENCRYPT_STARTED_EVENT"
                    )

                    time.sleep(3)
                    break
                except Exception as err:
                        logger().warning(f"Connection Failed...RETRY COUNT IS {retry_count + 1}\nWarning:{err}")
                        time.sleep(15)

        if self.pair_connect_from_dut:
            self.wifi_dut.interfaces.wifi.bt_set_local_name("BLE_UNIFIED_DEMO")
            # Start ble client
            ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                pin_code=self.pin_code, capability=self.client_capability, bt_dut_address=ble_dut_address
            )
            assert ble_client_address is not None
            time.sleep(1)
            # Start scanning and connect to ble client
            self.wifi_dut.interfaces.wifi.ble_start_scanning(
                ble_client_address=ble_client_address, timeout=60
            )

            def connect():
                self.wifi_dut.interfaces.wifi.ble_connect(
                    ble_remote_dev_address=ble_client_address, timeout=120
                )

            t = threading.Thread(target=connect)
            t.start()

            tw = Stopwatch()
            pass_key_found = False
            while tw.elapsed_sec < 30:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.BLE_SC_PASSKEY:
                        if "passkey" in event.event_data:
                            passkey = re.findall(r"passkey: ([\d]*)", event.event_data)
                            if passkey[0] is not None:
                                pass_key_value = str(passkey[0])
                                logger().info(f"passkey : {pass_key_value}")
                                self.ble_client.interfaces.bluetooth.set_pin(pass_key_value)
                                pass_key_found = True
                                break
                if pass_key_found:
                    break
                time.sleep(1)

            time.sleep(10)

            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            if t is not None:
                t.join()
            if state_int == 8:
                self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)

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
            logger().info(f"Link Key Extracted:{link_key}")
            if self.ble_connect_from_raspi or self.pair_connect_from_dut or len(link_key) > 34:
                link_key_data =link_key
                link_key_value = re.split("--", link_key_data)
                link_key_re = re.split("$", link_key_value[0])
                link_key = ""
                for value in link_key_re[0]:
                    if value.isalnum():
                        link_key = link_key + value
                logger().info(f"Link Key Extracted:{link_key}")
            else:
               logger().info(f"**************Link Key Extracted: {link_key}***************")
               assert len(link_key) == 34, f"link key is not proper format"
            time.sleep(60)
            if self.ble_connect_from_raspi or self.pair_connect_from_dut:
                self.ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])
                time.sleep(30)
                if link_key != "":
                    self.ble_sniffer.interfaces.sniffer.add_link_key(link_key.upper(), master_address,
                                                                     slave_address)
            else:
                self.ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address+f" type=random"])
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
        # self.sniffer_file_export()
        if self.sniffer_check:
            self.ble_sniffer.interfaces.sniffer.stop_capture()
            captured_files = str(self.ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            for layer in self.layer_name:
                layer_file = self.ble_sniffer.interfaces.sniffer.export_to_csv("LE", layer)
                logger().info(f"**********layer name : {layer_file}**********")
                layer_file = layer_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(layer_file)
                assert file_size > 0
                if layer == "LE LL":
                    self.sniffer_data_df_1 = self.ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(
                        layer_file)
                    assert self.sniffer_data_df_1 is not None
                else:
                    self.sniffer_data_df_2 = self.ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(
                        layer_file)
                    assert self.sniffer_data_df_2 is not None
            return self.sniffer_data_df_1, self.sniffer_data_df_2

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

"""
    Test case category : BLE SMP with IO Capabilities 
    Device roles       : DUT is performing Central role with Public address with Different IO Capabilities
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through Teledyne sniffer
"""

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_JustWorks_Pairing_IOCap_Both_Initiator_Responder_DisplayOnly_C664756(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Just Works][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664756",  smp_io_capability=0, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY,  nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[(ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]) , "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                    ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                         'MITM'] == "MITM Protection:  Yes") & (
                                                           ble_obj.sniffer_data_df_2[
                                                               'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                    ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                         'MITM'] == "MITM Protection:  Yes") & (
                                                           ble_obj.sniffer_data_df_2[
                                                               'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Just_Works_Pairing_IOCap_Initiator_DisplayOnly_Responder_Display_Yes_or_No_C664761(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Just Works][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664761",  smp_io_capability=0, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Just_works_Pairing_IOCap_Initiator_DisplayOnly_Responder_No_Input_No_Output_C664771(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Just Works][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664771",  smp_io_capability=0, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                     'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_JustWorks_Pairing_IOCap_Initiator_Display_yes_no_Responder_DisplayOnly_C664757(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Just Works][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664757",  smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY,  nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                        'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Numeric_comparision_IOCap_Both_Initiator_Responder_Display_Yes_No_C664762(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Numeric Comparison][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664762",  smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO,  nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                     'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Just_works_Pairing_IOCap_Initiator_Display_Yes_No_Responder_No_Input_No_Output_C664772(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Just Works][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664772",  smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                     'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                     'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Just_works_Pairing_IOCap_Initiator_No_Input_No_Output_Responder_DisplayOnly_C664759(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Just Works][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664759",  smp_io_capability=3, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                     'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                     'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"

        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Just_works_Pairing_IOCap_Initiator_No_Input_No_Output_Responder_Display_Yes_or_no_C664764(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Just Works][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664764",  smp_io_capability=3, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                        'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Just_works_Pairing_IOCap_Both_Initiator_and_Responder_No_Input_No_Output_C664774(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Just Works][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664774",  smp_io_capability=3, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                        'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

"""
    Test case category : BLE SMP with IO Capabilities 
    Device roles       : DUT is performing Central role with Random address with Different IO Capabilities
    Fixures used: * ble_sniffer: To caputre BLE OTA logs through Teledyne sniffer
"""

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_JustWorks_Pairing_IOCap_Both_Initiator_Responder_DisplayOnly_DUT_Random_Addr_C664781(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Just Works][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664781",
                          smp_io_capability=0, passkey_state=0, ble_address_type=1,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY,  nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                        'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                        'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(5)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Just_Works_Pairing_IOCap_Initiator_DisplayOnly_Responder_Display_Yes_or_No_DUT_Random_addr_C664786(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Just Works][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client,ble_address_type=1, ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664786",  smp_io_capability=0, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(5)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Just_works_Pairing_IOCap_Initiator_DisplayOnly_Responder_No_Input_No_Output_DUT_Random_addr_C664796(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Just Works][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_address_type=1,ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664796",  smp_io_capability=0, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(5)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_JustWorks_Pairing_IOCap_Initiator_Display_yes_no_Responder_DisplayOnly_DUT_Random_addr_C664782(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Just Works][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client,ble_address_type=1, ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664782",  smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY,  nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(5)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Numeric_comparision_IOCap_Both_Initiator_Responder_Display_Yes_No_DUT_Random_addr_C664787(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Numeric Comparison][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_address_type=1,ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664787",  smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO,  nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(5)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Just_works_Pairing_IOCap_Initiator_Display_Yes_No_Responder_No_Input_No_Output_DUT_Random_addr_C664797(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Just Works][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client,ble_address_type=1, ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664797",  smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(5)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Just_works_Pairing_IOCap_Initiator_No_Input_No_Output_Responder_DisplayOnly_DUT_Random_addr_C664784(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Just Works][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,ble_address_type=1,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664784",  smp_io_capability=3, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(5)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Just_works_Pairing_IOCap_Initiator_No_Input_No_Output_Responder_Display_Yes_or_no_DUT_Random_addr_C664789(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Just Works][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,ble_address_type=1,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664789",  smp_io_capability=3, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                        'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(5)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Just_works_Pairing_IOCap_Both_Initiator_and_Responder_No_Input_No_Output_DUT_Random_addr_C664799(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Just Works][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,ble_address_type=1,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664799",  smp_io_capability=3, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                        'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(5)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Numeric_comparision_IOCap_Both_Initiator_Responder_keyboard_display_Display_Yes_No_C664765(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Numeric Comparison][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664765",  smp_io_capability=4, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO,  nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                     'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Numeric_comparision_IOCap_Both_Initiator_Responder_keyboard_display_keyboard_display_C664780(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Numeric Comparison][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664780",  smp_io_capability=4, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_DISPLAY,  nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                     'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Numeric_comparision_IOCap_Both_Initiator_Responder_keyboard_display_Display_Yes_No_using_random_C664790(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Numeric Comparison][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C664790",  smp_io_capability=4, passkey_state=0,
                          cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO,  nrf_connect_to_dut=True,
                          random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                     'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_Numeric_comparision_IOCap_Both_Initiator_Responder_keyboard_display_keyboard_display_using_random_C664805(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Numeric Comparison][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C664805",  smp_io_capability=4, passkey_state=0,
                          cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_DISPLAY,  nrf_connect_to_dut=True,
                          random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                    ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                     'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                    'MITM'] == "MITM Protection:  Yes") & (
                                                       ble_obj.sniffer_data_df_2[
                                                           'Secure Connection Pairing'] == "Yes")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "1") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Side'] == "2") & (
                    ble_obj.sniffer_data_df_2['Code'] == "Pairing DHKey Check")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


