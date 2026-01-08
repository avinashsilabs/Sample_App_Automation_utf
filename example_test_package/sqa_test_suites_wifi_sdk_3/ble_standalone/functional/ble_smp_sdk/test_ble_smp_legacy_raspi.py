from utf.utils.logger import get_logger
import time
import pytest
from utf.utils.stopwatch import Stopwatch
import threading
import re
import os
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import (Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap,
    Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes)
from utf.utils.thread_base import ThreadBase
from utf.utils import mac_address_to_string, mac_address_to_dbus_bt_path


def logger():
    return get_logger(__name__)

"""
    * setup requirement:
        1. DUT(RS9117) SOC board
        2. REF(RS9117) SOC board 
        3. Raspberry Pi with BlueZ stack
        4. Frontline sniffer(with BLE option) 
        5. Ellysis (to Capture OTA logs) - optional
    Author: 
        RaviNemali/ Kagitha Srinivasarao
"""


class BLEFunc(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_sniffer=None, error_code_expected=None, check_error=True,
                 sniffer_check=False, layer_name=None, capture_filename=None, smp_io_capability=None,
                 encrypted_file=False, smp_auth_bond=1, smp_mtim=1, smp_enc_key=1, passkey_state=None, smp_sc=0,
                 cap_on_dongle=None, delay=0, nrf_connect_to_dut=False, ble_connect_from_raspi=False,
                 pair_connect_from_dut=False, pin_code=None, client_capability=None, dut_capability=None,
                 capability_on_remote=None, mtim_disabled=False, lesc_disabled=False, reconnection_from_remote=False,
                 powersave=True, random_addr_on_dut=False, local_oob_flag=False, nrf_dongle_as_master=False,
                 passkey_entry=False, dynamic_passkey=False, auth_req=None, passkey_entry_on_dut_ref=False):
        super().__init__()
        self.sniffer_data_df_2 = None
        self.sniffer_data_df_1 = None
        self.wifi_dut = wifi_dut
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
        self.ble_dut_address = None
        self.ble_client_address = None
        self.sniffer_data_df = None
        self.auth_req = auth_req
        self.passkey_entry_on_dut_ref = passkey_entry_on_dut_ref

    def run(self):
        if self.sniffer_check or self.encrypted_file:
            self.ble_sniffer.interfaces.sniffer.init_sniffer()
            logger().info("sniffer capture started")
            self.ble_sniffer.interfaces.sniffer.start_capture(capture_file=self.capture_filename)
        logger().info("Initiate ble service in DUT")
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(capability=self.dut_capability,
                                                                       set_smp=0)
        assert self.ble_dut_address, "failed to initiate ble in dut"
        if self.random_addr_on_dut:
            self.ble_dut_address = "11:33:33:33:33:11"
            self.wifi_dut.interfaces.wifi.set_ble_address(ble_address=self.ble_dut_address)
        if self.random_addr_on_dut:
            self.wifi_dut.interfaces.wifi.ble_set_cap_data(remote_addr_type=1, smp_io_cap=self.smp_io_capability,
                                                           smp_auth_req_bonding=self.smp_auth_bond,
                                                           smp_auth_req_mitm=self.smp_mtim,
                                                           smp_auth_req_sc=self.smp_sc, smp_max_enc_key_size=16,
                                                           smp_local_oob_data_flag_not_present=0,
                                                           smp_enc_key=self.smp_enc_key, smp_id_key=0, smp_sign_key=0)
        else:
            self.wifi_dut.interfaces.wifi.ble_set_cap_data(remote_addr_type=0, smp_io_cap=self.smp_io_capability,
                                                           smp_auth_req_bonding=self.smp_auth_bond,
                                                           smp_auth_req_mitm=self.smp_mtim,
                                                           smp_auth_req_sc=self.smp_sc, smp_max_enc_key_size=16,
                                                           smp_local_oob_data_flag_not_present=0,
                                                           smp_enc_key=self.smp_enc_key, smp_id_key=0, smp_sign_key=0)

        if self.smp_io_capability == 0:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> DisplayOnly")
        elif self.smp_io_capability == 1:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> Display yes or no")
        elif self.smp_io_capability == 2:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> keyboardOnly")
        elif self.smp_io_capability == 3:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> No Input No output")
        else:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> Keyboarddisplay")
        self.wifi_dut.interfaces.wifi.ble_modify_passkey_event(passkey_state=self.passkey_state, delay=0)
        if self.random_addr_on_dut:
            logger().info("\n\n======= start ble adv in dut with random addr========")
            self.wifi_dut.interfaces.wifi.ble_start_advertising(own_addr_type=1, ble_addr_type=1, ble_dir_addr=self.ble_client_address)
        else:
            self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_dir_addr=self.ble_client_address)
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                           psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        logger().info("Start smp scan from the remote device")
        self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=self.ble_dut_address,
            capability=self.client_capability,
            pin_code=self.pin_code)
        assert self.ble_client_address, "failed to initiate ble in remote device"
        time.sleep(5)
        logger().info("stop scanning ....")
        self.ble_client.interfaces.bluetooth.stop_scanning()
        logger().info("Check the dut is listed...")
        self.ble_client.interfaces.bluetooth.get_devices()
        logger().info("Set secure connection to off in remote device...")
        self.ble_client.interfaces.bluetooth.set_secure_connection(sc="off")
        if self.passkey_entry:
            def connect():
                logger().info("Connect to the dut with mac address..")
                connect_state = self.ble_client.interfaces.bluetooth.pair_and_connect(self.ble_dut_address)
                assert connect_state, "unable to connect to the given address"
                logger().info("BLE Connection success")
            t = threading.Thread(target=connect)
            t.start()
            time.sleep(10)
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
                            self.ble_client.interfaces.bluetooth.set_pin(pass_key_value)
                            logger().info("checking the connection state...")
                            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                            state_int = int(state) if state.isdigit() else -1
                            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
                            logger().info("checking connection stability")
                            time.sleep(180)
                            pass_key_found = True
                            break
                    time.sleep(1)
                if pass_key_found:
                    break
        elif self.passkey_entry_on_dut_ref:
            self.ble_client.interfaces.bluetooth.connect(dev_addr=self.ble_dut_address)
            self.ble_client.interfaces.bluetooth.set_pin(pin_code="123456")
            self.wifi_dut.interfaces.wifi.ble_set_smp_passkey(remote_dev_addr=self.ble_client_address,
                                                         smp_passkey="123456")
            device_path = mac_address_to_dbus_bt_path(
                self.ble_client.interfaces.bluetooth.adapter_path, mac_address=self.ble_dut_address
            )
            def pair_reply():
                pass

            def pair_error(error):
                pass

            self.ble_client.interfaces.bluetooth._dev_manager.pair(
                bus=self.ble_client.interfaces.bluetooth.bus,
                device_path=device_path,
                reply_handler=pair_reply,
                error_handler=pair_error,
                timeout=60 * 1000,
            )

            logger().info("checking the connection state...")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            time.sleep(180)
        else:
            def connect():
                logger().info("Connect to the dut with mac address..")
                connect_state = self.ble_client.interfaces.bluetooth.pair_and_connect(self.ble_dut_address)
                assert connect_state, "unable to connect to the given address"
                logger().info("BLE Connection success")
            t = threading.Thread(target=connect)
            t.start()
            time.sleep(10)
            passkey = self.ble_client.interfaces.bluetooth.get_passkey()
            time.sleep(5)
            self.wifi_dut.interfaces.wifi.ble_set_smp_passkey(remote_dev_addr=self.ble_client_address,
                                                              smp_passkey=passkey)
            time.sleep(3)
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            time.sleep(180)
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
        logger().info("Connection has set successfully...")
        if state_int == 8:
            self.ble_client.interfaces.bluetooth.disconnect(dev_addr=self.ble_dut_address)
        if self.sniffer_check:
            ble_dut_address_hex = re.split(":", self.ble_dut_address)
            ble_client_address_hex = re.split(":", self.ble_client_address)
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
            link_key1 = link_key.replace(" ", "")
            link_key1 = link_key1.replace("link_key", "")
            link_value1 = link_key1.split("$")
            logger().info(f"**********link key : {link_value1[0]}")
            linkey_key_value = link_value1[0]
            if self.random_addr_on_dut:
                self.ble_sniffer.interfaces.sniffer.select_bt_devices(
                    [slave_address])
                if link_key != "":
                    self.ble_sniffer.interfaces.sniffer.add_link_key(linkey_key_value.upper(), master_address,
                                                                     slave_address)
            else:
                logger().info("selecting bt devices for sniffer capture")
                self.ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])
                time.sleep(30)
                if link_key != "":
                    logger().info("adding link key for sniffer capture")
                    self.ble_sniffer.interfaces.sniffer.add_link_key(linkey_key_value.upper(), master_address,
                                                                     slave_address)
        if self.sniffer_check:
            logger().info("Waiting for sniffer capture to complete...")
            self.ble_sniffer.interfaces.sniffer.stop_capture()
            captured_files = str(self.ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            logger().info(f"captured_files : {captured_files}")
            time.sleep(30)
            for layer in self.layer_name:
                logger().info(f"layer : {self.layer_name}")
                logger().info(f"Exporting layer : {layer}")
                layer_file = self.ble_sniffer.interfaces.sniffer.export_to_csv("LE", layer)
                logger().info(f"layer_file : {layer_file}")
                layer_file = layer_file.replace("/tmp/reports", "/app/reports")
                logger().info(f"layer_file after replace : {layer_file}")
                file_size = os.path.getsize(layer_file)
                logger().info(f"file_size : {file_size}, layer_file : {layer_file}")
                assert file_size > 0
                if layer == "LE LL":
                    self.sniffer_data_df_1 = self.ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(
                        layer_file)
                    logger().info(f"sniffer_data_df_1 : {self.sniffer_data_df_1}")
                    assert self.sniffer_data_df_1 is not None
                else:
                    self.sniffer_data_df_2 = self.ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(
                        layer_file)
                    logger().info(f"sniffer_data_df_2 : {self.sniffer_data_df_2}")
                    assert self.sniffer_data_df_2 is not None
            return self.sniffer_data_df_1, self.sniffer_data_df_2, self.ble_dut_address, self.ble_client_address


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                        Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                              Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                                   Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                               Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
]


@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (2, "DisplayOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_passkey_entry_pairing_Initiator_display_only_responder_keyboard_only_C664300(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    """ Verify PasskeyEntry Pairing method for IOCap,Initiator(remote device) : DisplayOnly and Responder(DUT) :
    KeyboardOnly"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664300",
                          dut_capability=dut_capability, smp_io_capability=2, smp_sc=0, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01")
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (2, "DisplayYesNo", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_passkey_entry_pairing_Initiator_display_yesno_responder_keyboard_only_C664301(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    """ Verify PasskeyEntry Pairing method for IOCap, Initiator: DisplayYesNo and Responder: KeyboardOnly"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664301",
                          dut_capability=dut_capability, smp_io_capability=2, smp_sc=0, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01")
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (2, "KeyboardDisplay", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_display_responder_keyboard_only_C664304(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    """ Verify JustWorks Pairing method for IOCap, Initiator: KeyboardDisplay , Responder: KeyboardOnly."""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664304",
                          dut_capability=dut_capability, smp_io_capability=2, smp_sc=0, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01")
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()



@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (2, "DisplayYesNo", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_passkey_entry_pairing_Initiator_display_yesno_responder_keyboard_only_C664326(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    """ Verify PasskeyEntry Pairing method for IOCap, Initiator: DisplayYesNo and Responder: KeyboardOnly."""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664326",
                          dut_capability=dut_capability, smp_io_capability=2, smp_sc=0, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01",
                          random_addr_on_dut=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (4, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_only_responder_keyboard_display_C664312(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    """ Verify PasskeyEntry Pairing method for IOCap, Initiator: KeyBoardOnly , Responder: KeyboardDisplay."""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664312",
                          dut_capability=dut_capability, smp_io_capability=4, smp_sc=0, passkey_state=0,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01", passkey_entry=True)

        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                      'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (2, "DisplayOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_passkey_entry_pairing_Initiator_display_only_responder_keyboard_only_C664325(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    """ Verify PasskeyEntry Pairing method for IOCap,Initiator(remote device) : DisplayOnly and Responder(DUT) :
    KeyboardOnly."""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664325",
                          dut_capability=dut_capability, smp_io_capability=2, smp_sc=0, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01",
                          random_addr_on_dut=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (2, "KeyboardDisplay", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_display_responder_keyboard_only_C664329(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    """ Verify JustWorks Pairing method for IOCap, Initiator: KeyboardDisplay , Responder: KeyboardOnly."""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664329",
                          dut_capability=dut_capability, smp_io_capability=2, smp_sc=0, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01",
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (4, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_only_responder_keyboard_display_C664337(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    """ Verify PasskeyEntry Pairing method for IOCap, Initiator: KeyBoardOnly , Responder: KeyboardDisplay."""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664337",
                          dut_capability=dut_capability, smp_io_capability=4, smp_sc=0, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01",
                          random_addr_on_dut=True, passkey_entry=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (2, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_only_responder_keyboard_only_C664302(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    """ Verify PasskeyEntry Pairing method for IOCap, Initiator : KeyBoardOnly , Responder : KeyboardOnly."""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664302",
                          dut_capability=dut_capability, smp_io_capability=2, smp_sc=0, passkey_state=0,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01",
                          passkey_entry_on_dut_ref=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                      'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (2, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_only_responder_keyboard_only_C664327(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    """ Verify PasskeyEntry Pairing method for IOCap, Initiator : KeyBoardOnly , Responder : KeyboardOnly."""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664327",
                          dut_capability=dut_capability, smp_io_capability=2, smp_sc=0, passkey_state=0,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01",
                          passkey_entry_on_dut_ref=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()


class BLEFunc1(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_sniffer=None, error_code_expected=None, check_error=True,
                 sniffer_check=False, layer_name=None, capture_filename=None, smp_io_capability=None,
                 encrypted_file=False, smp_auth_bond=1, smp_mtim=1, smp_enc_key=1, passkey_state=None, smp_sc=0,
                 cap_on_dongle=None, delay=0, nrf_connect_to_dut=False, ble_connect_from_raspi=False,
                 pair_connect_from_dut=False, pin_code=None, client_capability=None, dut_capability=None,
                 capability_on_remote=None, mtim_disabled=False, lesc_disabled=False, reconnection_from_remote=False,
                 powersave=True, random_addr_on_dut=False, local_oob_flag=False, nrf_dongle_as_master=False,
                 passkey_entry=False, dynamic_passkey=False, auth_req=None, passkey_entry_on_dut_ref=None,
                 confirmation_passkey=False, reconnection=False, bond_info=False, passkey_timeout=30):
        super().__init__()
        self.sniffer_data_df_2 = None
        self.sniffer_data_df_1 = None
        self.wifi_dut = wifi_dut
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
        self.ble_dut_address = None
        self.ble_client_address = None
        self.sniffer_data_df = None
        self.auth_req = auth_req
        self.passkey_entry_on_dut_ref = passkey_entry_on_dut_ref
        self.confirmation_passkey = confirmation_passkey
        self.reconnection = reconnection
        self.bond_info = bond_info
        self.passkey_timeout = passkey_timeout

    def run(self):
        io_capability = {"DisplayOnly": 0x00, "DisplayYesNo": 0x01, "KeyboardOnly": 0x02, "NoInputNoOutput": 0x03,
                         "KeyboardDisplay": 0x04}

        if self.sniffer_check or self.encrypted_file:
            self.ble_sniffer.interfaces.sniffer.init_sniffer()
            logger().info("sniffer capture started")
            self.ble_sniffer.interfaces.sniffer.start_capture(capture_file=self.capture_filename)

        logger().info("Initiate ble service in DUT")
        if self.bond_info:
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(capability=self.dut_capability,
                                                                           set_smp=self.smp_sc, bond_info=1)
        else:
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(capability=self.dut_capability,
                                                                           set_smp=0)
        assert self.ble_dut_address, "failed to initiate ble in dut"

        if self.random_addr_on_dut:
            self.ble_dut_address = "11:22:22:33:33:11"
            self.wifi_dut.interfaces.wifi.set_ble_address(ble_address=self.ble_dut_address)
            time.sleep(2)

        # Configure SMP parameters
        self.wifi_dut.interfaces.wifi.ble_set_cap_data(
            remote_addr_type=0,
            smp_io_cap=self.smp_io_capability,
            smp_auth_req_bonding=self.smp_auth_bond,
            smp_auth_req_mitm=self.smp_mtim,
            smp_auth_req_sc=self.smp_sc,
            smp_max_enc_key_size=16,
            smp_local_oob_data_flag_not_present=0,
            smp_enc_key=self.smp_enc_key,
            smp_id_key=0,
            smp_sign_key=0
        )
        time.sleep(1)

        capability_names = ["DisplayOnly", "Display yes or no", "keyboardOnly", "No Input No output", "Keyboarddisplay"]
        logger().info(
            f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> {capability_names[self.smp_io_capability]}")

        time.sleep(1)
        self.wifi_dut.interfaces.wifi.ble_modify_passkey_event(passkey_state=self.passkey_state, delay=0)
        time.sleep(1)

        # Start advertising
        if self.random_addr_on_dut:
            logger().info("\n\n======= start ble adv in dut with random addr========")
            self.wifi_dut.interfaces.wifi.ble_start_advertising(own_addr_type=1, ble_addr_type=1,
                                                                ble_dir_addr=self.ble_client_address)
        else:
            self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_dir_addr=self.ble_client_address)
        time.sleep(2)

        # Enable power save
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        time.sleep(1)
        self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                           psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        time.sleep(1)

        logger().info("Start smp scan from the remote device")
        self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=self.ble_dut_address,
            capability=self.client_capability,
            pin_code=self.pin_code
        )
        assert self.ble_client_address, "failed to initiate ble in remote device"
        time.sleep(5)

        logger().info("stop scanning ....")
        self.ble_client.interfaces.bluetooth.stop_scanning()
        logger().info("Check the dut is listed...")
        time.sleep(1)
        self.ble_client.interfaces.bluetooth.get_devices()

        logger().info("Set secure connection to off in remote device...")
        if not self.smp_sc:
            self.ble_client.interfaces.bluetooth.set_secure_connection(sc="off")
            time.sleep(1)

        # PASSKEY ENTRY MODE (when passkey is entered on Raspberry Pi)
        if self.passkey_entry:
            pairing_success = False
            passkey_value = None

            def connect():
                nonlocal pairing_success
                try:
                    logger().info("Connect to the dut with mac address..")
                    time.sleep(1)
                    connect_state = self.ble_client.interfaces.bluetooth.pair_and_connect(self.ble_dut_address)
                    pairing_success = connect_state
                    if connect_state:
                        logger().info("BLE Connection success")
                except Exception as e:
                    logger().error(f"Connection error: {e}")

            t = threading.Thread(target=connect)
            t.start()
            time.sleep(3)
            tw = Stopwatch()
            pass_key_found = False

            logger().info(f"Monitoring for passkey event (timeout: {self.passkey_timeout}s)...")

            while tw.elapsed_sec < self.passkey_timeout and not pass_key_found:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                for event in events:
                    if "passkey" in event.event_data:
                        passkey = re.findall(r"passkey[:\s]+(\d{6})", event.event_data)
                        if passkey and len(passkey) > 0:
                            passkey_value = str(passkey[0])
                            logger().info(f"✓ Passkey received: {passkey_value}")
                            logger().info("Entering passkey on Raspberry Pi immediately")
                            self.ble_client.interfaces.bluetooth.set_pin(passkey_value)
                            pass_key_found = True
                            break

            if not pass_key_found:
                logger().error(f"✗ Passkey not found within {self.passkey_timeout}s")
                raise TimeoutError(f"Passkey not received within {self.passkey_timeout}s")

            t.join(timeout=15)

            if not pairing_success:
                logger().error("✗ Pairing did not complete successfully")
                raise ConnectionError("Pairing failed")
            time.sleep(2)      
        elif not self.passkey_entry_on_dut_ref and not self.confirmation_passkey:
            pairing_complete = threading.Event()
            pairing_error = []
            disconnect_detected = False
            encryption_started = False
            raspi_pairing_failed = False

            def monitor_events():
                """Monitor for encryption, SMP failures, and disconnect events"""
                nonlocal disconnect_detected, encryption_started
                while not pairing_complete.is_set():
                    events = self.wifi_dut.interfaces.wifi.get_async_events()
                    for event in events:
                        event_str = str(event.event_data)

                        # Check for encryption started
                        if 'RSI_BLE_ENCRYPT_STARTED_EVENT' in event_str or 'encrypt_started' in event_str.lower():
                            logger().info(f"✓ Encryption started on DUT")
                            encryption_started = True

                        # Check for SMP failure
                        if 'RSI_BLE_SMP_FAILED_EVENT' in event_str or 'smp_failed' in event_str.lower():
                            logger().error(f"SMP FAILURE DETECTED: {event_str}")
                            disconnect_detected = True
                            pairing_error.append(f"SMP failed: {event_str}")
                            pairing_complete.set()
                            return

                        # Check for disconnect
                        if 'disconnect' in event_str.lower():
                            logger().error(f"DISCONNECT DETECTED: {event_str}")
                            disconnect_detected = True
                            pairing_error.append(f"Disconnected: {event_str}")
                            pairing_complete.set()
                            return

                    time.sleep(0.2)

            def connect():
                nonlocal raspi_pairing_failed
                try:
                    logger().info("Initiating pairing and connection...")

                    # Pre-emptively trust the device to prevent BlueZ timeout cancellation
                    logger().info("Pre-emptively trusting device to prevent authentication cancellation...")
                    try:
                        device_path = f"/org/bluez/hci0/dev_{self.ble_dut_address.replace(':', '_')}"
                        self.ble_client.interfaces.bluetooth._dev_manager.set_trusted(
                            self.ble_client.interfaces.bluetooth.bus,
                            device_path,
                            value=True
                        )
                        logger().info("✓ Device pre-emptively trusted on Raspberry Pi")
                    except Exception as e:
                        logger().warning(f"⚠ Failed to pre-emptively trust device (may not exist yet): {e}")

                    connect_state = self.ble_client.interfaces.bluetooth.pair_and_connect(
                        self.ble_dut_address,
                        timeout=60
                    )
                    if connect_state:
                        logger().info("✓ Raspberry Pi pairing completed successfully")
                    else:
                        logger().error("✗ Raspberry Pi pairing returned False")
                        raspi_pairing_failed = True
                    pairing_complete.set()
                except Exception as e:
                    logger().error(f"✗ Raspberry Pi connection exception: {e}")
                    pairing_error.append(str(e))
                    pairing_complete.set()

            # Start both threads
            connect_thread = threading.Thread(target=connect, daemon=True)
            monitor_thread = threading.Thread(target=monitor_events, daemon=True)
            connect_thread.start()
            monitor_thread.start()
            # Wait for passkey to appear
            time.sleep(3)
            # Get passkey with timeout
            passkey = None
            get_passkey_attempts = 0
            while get_passkey_attempts < 5 and not pairing_complete.is_set():
                passkey = self.ble_client.interfaces.bluetooth.get_passkey()
                if passkey:
                    break
                time.sleep(0.5)
                get_passkey_attempts += 1

            if passkey and not disconnect_detected:
                logger().info(f" Passkey received: {passkey}")
                # Enter passkey on DUT
                logger().info(f"Entering passkey on DUT for connection to {self.ble_client_address}...")
                self.wifi_dut.interfaces.wifi.ble_set_smp_passkey(
                    remote_dev_addr=self.ble_client_address,
                    smp_passkey=passkey
                )
                # Wait for encryption to start
                logger().info("Waiting for encryption to start...")
                tw = Stopwatch()
                while tw.elapsed_sec < 10 and not encryption_started and not disconnect_detected:
                    time.sleep(0.5)

                if not encryption_started:
                    logger().error(" Encryption did not start within 10 seconds")
                    raise TimeoutError("Encryption did not start")

                if disconnect_detected:
                    logger().error(" Disconnected before encryption completed")
                    raise ConnectionError(f"Disconnected: {pairing_error[0] if pairing_error else 'Unknown'}")

                logger().info(" Encryption started successfully")

                # Trust device immediately after encryption to prevent any scheduled cancellation
                logger().info("Re-trusting device after encryption to prevent cancellation...")
                try:
                    device_path = f"/org/bluez/hci0/dev_{self.ble_dut_address.replace(':', '_')}"
                    self.ble_client.interfaces.bluetooth._dev_manager.set_trusted(
                        self.ble_client.interfaces.bluetooth.bus,
                        device_path,
                        value=True
                    )
                    logger().info(" Device re-trusted after encryption")
                except Exception as e:
                    logger().warning(f"⚠ Failed to re-trust device after encryption: {e}")

                # Wait for Raspberry Pi to complete pairing
                logger().info("Waiting for Raspberry Pi to confirm pairing...")
                pairing_complete.wait(timeout=65)  # Wait for connect thread to finish

                # Stop the initial monitor thread
                pairing_complete.set()
                monitor_thread.join(timeout=2)            
                connect_thread.join(timeout=2)
                # Handle pairing failure - cancel BlueZ pairing to stop the 2-minute timer
                if raspi_pairing_failed:
                    logger().info("Pairing returned False - canceling BlueZ pairing operation...")
                    try:
                        device_path = f"/org/bluez/hci0/dev_{self.ble_dut_address.replace(':', '_')}"

                        # Cancel the ongoing pairing to stop the 2-minute authentication timer
                        logger().info("Canceling BlueZ pairing to stop authentication timer...")
                        try:
                            self.ble_client.interfaces.bluetooth._dev_manager.cancel_pairing(
                                self.ble_client.interfaces.bluetooth.bus,
                                device_path
                            )
                            logger().info(" BlueZ pairing canceled")
                            time.sleep(1) 
                        except Exception as cancel_error:
                            logger().warning(f" Could not cancel pairing (may have already completed): {cancel_error}")

                        # Now trust the device
                        self.ble_client.interfaces.bluetooth._dev_manager.set_trusted(
                            self.ble_client.interfaces.bluetooth.bus,
                            device_path,
                            value=True
                        )
                        logger().info(" Device trusted on Raspberry Pi after pairing failure")
                    except Exception as e:
                        logger().warning(f" Failed to trust device after pairing: {e}")

                # Check for any pairing errors from monitor thread
                if pairing_error:
                    logger().error(f"✗ Pairing failed: {pairing_error[0]}")
                    raise ConnectionError(f"Pairing failed: {pairing_error[0]}")      
                stability_complete = threading.Event()
                stability_error = []

                def stability_event_monitor():
                    """Continuously monitor for disconnects during stability check"""
                    while not stability_complete.is_set():
                        events = self.wifi_dut.interfaces.wifi.get_async_events()
                        for event in events:
                            event_str = str(event.event_data).lower()
                            if 'disconnect' in event_str or 'smp_failed' in event_str:
                                #logger().error(f"STABILITY CHECK FAILURE: {event.event_data}")
                                stability_error.append(f"Event during stability check: {event.event_data}")
                                stability_complete.set()
                                return
                        time.sleep(0.5)               
                stability_monitor_thread = threading.Thread(target=stability_event_monitor, daemon=True)
                stability_monitor_thread.start()
              
                stability_complete.set()
                stability_monitor_thread.join(timeout=2)       
                if stability_error:
                    logger().error(f" Connection failed during stability check")
                    logger().error(f"   Reason: {stability_error[0]}")
                    raise ConnectionError(f"Connection dropped: {stability_error[0]}")

            else:
                if disconnect_detected:
                    raise ConnectionError(f"Connection dropped: {pairing_error[0] if pairing_error else 'Unknown'}")
                else:
                    raise ValueError("No passkey received from Raspberry Pi")

        
        elif self.confirmation_passkey:
            self.ble_client.interfaces.bluetooth.connect(dev_addr=self.ble_dut_address)
            device_path = mac_address_to_dbus_bt_path(
                self.ble_client.interfaces.bluetooth.adapter_path, mac_address=self.ble_dut_address
            )

            def pair_reply():
                logger().info("Pairing reply received")

            def pair_error(error):
                logger().error(f"Pairing error: {error}")

            def pair():
                self.ble_client.interfaces.bluetooth._dev_manager.pair(
                    bus=self.ble_client.interfaces.bluetooth.bus,
                    device_path=device_path,
                    reply_handler=pair_reply,
                    error_handler=pair_error,
                    timeout=60 * 1000,
                )

            time.sleep(2)
            t = threading.Thread(target=pair)
            t.start()
            time.sleep(10)         
        elif self.passkey_entry_on_dut_ref:
            def connect():
                logger().info("Connect to the dut with mac address..")
                connect_state = self.ble_client.interfaces.bluetooth.pair_and_connect(self.ble_dut_address)
                time.sleep(8)
                assert connect_state, "unable to connect to the given address"
                logger().info("BLE Connection success")
            t = threading.Thread(target=connect)
            t.start()
            time.sleep(8)
            logger().info("Entering passkey on DUT")
            self.wifi_dut.interfaces.wifi.ble_set_smp_passkey(remote_dev_addr=self.ble_client_address,
                                                              smp_passkey="123456")
            time.sleep(4)
            logger().info("Entering the passkey in the raspi side")
            self.ble_client.interfaces.bluetooth.set_pin(pin_code="123456")

        time.sleep(180)    
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, f"DUT BLE device is not in connected state: {state_int}"        
        if state_int == 8:
            self.ble_client.interfaces.bluetooth.disconnect(dev_addr=self.ble_dut_address)       
        if self.sniffer_check:
            ble_dut_address_hex = re.split(":", self.ble_dut_address)
            ble_client_address_hex = re.split(":", self.ble_client_address)
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

            link_key1 = link_key.replace(" ", "")
            link_key1 = link_key1.replace("link_key", "")
            link_value1 = link_key1.split("$")
            linkey_key_value = link_value1[0]

            if self.random_addr_on_dut:
                self.ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address])
                if link_key != "":
                    self.ble_sniffer.interfaces.sniffer.add_link_key(linkey_key_value.upper(), master_address,
                                                                     slave_address)
            else:
                logger().info("selecting bt devices for sniffer capture")
                self.ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])
                time.sleep(30)
                if link_key != "":
                    logger().info("adding link key for sniffer capture")
                    self.ble_sniffer.interfaces.sniffer.add_link_key(linkey_key_value.upper(), master_address,
                                                                     slave_address)

        if self.sniffer_check:
            logger().info("Waiting for sniffer capture to complete...")
            self.ble_sniffer.interfaces.sniffer.stop_capture()
            captured_files = str(self.ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            logger().info(f"captured_files : {captured_files}")
            time.sleep(30)

            for layer in self.layer_name:
                logger().info(f"Exporting layer : {layer}")
                layer_file = self.ble_sniffer.interfaces.sniffer.export_to_csv("LE", layer)
                layer_file = layer_file.replace("/tmp/reports", "/app/reports")
                logger().info(f"layer_file after replace : {layer_file}")
                file_size = os.path.getsize(layer_file)
                logger().info(f"file_size : {file_size}, layer_file : {layer_file}")
                assert file_size > 0

                if layer == "LE LL":
                    self.sniffer_data_df_1 = self.ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(
                        layer_file)
                    logger().info(f"sniffer_data_df_1 : {self.sniffer_data_df_1}")
                    assert self.sniffer_data_df_1 is not None
                else:
                    self.sniffer_data_df_2 = self.ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(
                        layer_file)
                    logger().info(f"sniffer_data_df_2 : {self.sniffer_data_df_2}")
                    assert self.sniffer_data_df_2 is not None

            return self.sniffer_data_df_1, self.sniffer_data_df_2, self.ble_dut_address, self.ble_client_address
        
pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                        Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                              Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                                   Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                               Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
]

@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (4, "KeyboardDisplay", "-8"),
    ],
)
@pytest.mark.failed_check
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_display_responder_keyboard_display_C664314(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    ble_obj = None
    try:
        ble_obj = BLEFunc1(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            check_error=False,
            ble_sniffer=ble_sniffer,
            #sniffer_check=True,
            layer_name=["LE LL", "SMP"],
            capture_filename="frontline_capture_C664314",
            dut_capability=dut_capability,
            smp_io_capability=4,
            smp_sc=0,
            passkey_state=2,
            pin_code=pin_code,
            client_capability=client_capability,
            auth_req="0x01",
            passkey_timeout=30
        )
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        logger().error(f"Test failed: {error}")
        if ble_obj:
            sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
        raise

    finally:
        if ble_obj and ble_obj.ble_client_address and ble_obj.ble_dut_address:
            try:
                sl_collections.cleanup_ble(
                    ble_dut=wifi_dut,
                    ble_client=ble_client,
                    ble_client_address=ble_obj.ble_client_address,
                    ble_dut_address=ble_obj.ble_dut_address
                )
            except Exception as cleanup_error:
                logger().warning(f"Cleanup error (non-critical): {cleanup_error}")

            try:
                ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
            except Exception as remove_error:
                logger().warning(f"Remove device error (non-critical): {remove_error}")

        try:
            ble_client.interfaces.bluetooth.close()
        except Exception as close_error:
            logger().warning(f"Close error (non-critical): {close_error}")

@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (4, "KeyboardDisplay", "-8"),
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.failed_check
def test_ble_smp_NumericComparision_pairing_Initiator_keyboard_display_responder_keyboard_display_C664339(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    ble_obj = None
    try:
        time.sleep(8)
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664339",
                          dut_capability=dut_capability, smp_io_capability=4, smp_sc=0, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01",
                          random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
    except Exception as error:
        logger().error(f"Test failed: {error}")
        if ble_obj:
            sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
        raise
    finally:
        if ble_obj and ble_obj.ble_client_address and ble_obj.ble_dut_address:
            try:
                sl_collections.cleanup_ble(
                    ble_dut=wifi_dut,
                    ble_client=ble_client,
                    ble_client_address=ble_obj.ble_client_address,
                    ble_dut_address=ble_obj.ble_dut_address
                )
            except Exception as cleanup_error:
                logger().warning(f"Cleanup error (non-critical): {cleanup_error}")

            try:
                ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
            except Exception as remove_error:
                logger().warning(f"Remove device error (non-critical): {remove_error}")

        try:
            ble_client.interfaces.bluetooth.close()
        except Exception as close_error:
            logger().warning(f"Close error (non-critical): {close_error}")

@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (4, "DisplayYesNo", "-8"),
    ],
)
@pytest.mark.failed_check
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_display_responder_keyboard_display_C664311_1(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C664311_1",
                          dut_capability=dut_capability, smp_io_capability=4, smp_sc=0, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01")
        ble_obj.start()
        ble_obj.wait_for_exit()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()

@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (4, "DisplayOnly", "-8"),
    ],
)
@pytest.mark.failed_check
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_display_responder_keyboard_display_C664310_1(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    try:
        time.sleep(4)
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C664310_1",
                          dut_capability=dut_capability, smp_io_capability=4, smp_sc=0, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01")
        ble_obj.start()
        ble_obj.wait_for_exit()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()

@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (4, "DisplayOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.failed_case
def test_ble_smp_passkey_entry_pairing_Initiator_display_only_responder_keyboard_display_C664335(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C664335",
                          dut_capability=dut_capability, smp_io_capability=4, smp_sc=0, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01", random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        
        if ble_obj and ble_obj.ble_client_address and ble_obj.ble_dut_address:
            try:
                sl_collections.cleanup_ble(
                    ble_dut=wifi_dut,
                    ble_client=ble_client,
                    ble_client_address=ble_obj.ble_client_address,
                    ble_dut_address=ble_obj.ble_dut_address
                )
            except Exception as cleanup_error:
                logger().warning(f"Cleanup error (non-critical): {cleanup_error}")

            try:
                ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
            except Exception as remove_error:
                logger().warning(f"Remove device error (non-critical): {remove_error}")

        try:
            ble_client.interfaces.bluetooth.close()
        except Exception as close_error:
            logger().warning(f"Close error (non-critical): {close_error}")

@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        
        (1, "KeyboardDisplay", "-8"),
    ],
)
@pytest.mark.failed_check
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_NumericComparision_pairing_Initiator_display_yesno_responder_keyboard_display_C664336(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    ble_obj = None
    try:
        time.sleep(8)

        ble_obj = BLEFunc1(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            check_error=False,
            ble_sniffer=ble_sniffer,
            sniffer_check=True,
            layer_name=["LE LL", "SMP"],
            capture_filename="frontline_capture_C664336",
            dut_capability=dut_capability,    
            smp_io_capability=1,   # 0=DisplayOnly, 1=DisplayYesNo
            smp_sc=0,              # legacy pairing (as in your current run)
            passkey_state=2,
            pin_code=pin_code,         
            client_capability=client_capability,
            passkey_entry=True,
            passkey_timeout=30,
            auth_req="0x01",
            random_addr_on_dut=True,
        )

        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        logger().error(f"Test failed: {error}")
        if ble_obj:
            sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
        raise

    finally:
        if ble_obj and ble_obj.ble_client_address and ble_obj.ble_dut_address:
            try:
                sl_collections.cleanup_ble(
                    ble_dut=wifi_dut,
                    ble_client=ble_client,
                    ble_client_address=ble_obj.ble_client_address,
                    ble_dut_address=ble_obj.ble_dut_address
                )
            except Exception as cleanup_error:
                logger().warning(f"Cleanup error (non-critical): {cleanup_error}")

            try:
                ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
            except Exception as remove_error:
                logger().warning(f"Remove device error (non-critical): {remove_error}")

        try:
            ble_client.interfaces.bluetooth.close()
        except Exception as close_error:
            logger().warning(f"Close error (non-critical): {close_error}")