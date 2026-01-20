from utf.utils.logger import get_logger
import time
import pytest
from utf.utils.stopwatch import Stopwatch
import threading
import re
import os
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.thread_base import ThreadBase
from utf.utils import mac_address_to_string, mac_address_to_dbus_bt_path


def logger():
    return get_logger(__name__)


class BLEFunc(ThreadBase):
    def __init__(self, wifi_dut=None, nrf_ble_client=None, ble_client=None, ble_sniffer=None, error_code_expected=None,
                 check_error=True, sniffer_check=False, layer_name=None,
                 capture_filename=None, smp_io_capability=None, encrypted_file=False, smp_auth_bond=1, smp_mtim=1,
                 smp_enc_key=1, passkey_state=None, smp_sc=1, cap_on_dongle=None, delay=0, nrf_connect_to_dut=False,
                 ble_connect_from_raspi=False, pair_connect_from_dut=False, pin_code=None, client_capability=None,
                 dut_capability=None, capability_on_remote=None, mtim_disabled=False, lesc_disabled=False,
                 reconnection_from_remote=False, powersave=True, random_addr_on_dut=False, local_oob_flag=False,
                 nrf_dongle_as_master=False, testcase_no=None, passkey_entry=False, dynamic_passkey=False,
                 auth_req=None, passkey_entry_on_dut_ref=False, confirmation_passkey=False):
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
        self.auth_req = auth_req
        self.passkey_entry_on_dut_ref = passkey_entry_on_dut_ref
        self.confirmation_passkey = confirmation_passkey

    def run(self):
        io_capability = {"DisplayOnly": 0x00, "DisplayYesNo": 0x01, "KeyboardOnly": 0x02, "NoInputNoOutput": 0x03,
                         "KeyboardDisplay": 0x04}
        if self.sniffer_check or self.encrypted_file:
            self.ble_sniffer.interfaces.sniffer.init_sniffer()
            logger().info("sniffer capture started")
            self.ble_sniffer.interfaces.sniffer.start_capture(capture_file=self.capture_filename)
        logger().info("Initiate ble service in DUT")
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
                                                           smp_enc_key=self.smp_enc_key, smp_id_key=0,
                                                           smp_sign_key=0)
        else:
            self.wifi_dut.interfaces.wifi.ble_set_cap_data(remote_addr_type=0, smp_io_cap=self.smp_io_capability,
                                                           smp_auth_req_bonding=self.smp_auth_bond,
                                                           smp_auth_req_mitm=self.smp_mtim,
                                                           smp_auth_req_sc=self.smp_sc, smp_max_enc_key_size=16,
                                                           smp_local_oob_data_flag_not_present=0,
                                                           smp_enc_key=self.smp_enc_key, smp_id_key=0,
                                                           smp_sign_key=0)
        self.wifi_dut.interfaces.wifi.ble_modify_passkey_event(passkey_state=self.passkey_state)
        if self.random_addr_on_dut:
            logger().info("\n\n======= start ble adv in dut with random addr========")
            self.wifi_dut.interfaces.wifi.ble_start_advertising(own_addr_type=1, ble_addr_type=1)
        else:
            self.wifi_dut.interfaces.wifi.ble_start_advertising()
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                           psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        logger().info("Set MITM and security requirements in BLE client")
        logger().info(f"{io_capability[self.client_capability]} 0x00 {self.auth_req} ")
        self.ble_client.interfaces.bluetooth.set_mitm_sc_bits(
            f"{io_capability[self.client_capability]} 0x00 {self.auth_req} ")
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
        if self.passkey_entry_on_dut_ref:
            self.ble_client.interfaces.bluetooth.connect(dev_addr=self.ble_dut_address)
            self.ble_client.interfaces.bluetooth.set_pin(pin_code="123456")
            logger().info("Passkey has set successfully in client")
            self.wifi_dut.interfaces.wifi.ble_set_smp_passkey(remote_dev_addr=self.ble_client_address,
                                                              smp_passkey="123456")
            logger().info("passkey has set successfully in DUT")

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
            time.sleep(10)
            logger().info("checking the connection state...")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            time.sleep(180)
        elif self.confirmation_passkey:
            self.ble_client.interfaces.bluetooth.connect(dev_addr=self.ble_dut_address)
            device_path = mac_address_to_dbus_bt_path(
                self.ble_client.interfaces.bluetooth.adapter_path, mac_address=self.ble_dut_address
            )
            def pair_reply():
                pass

            def pair_error(error):
                pass
            def pair():
                self.ble_client.interfaces.bluetooth._dev_manager.pair(
                    bus=self.ble_client.interfaces.bluetooth.bus,
                    device_path=device_path,
                    reply_handler=pair_reply,
                    error_handler=pair_error,
                    timeout=60 * 1000,
                )

            t = threading.Thread(target=pair)
            t.start()
            time.sleep(10)
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            time.sleep(180)
        else:
            def connect():
                logger().info("Connect to the dut with mac address..")
                self.ble_client.interfaces.bluetooth.pair_and_connect(self.ble_dut_address)

            t = threading.Thread(target=connect)
            t.start()
            tw = Stopwatch()
            time.sleep(20)
            passkey = self.ble_client.interfaces.bluetooth.get_passkey()
            logger().info(f"passkey : {passkey}")
            logger().info(f"type of passkey : {type(passkey)}")
            logger().info(f"**********{passkey}")
            self.wifi_dut.interfaces.wifi.ble_set_smp_passkey(remote_dev_addr=self.ble_client_address, smp_passkey=passkey)
            time.sleep(180)

        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
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
                                       # Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
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
def test_ble_smp_passkey_entry_pairing_Initiator_display_only_responder_keyboard_only_C663314(wifi_dut, ble_client,
                                                                                              pin_code,
                                                                                              client_capability,
                                                                                              dut_capability,
                                                                                              ble_sniffer,
                                                                                              sl_collections):
    """ Verify PasskeyEntry Pairing method for IOCap,Initiator(remote device) : DisplayOnly and
    Responder(DUT) : KeyboardOnly."""
    try:

        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C663314",
                          dut_capability=dut_capability, smp_io_capability=2, smp_sc=1, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x05")
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[
                       (ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (
                               ble_obj.sniffer_data_df_2["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df_2[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                       "Secure Connection Pairing"] == "Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
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
def test_ble_smp_passkey_entry_pairing_Initiator_display_yesno_responder_keyboard_only_C663315(wifi_dut, ble_client,
                                                                                               pin_code,
                                                                                               client_capability,
                                                                                               dut_capability,
                                                                                               ble_sniffer,
                                                                                               sl_collections):
    """ Verify PasskeyEntry Pairing method for IOCap, Initiator: DisplayYesNo and Responder: KeyboardOnly."""
    try:

        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C663315",
                          dut_capability=dut_capability, smp_io_capability=2, smp_sc=1, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x05")
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[
                       (ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (
                               ble_obj.sniffer_data_df_2["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df_2[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                       "Secure Connection Pairing"] == "Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
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
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_display_responder_keyboard_only_C663318(wifi_dut, ble_client,
                                                                                                  pin_code,
                                                                                                  client_capability,
                                                                                                  dut_capability,
                                                                                                  ble_sniffer,
                                                                                                  sl_collections):
    """Verify JustWorks Pairing method for IOCap, Initiator: KeyboardDisplay , Responder: KeyboardOnly"""
    try:

        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C663318",
                          dut_capability=dut_capability, smp_io_capability=2, smp_sc=1, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x05")
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[
                       (ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (
                               ble_obj.sniffer_data_df_2["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df_2[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                       "Secure Connection Pairing"] == "Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
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
def test_ble_smp_passkey_entry_pairing_Initiator_display_only_responder_keyboard_display_C663324(wifi_dut, ble_client,
                                                                                                 pin_code,
                                                                                                 client_capability,
                                                                                                 dut_capability,
                                                                                                 ble_sniffer,
                                                                                                 sl_collections):
    """ Verify PasskeyEntry Pairing method for IOCap, Initiator: DisplayOnly , Responder: KeyboardDisplay"""
    try:

        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C663324",
                          dut_capability=dut_capability, smp_io_capability=4, smp_sc=1, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x05")
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[
                       (ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (
                               ble_obj.sniffer_data_df_2["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df_2[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                          "Secure Connection Pairing"] == "Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
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
def test_ble_smp_passkey_entry_pairing_Initiator_display_only_responder_keyboard_only_C663339(wifi_dut, ble_client,
                                                                                              pin_code,
                                                                                              client_capability,
                                                                                              dut_capability,
                                                                                              ble_sniffer,
                                                                                              sl_collections):
    """ Verify PasskeyEntry Pairing method for IOCap,Initiator : DisplayOnly and Responder : KeyboardOnly."""
    try:

        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C663339",
                          dut_capability=dut_capability, smp_io_capability=2, smp_sc=1, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x05",
                          random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[
                       (ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (
                               ble_obj.sniffer_data_df_2["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df_2[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                       "Secure Connection Pairing"] == "Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
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
def test_ble_smp_passkey_entry_pairing_Initiator_display_yesno_responder_keyboard_only_C663340(wifi_dut, ble_client,
                                                                                               pin_code,
                                                                                               client_capability,
                                                                                               dut_capability,
                                                                                               ble_sniffer,
                                                                                               sl_collections):
    """ Verify PasskeyEntry Pairing method for IOCap, Initiator: DisplayYesnO and Responder: KeyboardOnly."""
    try:

        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C663340",
                          dut_capability=dut_capability, smp_io_capability=2, smp_sc=1, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x05",
                          random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[
                       (ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (
                               ble_obj.sniffer_data_df_2["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df_2[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                       "Secure Connection Pairing"] == "Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
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
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_display_responder_keyboard_only_C663343(wifi_dut, ble_client,
                                                                                                  pin_code,
                                                                                                  client_capability,
                                                                                                  dut_capability,
                                                                                                  ble_sniffer,
                                                                                                  sl_collections):
    """ Verify JustWorks Pairing method for IOCap, Initiator: KeyboardDisplay , Responder: KeyboardOnly."""
    try:

        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C663343",
                          dut_capability=dut_capability, smp_io_capability=2, smp_sc=1, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x05",
                          random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[
                       (ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (
                               ble_obj.sniffer_data_df_2["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df_2[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                       "Secure Connection Pairing"] == "Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
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
def test_ble_smp_passkey_entry_pairing_Initiator_display_only_responder_keyboard_display_C663349(wifi_dut, ble_client,
                                                                                                 pin_code,
                                                                                                 client_capability,
                                                                                                 dut_capability,
                                                                                                 ble_sniffer,
                                                                                                 sl_collections):
    """ Verify PasskeyEntry Pairing method for IOCap, Initiator: DisplayOnly , Responder: KeyboardDisplay."""
    try:

        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C663349",
                          dut_capability=dut_capability, smp_io_capability=4, smp_sc=1, passkey_state=2,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x05",
                          random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[
                       (ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (
                               ble_obj.sniffer_data_df_2["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df_2[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                          "Secure Connection Pairing"] == "Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing Confirm")]) == 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
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
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_only_responder_keyboard_only_C663316(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    """ Verify PasskeyEntry Pairing method for IOCap, Initiator : KeyBoardOnly , Responder : KeyboardOnly."""
    try:

        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C663316",
                          dut_capability=dut_capability, smp_io_capability=2, smp_sc=1, passkey_state=0,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x05", passkey_entry_on_dut_ref=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[
                       (ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (
                               ble_obj.sniffer_data_df_2["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df_2[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                       "Secure Connection Pairing"] == "Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing Confirm")]) >= 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
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
def test_ble_smp_passkey_entry_pairing_Initiator_keyboard_only_responder_keyboard_only_C663341(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    """ Verify PasskeyEntry Pairing method for IOCap, Initiator : KeyBoardOnly , Responder : KeyboardOnly."""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C663341",
                          dut_capability=dut_capability, smp_io_capability=2, smp_sc=1, passkey_state=0,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x05",
                          passkey_entry_on_dut_ref=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[
                       (ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (
                               ble_obj.sniffer_data_df_2["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df_2[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                       "Secure Connection Pairing"] == "Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing Confirm")]) >= 40, "unable to find Pairing Confirm"
        logger().info("Pairing Confirm has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (4, "DisplayYesNo", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_NumericComparision_pairing_Initiator_display_yesno_responder_keyboard_display_C663325(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    try:

        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C663325",
                          dut_capability=dut_capability, smp_io_capability=4, smp_sc=1, passkey_state=0,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01", confirmation_passkey=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[
                       (ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (
                               ble_obj.sniffer_data_df_2["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df_2[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                       "Secure Connection Pairing"] == "Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (4, "KeyboardDisplay", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_NumericComparision_pairing_Initiator_keyboard_display_responder_keyboard_display_C663328(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C663328",
                          dut_capability=dut_capability, smp_io_capability=4, smp_sc=1, passkey_state=0,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01",
                          confirmation_passkey=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[
                       (ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (
                               ble_obj.sniffer_data_df_2["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df_2[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                       "Secure Connection Pairing"] == "Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (4, "DisplayYesNo", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_NumericComparision_pairing_Initiator_display_yes_no_responder_keyboard_display_C663350(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C663350",
                          dut_capability=dut_capability, smp_io_capability=4, smp_sc=1, passkey_state=0,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01",
                          confirmation_passkey=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[
                       (ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (
                               ble_obj.sniffer_data_df_2["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df_2[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                       "Secure Connection Pairing"] == "Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (4, "KeyboardDisplay", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_NumericComparision_pairing_Initiator_keyboard_display_responder_keyboard_display_C663353(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C663353",
                          dut_capability=dut_capability, smp_io_capability=4, smp_sc=1, passkey_state=0,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01",
                          confirmation_passkey=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[
                       (ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (
                               ble_obj.sniffer_data_df_2["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df_2[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                       "Secure Connection Pairing"] == "Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (1, "DisplayYesNo", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_numeric_comparision_pairing_method_DUT_as_peripheral_random_address_C557268(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    """Verify numeric comparision pairing method for DUT as peripheral with random address"""
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, check_error=False, ble_sniffer=ble_sniffer,
                          sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C557268",
                          dut_capability=dut_capability, smp_io_capability=1, smp_sc=1, passkey_state=0,
                          pin_code=pin_code, client_capability=client_capability, auth_req="0x01",
                          confirmation_passkey=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Checking for sniffer data")
        assert len(ble_obj.sniffer_data_df_1.loc[
                       (ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_REQ")]), "unable to find encryption request"
        assert len(ble_obj.sniffer_data_df_1.loc[(
                ble_obj.sniffer_data_df_1['Control Pkt'] == "LL_ENC_RSP")]), "unable to find encryption response"
        assert len(ble_obj.sniffer_data_df_2.loc[
                       (ble_obj.sniffer_data_df_2['Code'] == "Pairing Request") & (
                               ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (
                               ble_obj.sniffer_data_df_2["Secure Connection Pairing"] == "Yes") & (
                               ble_obj.sniffer_data_df_2[
                                   'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
        logger().info("Pairing request has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       "Secure Connection Pairing"] == "Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
        logger().info("Pairing response has observed in sniffer")
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2[
                                                      'Code'] == "Pairing DHKey Check")]) == 2, "unable to find Pairing DHKey Check"
        logger().info("Pairing DHKey Check has observed in sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=ble_obj.ble_dut_address)
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardDisplay", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_timeout_C165699(
        wifi_dut, ble_client, pin_code, client_capability, dut_capability, ble_sniffer, sl_collections):
    """ Verify ble SMP timeout if the the remote device doesn't confirm the pairing popup within a couple of seconds."""
    layer_name = ["LE LL", "SMP"]
    ble_sniffer.interfaces.sniffer.init_sniffer()
    logger().info("sniffer capture started")
    ble_sniffer.interfaces.sniffer.start_capture(capture_file="frontline_capture_C165699")
    logger().info("Initiate ble service in DUT")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=0, set_smp=0)
    assert ble_dut_address, "failed to initiate ble in dut"
    wifi_dut.interfaces.wifi.ble_set_cap_data(remote_addr_type=0, smp_io_cap=0,
                                                   smp_auth_req_bonding=1,
                                                   smp_auth_req_mitm=1,
                                                   smp_auth_req_sc=1, smp_max_enc_key_size=16,
                                                   smp_local_oob_data_flag_not_present=0,
                                                   smp_enc_key=1, smp_id_key=0,
                                                   smp_sign_key=0)
    wifi_dut.interfaces.wifi.ble_modify_passkey_event(passkey_state=0)
    wifi_dut.interfaces.wifi.ble_start_advertising()
    wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
    wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                       psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
    logger().info("Set MITM and security requirements in BLE client 0x04 0x00 0x01")
    ble_client.interfaces.bluetooth.set_mitm_sc_bits("0x04 0x00 0x01")
    logger().info("Start smp scan from the remote device")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=ble_dut_address,
        capability="KeyboardDisplay",
        pin_code="-8")
    assert ble_client_address, "failed to initiate ble in remote device"
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()
    logger().info("Check the dut is listed...")
    ble_client.interfaces.bluetooth.get_devices()
    def connect():
        logger().info("Connect to the dut with mac address..")
        ble_client.interfaces.bluetooth.pair_and_connect(ble_dut_address)

    t = threading.Thread(target=connect)
    t.start()
    tw = Stopwatch()
    time.sleep(20)
    tw = Stopwatch()
    pass_key_found = False
    while tw.elapsed_sec < 120:
        events = wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if "passkey" in event.event_data:
                passkey = re.findall(r"passkey: ([\d]*)", event.event_data)
                if passkey[0] is not None:
                    pass_key_value = str(passkey[0])
                    logger().info(f"passkey : {pass_key_value}")
                    time.sleep(20)
                    state = wifi_dut.interfaces.wifi.ble_get_device_state()
                    state_int = int(state) if state.isdigit() else -1
                    logger().info(f"********{state_int}*********")
                    pass_key_found = True
                    break
            time.sleep(1)
        if pass_key_found:
            break
    time.sleep(180)
    ble_dut_address_hex = re.split(":", ble_dut_address)
    ble_client_address_hex = re.split(":", ble_client_address)
    master_address = "0x"
    for hex_data_part in ble_dut_address_hex:
        master_address = master_address + hex_data_part
    slave_address = "0x"
    for hex_data_part in ble_client_address_hex:
        slave_address = slave_address + hex_data_part
    logger().info("selecting bt devices for sniffer capture")
    ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])
    time.sleep(30)
    logger().info("Waiting for sniffer capture to complete...")
    ble_sniffer.interfaces.sniffer.stop_capture()
    captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
    logger().info(f"captured_files : {captured_files}")
    time.sleep(30)
    for layer in layer_name:
        logger().info(f"layer : {layer_name}")
        logger().info(f"Exporting layer : {layer}")
        layer_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", layer)
        logger().info(f"layer_file : {layer_file}")
        layer_file = layer_file.replace("/tmp/reports", "/app/reports")
        logger().info(f"layer_file after replace : {layer_file}")
        file_size = os.path.getsize(layer_file)
        logger().info(f"file_size : {file_size}, layer_file : {layer_file}")
        assert file_size > 0
        if layer == "LE LL":
            sniffer_data_df_1 = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(
                layer_file)
            logger().info(f"sniffer_data_df_1 : {sniffer_data_df_1}")
            assert sniffer_data_df_1 is not None
        else:
            sniffer_data_df_2 = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(
                layer_file)
            logger().info(f"sniffer_data_df_2 : {sniffer_data_df_2}")
            assert sniffer_data_df_2 is not None
    logger().info("Checking for sniffer data")
    assert len(sniffer_data_df_1.loc[
                   (sniffer_data_df_1['Control Pkt'] == "LL_TERMINATE_IND")]), "unable to get the terminate indication"
    assert len(sniffer_data_df_2.loc[
                   (sniffer_data_df_2['Code'] == "Pairing Request") & (
                           sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (
                           sniffer_data_df_2["Secure Connection Pairing"] == "Yes") & (
                           sniffer_data_df_2[
                               'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing request"
    logger().info("Pairing request has observed in sniffer")
    assert len(sniffer_data_df_2.loc[(sniffer_data_df_2['Code'] == "Pairing Response") & (
            sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (sniffer_data_df_2[
                                                                                   "Secure Connection Pairing"] == "Yes") & (
                                                     sniffer_data_df_2[
                                                         'MITM'] == "MITM Protection:  Yes")]), "unable to find Pairing response"
    logger().info("Pairing response has observed in sniffer")