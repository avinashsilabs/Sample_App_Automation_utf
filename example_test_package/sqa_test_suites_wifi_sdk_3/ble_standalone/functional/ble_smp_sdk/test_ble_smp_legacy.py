import re
import pytest
import time
from utf.interfaces.bluetooth.nrf_blatann import (
    NRFBLEIoCapabilities, NRFBLEPeerDevAddrTypes
)
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
    def __init__(self, wifi_dut=None, nrf_ble_client=None, ble_client=None, ble_sniffer=None, error_code_expected=None, check_error=True, sniffer_check=False, layer_name=None,
                 capture_filename=None, smp_io_capability=None, encrypted_file=False, smp_auth_bond=1, smp_mtim=1, smp_enc_key=1, passkey_state=None, smp_sc=1, cap_on_dongle=None, delay=0, nrf_connect_to_dut=False,
                 ble_connect_from_raspi=False, pair_connect_from_dut=False, pin_code=None, client_capability=None, dut_capability=None, capability_on_remote=None, mtim_disabled=False, lesc_disabled=False,
                 reconnection_from_remote=False, powersave=True, random_addr_on_dut=False, local_oob_flag=False, nrf_dongle_as_master=False, testcase_no=None, link_key=True, gatt_init=False):
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
        self.link_key  = link_key
        self.gatt_init = gatt_init


    def run(self):
        if self.sniffer_check or self.encrypted_file:
            self.ble_sniffer.interfaces.sniffer.init_sniffer()
            self.ble_sniffer.interfaces.sniffer.start_capture(capture_file=self.capture_filename)
        logger().info("Initiate ble service in DUT")
        logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability}")
        if self.gatt_init:
            ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1)
            assert ble_dut_address, "failed to initiate ble in dut"
        else:
            ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(capability=self.smp_io_capability)
        if self.smp_io_capability == 0x00:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> DisplayOnly")
        elif self.smp_io_capability == 0x01:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> Display yes or no")
        else:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> No input No output")
        assert ble_dut_address, "failed to initiate ble in dut"
        if self.random_addr_on_dut:
            ble_dut_address = "11:33:33:33:33:11"
            self.wifi_dut.interfaces.wifi.set_ble_address(ble_address=ble_dut_address)
        if self.nrf_connect_to_dut:
            logger().info(f"********setting sc bit : {self.smp_sc}, authencation bonding : {self.smp_auth_bond}, mtim bit on dut : {self.smp_mtim}")

            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability}")
            self.wifi_dut.interfaces.wifi.ble_set_cap_data(remote_addr_type=1, smp_io_cap=self.smp_io_capability, smp_auth_req_bonding= self.smp_auth_bond, smp_auth_req_mitm=self.smp_mtim,
                                                      smp_auth_req_sc=self.smp_sc, smp_max_enc_key_size=16,
                                                      smp_local_oob_data_flag_not_present=0, smp_enc_key=self.smp_enc_key, smp_id_key=0,
                                                      smp_sign_key=0)
            logger().info(f"Entered the device passkey state")
            self.wifi_dut.interfaces.wifi.ble_modify_passkey_event(passkey_state=self.passkey_state, delay=self.delay)
            logger().info(f"Setting IO capability on nrf dongle: {self.cap_on_dongle}")
            logger().info(f"preparing nRF dongle for secure connection")
            if self.mtim_disabled:
                logger().info(f"Capability on dongle: {self.cap_on_dongle}")
                self.nrf_ble_client.interfaces.bluetooth.set_security_params(passcode_pairing=False,
                                                                        io_capabilities=self.cap_on_dongle,
                                                                        long_term_bonding=True, lesc_pairing=True)
            elif self.lesc_disabled:
                if self.cap_on_dongle == 0:
                     logger().info(f"Capability on dongle: {self.cap_on_dongle} --> DisplayOnly")
                elif self.cap_on_dongle == 1:
                    logger().info(f"Capability on dongle: {self.cap_on_dongle} --> Display yes or no")
                else:
                    logger().info(f"Capability on dongle: {self.cap_on_dongle} --> No input No output")
                logger().info(f"Disabling the lesc_paring")
                self.nrf_ble_client.interfaces.bluetooth.set_security_params(passcode_pairing=True,
                                                                        io_capabilities=self.cap_on_dongle,
                                                                        long_term_bonding=True, lesc_pairing=False)
            else:
                logger().info(f"Capability on dongle: {self.cap_on_dongle}")
                self.nrf_ble_client.interfaces.bluetooth.set_security_params(passcode_pairing=True,
                                                                        io_capabilities=self.cap_on_dongle,
                                                                        long_term_bonding=True, lesc_pairing=True)
            logger().info(f"****registering events on nrf dongle**************")
            self.nrf_ble_client.interfaces.bluetooth.register_on_connect()
            self.nrf_ble_client.interfaces.bluetooth.register_on_disconnect()
            self.nrf_ble_client.interfaces.bluetooth.register_on_security_level_changed()
            self.nrf_ble_client.interfaces.bluetooth.register_on_client_pairing_complete()
            if self.testcase_no == 557287 or 557289 or 557290:
                self.nrf_ble_client.interfaces.bluetooth.register_passkey_display(confirm=False)
            elif self.testcase_no == 557291:
                  pass
            else:
               self.nrf_ble_client.interfaces.bluetooth.register_passkey_display()
            logger().info(f"Start Advertising on nrf dongle")
            ble_client_address = self.nrf_ble_client.interfaces.bluetooth.start_advertising(local_name="slave11",
                                                                                       timeout_sec=0, auto_restart=False
                                                                                       )
            time.sleep(3)
            if self.random_addr_on_dut:
                logger().info(f"Start scanning and connect to ble client")
                self.wifi_dut.interfaces.wifi.ble_start_scanning(
                    ble_client_address=ble_client_address, ble_address_type=1, timeout=30
                )
            else:
                logger().info(f"Start scanning and connect to ble client")
                self.wifi_dut.interfaces.wifi.ble_start_scanning(
                    ble_client_address=ble_client_address, timeout=30
                )
            timeout = 120
            time.sleep(5)
            if self.powersave:
                logger().info("enabling the power save modes ")
                self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                   psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            logger().info(f"Stopping scanning on dut")
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
                    # disconnecting from dut
        if self.nrf_dongle_as_master:
            logger().info(f"Setting the sc bit as {self.smp_sc}, authencation bond as {self.smp_auth_bond}, mtim bit as {self.smp_mtim}")
            self.wifi_dut.interfaces.wifi.ble_set_cap_data(remote_addr_type=1, smp_io_cap=self.smp_io_capability,
                                                           smp_auth_req_bonding=self.smp_auth_bond,
                                                           smp_auth_req_mitm=self.smp_mtim,
                                                           smp_auth_req_sc=self.smp_sc, smp_max_enc_key_size=16,
                                                           smp_local_oob_data_flag_not_present=0,
                                                           smp_enc_key=1, smp_id_key=0,
                                                           smp_sign_key=0)
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
            if self.cap_on_dongle == 0:
                logger().info(f"Capability on dongle: {self.cap_on_dongle} --> DisplayOnly")
            elif self.cap_on_dongle == 1:
                logger().info(f"Capability on dongle: {self.cap_on_dongle} --> Display yes or no")
            else:
                logger().info(f"Capability on dongle: {self.cap_on_dongle} --> No input No output")
            if self.lesc_disabled:
                logger().info(f"Disabling the lesc_paring")
                self.nrf_ble_client.interfaces.bluetooth.set_security_params(passcode_pairing=True,
                                                                             io_capabilities=self.cap_on_dongle,
                                                                             long_term_bonding=True, lesc_pairing=False)
            else:
                self.nrf_ble_client.interfaces.bluetooth.set_security_params(passcode_pairing=True,
                                                                             io_capabilities=self.cap_on_dongle,
                                                                             long_term_bonding=True, lesc_pairing=True)
            logger().info(f"******registering events on dongle")
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
            assert str(ble_dut_address) in found_devices
            self.nrf_ble_client.interfaces.bluetooth.stop_scanning()
            self.nrf_ble_client.interfaces.bluetooth.set_connection_parameters(100, 120, 6000)
            connection_status = False
            logger().info("\n\n======= start nRF dongle ========")
            ble_client_address = self.nrf_ble_client.interfaces.bluetooth.get_ble_address()
            assert ble_client_address is not None
            if self.random_addr_on_dut:
                self.nrf_ble_client.interfaces.bluetooth.connect(ble_dut_address, 30,
                                                                 NRFBLEPeerDevAddrTypes.RANDOM_PRIVATE_NON_RESOLVABLE)
                time.sleep(2)
            else:
                logger().info(f"**********Initiating connection from dongle****************")
                self.nrf_ble_client.interfaces.bluetooth.connect(ble_dut_address)
            time.sleep(2)
            connection_status = self.nrf_ble_client.interfaces.bluetooth.get_peer_connection_status(ble_dut_address)
            logger().info(f"\n\nConnection status: {connection_status}")
            assert connection_status
            self.nrf_ble_client.interfaces.bluetooth.set_peer_security_params(ble_dut_address, passcode_pairing=True,
                                                                              io_capabilities=self.cap_on_dongle,
                                                                              lesc_pairing=False,
                                                                              long_term_bonding=True)
            self.nrf_ble_client.interfaces.bluetooth.pair(ble_dut_address)
            security_level = self.nrf_ble_client.interfaces.bluetooth.get_peer_connection_security_status(
                ble_dut_address)
            assert security_level.value == 2
        if self.ble_connect_from_raspi:
            if self.random_addr_on_dut:
                  logger().info("Set DUT in advertise mode with random")
                  self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_addr_type=1)
            else:
                logger().info("Set DUT in advertise mode")
                self.wifi_dut.interfaces.wifi.ble_start_advertising()
            logger().info("Start smp scan from the remote device")
            logger().info(f"Capability on remote: {self.capability_on_remote}")
            ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address, capability=self.capability_on_remote)
            assert ble_client_address, "failed to initiate ble in remote device"

            time.sleep(5)
            logger().info("stop scanning ....")
            self.ble_client.interfaces.bluetooth.stop_scanning()

            logger().info("Check the dut is listed...")
            self.ble_client.interfaces.bluetooth.get_devices()

            logger().info("Connect to the dut with mac address..")
            connect_time = datetime.datetime.now()
            self.ble_client.interfaces.bluetooth.pair_and_connect(ble_dut_address)
            logger().info(f"connect_time:  {connect_time}")
            time.sleep(60)
            logger().info("Connection successfully stable for 60sec")
            self.wifi_dut.interfaces.wifi.ble_advertising = False
            logger().info("Checking connection status of BLE")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            if (state_int > 0):
                logger().info("Disconnecting the bt host....")
                self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
        time.sleep(180)
        logger().info(f"************Checking stability after 3mins****************")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        if state_int == 8:
            logger().info(f"*********Disconnecting from dut ****************")
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
            time.sleep(10)
        # self.sniffer_file_export()
        if self.sniffer_check:
            self.ble_sniffer.interfaces.sniffer.stop_capture()
            captured_files = str(self.ble_sniffer.interfaces.sniffer.local_capture_files).split(';')

            time.sleep(30)
            logger().info(f"***************************************")
            if self.link_key:
             exported_csv_file = self.ble_sniffer.interfaces.sniffer.export_to_csv("LE", self.layer_name)
            for captured_file in captured_files:
                captured_file = captured_file.replace("/tmp/reports", "/app/reports")
                file_size = os.path.getsize(captured_file)
                assert file_size > 0
            if self.link_key:
                sniffer_data_df = self.ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
                assert sniffer_data_df is not None







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
def test_ble_smp_anthencation_legacy_pairing_using_public_C664496(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with DUT & DisplayOnly on dongle as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664496", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing__using_public_C664497(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with DUT & DisplayOnly on dongle as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664497", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_public_C664499(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output with DUT & DisplayOnly on dongle as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,  passkey_state=0,sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664499", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_public_C664501(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with DUT & Display yes or no on dongle as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,  passkey_state=0,sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664501", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_public_C664572(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap On both dut & dongle as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,  passkey_state=0, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664572", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_public_C664574(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input no output & Display Yes/No IOCap on nrf dongle as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, passkey_state=0, layer_name="SMP", capture_filename="frontline_capture_C664574", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_public_C664581(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Only with DUT as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,  passkey_state=0, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664581", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_public_C664582(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap with DUT as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer,  passkey_state=0, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664582", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_public_C664584(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap with DUT as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer,  passkey_state=0,check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664584", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664661(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with DUT & DisplayOnly on dongle as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer,  passkey_state=0, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664661", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664662(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with DUT & DisplayOnly on dongle as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, passkey_state=0, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664662", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True,gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664664(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output with DUT & DisplayOnly on dongle as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, passkey_state=0,  check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664664", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664666(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with DUT & Display yes or no on dongle as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, passkey_state=0,check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664666", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664667(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap On dut & dongle as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, passkey_state=0,check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664667", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)



@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664669(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input no output & Display Yes/No IOCap on nrf dongle as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, passkey_state=0,check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664669", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664676(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Only with DUT as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, passkey_state=0,check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664669", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664677(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap with DUT as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, passkey_state=0,check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664677", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664679(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap with DUT as Central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, passkey_state=0,check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664679", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664290(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with DUT & DisplayOnly on dongle, dut as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer,check_error=False, passkey_state=0, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664290", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664291(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with dongle & DisplayOnly on dut, dut as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664291", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664293(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output with dongle & DisplayOnly on dut, dut as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0,  sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664293", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664295(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with dongle & Display yes or no , dut as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664295", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664296(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap On dongle & dongle, dut as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664296", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664298(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input no output on dongle & Display Yes/No IOCap on dut, dut as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664298", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664305(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Only on dongle & no input no output on  DUT as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0,  sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664305", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664306(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap on dongle, dut as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0,  sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664306", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664308(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output on both side , dut as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664308", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_dut_as_slave_using_random_C664315(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with DUT & DisplayOnly on dongle, dut as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer,check_error=False, passkey_state=0, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664315", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_random_C664316(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with dongle & DisplayOnly on dut, dut as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664316", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_random_C664318(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output with dongle & DisplayOnly on dut, dut as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0,  sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664318", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_random_C664320(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with dongle & Display yes or no , dut as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664320", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_random_C664321(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap On dongle & dongle, dut as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664321", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_random_C664323(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input no output on dongle & Display Yes/No IOCap on dut, dut as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664323", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_random_C664330(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Only on dongle & no input no output on  DUT as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0,  sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664330", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_random_C664331(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output on dut side & display yes or no on remote , dut as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664331", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_random_C664333(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as slave """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C664333", smp_sc=0, smp_mtim=1, smp_io_capability=3, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True,  lesc_disabled=True, link_key=False, gatt_init=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

