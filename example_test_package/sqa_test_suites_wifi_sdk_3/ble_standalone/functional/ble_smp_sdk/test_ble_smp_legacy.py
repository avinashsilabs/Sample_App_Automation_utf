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
                 reconnection_from_remote=False, powersave=True, random_addr_on_dut=False, local_oob_flag=False, nrf_dongle_as_master=False, testcase_no=None, link_key=True, gatt_init=False, passkey_entry=None, ble_dut_address=None, ble_client_address=None):
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
        self.passkey_entry = passkey_entry
        self.ble_client_address = ble_client_address
        self.ble_dut_address = ble_dut_address


    def run(self):
        if self.sniffer_check or self.encrypted_file:
            self.ble_sniffer.interfaces.sniffer.init_sniffer()
            self.ble_sniffer.interfaces.sniffer.start_capture(capture_file=self.capture_filename)
        logger().info("Initiate ble service in DUT")
        logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability}")
        if self.gatt_init:
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1, bond_info=0)
            assert self.ble_dut_address, "failed to initiate ble in dut"
        else:
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=1, capability=self.smp_io_capability)
        if self.smp_io_capability == 0x00:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> DisplayOnly")
        elif self.smp_io_capability == 0x01:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> Display yes or no")
        elif self.smp_io_capability == 0x02:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> keyboard Only")
        elif self.smp_io_capability == 0x04:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> keyboard display")
        else:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> No input No output")
        assert self.ble_dut_address, "failed to initiate ble in dut"
        if self.random_addr_on_dut:
            self.ble_dut_address = "11:33:33:33:33:11"
            self.wifi_dut.interfaces.wifi.set_ble_address(ble_address=self.ble_dut_address)
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
                elif self.cap_on_dongle == 2:
                    logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> keyboard Only")
                elif self.cap_on_dongle == 4:
                    logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> keyboard display")
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
            self.ble_client_address = self.nrf_ble_client.interfaces.bluetooth.start_advertising(local_name="slave11",
                                                                                       timeout_sec=0, auto_restart=False
                                                                                       )
            time.sleep(3)
            if self.testcase_no  == 664576 :
                self.nrf_ble_client.interfaces.bluetooth.register_dynamic_passkey_entry()
                time.sleep(3)
            if self.random_addr_on_dut:
                logger().info(f"Start scanning and connect to ble client")
                self.wifi_dut.interfaces.wifi.ble_start_scanning(
                    ble_client_address=self.ble_client_address, ble_address_type=1, timeout=30
                )
            else:
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
            logger().info(f"Stopping scanning on dut")
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
                for retry_count in range(0, 3):
                    try:
                        self.wifi_dut.interfaces.wifi.ble_connect(
                            ble_remote_dev_address=self.ble_client_address, timeout=timeout,
                            expected="RSI_BLE_ENCRYPT_STARTED_EVENT"
                        )
                        time.sleep(3)
                        break
                    except Exception as err:
                        logger().warning(f"Connection Failed...RETRY COUNT IS {retry_count + 1}\nWarning:{err}")
                        time.sleep(15)

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
                logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> DisplayOnly")
            elif self.cap_on_dongle == 1:
                logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> Display yes or no")
            elif self.cap_on_dongle == 2:
                logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> keyboard Only")
            elif self.cap_on_dongle == 4:
                logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> keyboard display")
            else:
                logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> No input No output")
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
            assert str(self.ble_dut_address) in found_devices
            self.nrf_ble_client.interfaces.bluetooth.stop_scanning()
            self.nrf_ble_client.interfaces.bluetooth.set_connection_parameters(100, 120, 6000)
            connection_status = False
            logger().info("\n\n======= start nRF dongle ========")
            self.ble_client_address = self.nrf_ble_client.interfaces.bluetooth.get_ble_address()
            assert self.ble_client_address is not None
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
                                                                                  lesc_pairing=False,
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
                                                                                  lesc_pairing=False,
                                                                                  long_term_bonding=True)
                self.nrf_ble_client.interfaces.bluetooth.pair(self.ble_dut_address)
                security_level = self.nrf_ble_client.interfaces.bluetooth.get_peer_connection_security_status(
                    self.ble_dut_address)
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
            self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.ble_dut_address, capability=self.capability_on_remote)
            assert self.ble_client_address, "failed to initiate ble in remote device"

            time.sleep(5)
            logger().info("stop scanning ....")
            self.ble_client.interfaces.bluetooth.stop_scanning()

            logger().info("Check the dut is listed...")
            self.ble_client.interfaces.bluetooth.get_devices()

            logger().info("Connect to the dut with mac address..")
            connect_time = datetime.datetime.now()
            self.ble_client.interfaces.bluetooth.pair_and_connect(self.ble_dut_address)
            logger().info(f"connect_time:  {connect_time}")
            time.sleep(60)
            logger().info("Connection successfully stable for 60sec")
            self.wifi_dut.interfaces.wifi.ble_advertising = False
            logger().info("Checking connection status of BLE")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            if (state_int > 0):
                logger().info("Disconnecting the bt host....")
                self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
        time.sleep(180)
        logger().info(f"************Checking stability after 3mins****************")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        if state_int == 8:
            if self.nrf_dongle_as_master:
                self.nrf_ble_client.interfaces.bluetooth.disconnect(dev_addr=self.ble_dut_address, clear_peer=True)
            else:
                logger().info(f"*********Disconnecting from dut ****************")
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
            tw = Stopwatch()
            link_key = ""
            while tw.elapsed_sec < 120:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                for event in events:
                    logger().info(f"************{event.event_data}")
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
                    [slave_address + f" type=random"])
                if link_key != "":
                    self.ble_sniffer.interfaces.sniffer.add_link_key(linkey_key_value.upper(), master_address,
                                                                     slave_address + f" type=random")
            else:
                self.ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address + f" type=random"])
                time.sleep(30)
                if link_key != "":
                    self.ble_sniffer.interfaces.sniffer.add_link_key(linkey_key_value.upper(), master_address,
                                                                     slave_address + f" type=random")

        if self.sniffer_check:
            self.ble_sniffer.interfaces.sniffer.stop_capture()
            captured_files = str(self.ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
            time.sleep(30)
            for layer in self.layer_name:
                layer_file = self.ble_sniffer.interfaces.sniffer.export_to_csv("LE", layer)
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
            return self.sniffer_data_df_1, self.sniffer_data_df_2, self.ble_dut_address, self.ble_client_address







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
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
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
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664290(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with DUT & DisplayOnly on dongle, dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer,check_error=False, passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664290", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                      'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664291(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with dongle & DisplayOnly on dut, dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664291", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                      'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664293(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output with dongle & DisplayOnly on dut, dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0,  sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664293", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                      'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664295(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with dongle & Display yes or no , dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664295", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664296(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap On dongle & dongle, dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664296", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664298(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input no output on dongle & Display Yes/No IOCap on dut, dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664298", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664305(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Only on dongle & no input no output on  DUT as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0,  sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664305", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664306(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap on dongle, dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0,  sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664306", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_public_C664308(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output on both side , dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664308", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_dut_as_slave_using_random_C664315(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with DUT & DisplayOnly on dongle, dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer,check_error=False, passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664315", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True, random_addr_on_dut=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                      'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_random_C664316(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with dongle & DisplayOnly on dut, dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664316", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True, random_addr_on_dut=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                      'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_random_C664318(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output with dongle & DisplayOnly on dut, dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0,  sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664318", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True, random_addr_on_dut=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                      'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_random_C664320(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with dongle & Display yes or no , dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664320", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, random_addr_on_dut=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_random_C664321(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap On dongle & dongle, dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664321", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True, random_addr_on_dut=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()



@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_random_C664323(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input no output on dongle & Display Yes/No IOCap on dut, dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664323", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True, random_addr_on_dut=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_random_C664330(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Only on dongle & no input no output on  DUT as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0,  sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664330", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True, random_addr_on_dut=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_random_C664331(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output on dut side & display yes or no on remote , dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664331", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_dongle_as_master=True, link_key=False, lesc_disabled=True, gatt_init=True, random_addr_on_dut=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_dut_as_slave_using_random_C664333(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664333", smp_sc=0, smp_mtim=1, smp_io_capability=3, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True,  lesc_disabled=True, link_key=False, gatt_init=True, random_addr_on_dut=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_public_C664496(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with DUT & DisplayOnly on dongle as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664496", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                      'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)
    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client, ble_client_address=ble_obj.ble_client_address,
                                ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()



@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing__using_public_C664497(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with DUT & DisplayOnly on dongle as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664497", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                      'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client, ble_client_address=ble_obj.ble_client_address,
                                ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_public_C664499(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output with DUT & DisplayOnly on dongle as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,  passkey_state=0,sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664499", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                      'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client, ble_client_address=ble_obj.ble_client_address,
                                ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_public_C664501(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with DUT & Display yes or no on dongle as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,  passkey_state=0,sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664501", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client, ble_client_address=ble_obj.ble_client_address,
                                ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=[ "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_public_C664572(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap On both dut & dongle as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,  passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664572", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client, ble_client_address=ble_obj.ble_client_address,
                                ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_public_C664574(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input no output & Display Yes/No IOCap on nrf dongle as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, passkey_state=0, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664574", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client, ble_client_address=ble_obj.ble_client_address,
                                ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_public_C664581(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Only with DUT as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False,  passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664581", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client, ble_client_address=ble_obj.ble_client_address,
                                ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_public_C664582(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap with DUT as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer,  passkey_state=0, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664582", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client, ble_client_address=ble_obj.ble_client_address,
                                ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_public_C664584(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap with DUT as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer,  passkey_state=0,check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664584", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client, ble_client_address=ble_obj.ble_client_address,
                                ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664661(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with DUT & DisplayOnly on dongle as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer,  passkey_state=0, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664661", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                      'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client, ble_client_address=ble_obj.ble_client_address,
                                ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664662(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with DUT & DisplayOnly on dongle as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, passkey_state=0, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664662", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True,gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                      'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client, ble_client_address=ble_obj.ble_client_address,
                                ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664664(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output with DUT & DisplayOnly on dongle as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, passkey_state=0,  check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664664", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                      'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client, ble_client_address=ble_obj.ble_client_address,
                                ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664666(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with DUT & Display yes or no on dongle as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, passkey_state=0,check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664666", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client, ble_client_address=ble_obj.ble_client_address,
                                ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664667(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap On dut & dongle as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, passkey_state=0,check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664667", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()



@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664669(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input no output & Display Yes/No IOCap on nrf dongle as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, passkey_state=0,check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664669", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664676(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Only with DUT as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, passkey_state=0,check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664669", smp_sc=0, smp_mtim=1, smp_io_capability=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()



@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664677(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap with DUT as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, passkey_state=0,check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664677", smp_sc=0, smp_mtim=1, smp_io_capability=1, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()



@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=[ "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_anthencation_legacy_pairing_using_random_C664679(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display Yes/No IOCap with DUT as Central """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, passkey_state=0,check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664679", smp_sc=0, smp_mtim=1, smp_io_capability=3, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True, random_addr_on_dut=True, link_key=False, lesc_disabled=True, gatt_init=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()



####################################################################

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_No_input_No_output_responder_keyboard_only_using_public_C664579(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664579", smp_sc=0, smp_mtim=1, smp_io_capability=3, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_connect_to_dut=True,  lesc_disabled=True, link_key=False, gatt_init=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_No_input_No_output_responder_keyboard_display_using_public_C664589(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664589", smp_sc=0, smp_mtim=1, smp_io_capability=3, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_DISPLAY, nrf_connect_to_dut=True,  lesc_disabled=True, link_key=False, gatt_init=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_keyboard_only_responder_No_input_no_output_using_public_C664583(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664583", smp_sc=0, smp_mtim=1, smp_io_capability=2, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True,  lesc_disabled=True, link_key=False, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()



@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_keyboard_display_responder_No_input_No_output_using_public_C664585(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664585", smp_sc=0, smp_mtim=1, smp_io_capability=4, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True,  lesc_disabled=True, link_key=False, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_No_input_No_output_responder_keyboard_only_using_random_C664674(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664674", smp_sc=0, smp_mtim=1, smp_io_capability=3, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_connect_to_dut=True,  lesc_disabled=True, link_key=False, gatt_init=True, random_addr_on_dut=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_keyboard_only_responderNo_input_No_output_using_random_C664678(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664678", smp_sc=0, smp_mtim=1, smp_io_capability=2, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True,  lesc_disabled=True, link_key=False, gatt_init=True, random_addr_on_dut=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_keyboard_display_responder_No_input_No_output_using_random_C664680(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664583", smp_sc=0, smp_mtim=1, smp_io_capability=4, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True,  lesc_disabled=True, link_key=False, gatt_init=True, random_addr_on_dut=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()



@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_No_input_No_output_responder_keyboard_display_using_random_C664684(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664584", smp_sc=0, smp_mtim=1, smp_io_capability=4, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_connect_to_dut=True,  lesc_disabled=True, link_key=False, gatt_init=True, random_addr_on_dut=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()




@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_No_input_No_output_responder_keyboard_display_using_public_C664313(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664313", smp_sc=0, smp_mtim=1, smp_io_capability=4, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True,  lesc_disabled=True, link_key=False, gatt_init=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_No_input_No_output_responder_keyboard_Only_using_public_C664303(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664303", smp_sc=0, smp_mtim=1, smp_io_capability=2, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True,  lesc_disabled=True, link_key=False, gatt_init=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_Keyboard_display_responder_No_input_No_output_using_public_C664309(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664309", smp_sc=0, smp_mtim=1, smp_io_capability=3, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_DISPLAY, nrf_dongle_as_master=True,  lesc_disabled=True, link_key=False, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_Keyboard_Only_responder_No_input_No_output_using_public_C664307(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664307", smp_sc=0, smp_mtim=1, smp_io_capability=3, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_dongle_as_master=True,  lesc_disabled=True, link_key=False, gatt_init=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()





@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_No_input_No_output_responder_keyboard_display_using_random_C664338(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664338", smp_sc=0, smp_mtim=1, smp_io_capability=4, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True,  lesc_disabled=True, link_key=False, gatt_init=True, random_addr_on_dut=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_No_input_No_output_responder_keyboard_Only_using_random_C664328(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664328", smp_sc=0, smp_mtim=1, smp_io_capability=2, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True,  lesc_disabled=True, link_key=False, gatt_init=True, random_addr_on_dut=True)
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
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        assert len(ble_obj.sniffer_data_df_2.loc[(ble_obj.sniffer_data_df_2['Code'] == "Pairing Response") & (
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardOnly") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_Keyboard_display_responder_No_input_No_output_using_random_C664334(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664334", smp_sc=0, smp_mtim=1, smp_io_capability=3, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_DISPLAY, nrf_dongle_as_master=True,  lesc_disabled=True, link_key=False, gatt_init=True, random_addr_on_dut=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()



@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=[ "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_Keyboard_Only_responder_No_input_No_output_using_random_C664332(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for No input No output IOCap with DUT & dongle , dut as slave """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664332", smp_sc=0, smp_mtim=1, smp_io_capability=3, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_dongle_as_master=True,  lesc_disabled=True, link_key=False, gatt_init=True, random_addr_on_dut=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "NoInputNoOutput") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_verify_legacy_pairing_Display_yes_No_DUT_as_master_C557262(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify legacy pairing with Display Yes/No with DUT as master"""
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"],capture_filename="frontline_capture_C557262", smp_sc=0, smp_mtim=0, smp_io_capability=1, cap_on_dongle=NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, lesc_disabled=True, gatt_init=True, link_key=False)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                          'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_verify_Rand_memset_0_for_encryption_using_STK_C557279(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify EDIV/Rand memset 0 for encryption using STK"""
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,ble_sniffer=ble_sniffer, check_error=False, passkey_state=0, sniffer_check=True, layer_name=["LE LL", "SMP"], smp_sc=0, smp_io_capability=1, cap_on_dongle=NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_dongle_as_master=True, lesc_disabled=True, gatt_init=False, link_key=False)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()



@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_DisplayOnly_responder_keyboard_only_using_public_C664576(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664576", smp_sc=0, smp_mtim=1, smp_io_capability=0, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_connect_to_dut=True,  lesc_disabled=True, link_key=True, gatt_init=False, passkey_entry=True, testcase_no=664576)
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
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan","wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_Displayyes_or_no_responder_keyboard_only_using_public_C664577(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664577", smp_sc=0, smp_mtim=1, smp_io_capability=1, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_connect_to_dut=True,  lesc_disabled=True, link_key=True, gatt_init=False, passkey_entry=True, testcase_no=664576)
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
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan","wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_Display_only_responder_keyboard_display_using_public_C664586(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display only IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664586", smp_sc=0, smp_mtim=1, smp_io_capability=0, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_DISPLAY, nrf_connect_to_dut=True,  lesc_disabled=True, link_key=True, gatt_init=False, passkey_entry=True, testcase_no=664576)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_Display_yes_or_no_responder_keyboard_display_using_public_C664587(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664587", smp_sc=0, smp_mtim=1, smp_io_capability=1, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_DISPLAY, nrf_connect_to_dut=True,  lesc_disabled=True, link_key=True, gatt_init=False, passkey_entry=True, testcase_no=664576)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_DisplayOnly_responder_keyboard_only_using_random_C664671(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for DisplayOnly IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664671", smp_sc=0, smp_mtim=1, smp_io_capability=0, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_connect_to_dut=True,  lesc_disabled=True, link_key=True, gatt_init=False, passkey_entry=True, random_addr_on_dut=True, testcase_no=664576)
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
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_Displayyes_or_no_responder_keyboard_only_using_random_C664672(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664672", smp_sc=0, smp_mtim=1, smp_io_capability=1, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_connect_to_dut=True,  lesc_disabled=True, link_key=True, gatt_init=False, passkey_entry=True, random_addr_on_dut=True, testcase_no=664576)
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
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()




@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_Display_only_responder_keyboard_display_using_random_C664681(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display only IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664681", smp_sc=0, smp_mtim=1, smp_io_capability=0, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_DISPLAY, nrf_connect_to_dut=True,  lesc_disabled=True, link_key=True, gatt_init=False, passkey_entry=True, random_addr_on_dut=True, testcase_no=664576)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()




@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_Display_yes_or_no_responder_keyboard_display_using_random_C664682(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664682", smp_sc=0, smp_mtim=1, smp_io_capability=1, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_DISPLAY, nrf_connect_to_dut=True,  lesc_disabled=True, link_key=True, gatt_init=False, passkey_entry=True, random_addr_on_dut=True, testcase_no=664576)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "KeyboardDisplay") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()



@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_keyboard_only_responder_display_only_using_public_C664292(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664292", smp_sc=0, smp_mtim=1, smp_io_capability=0, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_dongle_as_master=True,  lesc_disabled=True, link_key=True, gatt_init=False, passkey_entry=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                      'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_keyboard_only_responder_display_only_using_public_C664294(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664294", smp_sc=0, smp_mtim=1, smp_io_capability=0, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_DISPLAY, nrf_dongle_as_master=True,  lesc_disabled=True, link_key=True, gatt_init=False, passkey_entry=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                      'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()



@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_keyboard_only_responder_display_yer_or_no_using_public_C664297(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664294", smp_sc=0, smp_mtim=1, smp_io_capability=1, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_dongle_as_master=True,  lesc_disabled=True, link_key=True, gatt_init=False, passkey_entry=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")


    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()



@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_keyboard_display_responder_display_yer_or_no_using_public_C664299(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"], capture_filename="frontline_capture_C664299", smp_sc=0, smp_mtim=1, smp_io_capability=1, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_DISPLAY, nrf_dongle_as_master=True,  lesc_disabled=True, link_key=True, gatt_init=False, passkey_entry=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_keyboard_only_responder_display_only_using_random_C664317(wifi_dut,
                                                                                                    nrf_ble_client,
                                                                                                    ble_sniffer,
                                                                                                    sl_collections,
                                                                                                    ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C664317", smp_sc=0, smp_mtim=1, smp_io_capability=0,
                          passkey_state=0, cap_on_dongle=NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_dongle_as_master=True,
                          lesc_disabled=True, link_key=True, gatt_init=False, passkey_entry=True, random_addr_on_dut=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_keyboard_only_responder_display_only_using_random_C664319(wifi_dut,
                                                                                                    nrf_ble_client,
                                                                                                    ble_sniffer,
                                                                                                    sl_collections,
                                                                                                    ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C664319", smp_sc=0, smp_mtim=1, smp_io_capability=0,
                          passkey_state=0, cap_on_dongle=NRFBLEIoCapabilities.KEYBOARD_DISPLAY,
                          nrf_dongle_as_master=True, lesc_disabled=True, link_key=True, gatt_init=False,
                          passkey_entry=True, random_addr_on_dut=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayOnly") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_keyboard_only_responder_display_yer_or_no_using_random_C664322(wifi_dut,
                                                                                                         nrf_ble_client,
                                                                                                         ble_sniffer,
                                                                                                         sl_collections,
                                                                                                         ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C664322", smp_sc=0, smp_mtim=1, smp_io_capability=1,
                          passkey_state=0, cap_on_dongle=NRFBLEIoCapabilities.KEYBOARD_ONLY, nrf_dongle_as_master=True,
                          lesc_disabled=True, link_key=True, gatt_init=False, passkey_entry=True, random_addr_on_dut=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_legacy_pairing_initiator_keyboard_display_responder_display_yer_or_no_using_random_C664324(wifi_dut,
                                                                                                            nrf_ble_client,
                                                                                                            ble_sniffer,
                                                                                                            sl_collections,
                                                                                                            ble_client):
    """Verify the Legacy pairing for Display yes or no IOCap with DUT & dongle , dut as master """
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C663338", smp_sc=0, smp_mtim=1, smp_io_capability=1,
                          passkey_state=0, cap_on_dongle=NRFBLEIoCapabilities.KEYBOARD_DISPLAY,
                          nrf_dongle_as_master=True, lesc_disabled=True, link_key=True, gatt_init=False,
                          passkey_entry=True, random_addr_on_dut=True)
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
                ble_obj.sniffer_data_df_2['IO Capabilities'] == "DisplayYesNo") & (ble_obj.sniffer_data_df_2[
                                                                                       'MITM'] == "MITM Protection:  Yes") & (
                                                         ble_obj.sniffer_data_df_2[
                                                             'Secure Connection Pairing'] == "No")]), "unable to find the packets in sniffer"
        logger().info(f"**************Testcase passed****************")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
        nrf_ble_client.interfaces.bluetooth.stop_advertising()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()



